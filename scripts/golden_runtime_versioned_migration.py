#!/usr/bin/env python3
"""Promote an independently copied Kali Golden after verified runtime-only changes.

Run from the repository root. No repository file is modified. The original image
is retained under a content-addressed archive beside the configured image.
No existing attempts, template generations, running broker or dependent layers
are permitted. An interrupted promotion is replayable from its durable journal.
"""
from __future__ import annotations

import argparse
import csv
import fcntl
import hashlib
import json
import os
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path


def fail(message):
    raise RuntimeError(message)


def sha_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def load_builder(root):
    folder = root / 'infra/workstation/image'
    if not (folder / 'build.py').is_file() or not (root / 'config/distributed.toml').is_file():
        fail('run this script from the repository root')
    sys.path[:0] = [str(folder), str(root / 'shared')]
    import build
    if build.ROOT.resolve() != root.resolve():
        fail('imported Golden constructor belongs to another repository')
    return build


def command(*args, timeout, capture=True):
    result = subprocess.run([str(a) for a in args], capture_output=capture, text=True, timeout=timeout)
    if result.returncode:
        fail(f'{args[0]} failed (exit {result.returncode}): {result.stderr[-2500:] if capture else "see process output"}')
    return result.stdout.strip() if capture else ''


def durable_dir(directory):
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def immutable(path, *, directory=False):
    path = Path(path)
    if path.is_symlink():
        fail(f'symlink is not trusted: {path}')
    info = path.stat()
    if info.st_uid != 0 or info.st_mode & 0o022 or not (
        stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    ):
        fail(f'untrusted root-owned artifact: {path}')
    if not directory and info.st_mode & 0o222:
        fail(f'artifact must be immutable: {path}')
    return path


def read_proof(golden, path, *, private=False):
    return golden.read_json(path, private=private)


def checked_paths(golden):
    source = golden.ROOT / 'apps/kali-workstation/src'
    guest = source / 'kali_workstation/guest'
    contract = source / 'kali_workstation/contracts.py'
    if not guest.is_dir() or guest.is_symlink() or not contract.is_file():
        fail('guest runtime source tree is invalid')
    items = sorted(guest.rglob('*.py')) + [contract]
    if not items:
        fail('guest runtime is empty')
    return {p.relative_to(source).as_posix(): golden.versioned_file(p) for p in items}


def guest_file(golden, name):
    return str(golden.guest_build.BUNDLE / 'src' / name)


def checked_units(golden):
    unit_source = golden.ROOT / 'infra/workstation/systemd'
    return {path.name: golden.versioned_file(path) for path in golden.input_files()
            if path.parent == unit_source}


def unit_guest_file(name):
    return str(Path('/etc/systemd/system') / name)


def guest_profile(golden, image, paths, timeout, *, units=False):
    if not paths:
        return {}
    prefix = (Path('/etc/systemd/system') if units
              else golden.guest_build.BUNDLE / 'src/kali_workstation')
    raw = command('virt-ls', '-lR', '--uids', '--csv', '-a', image, prefix, timeout=timeout)
    location = unit_guest_file if units else lambda name: guest_file(golden, name)
    requested = {location(name): name for name in paths}
    profiles = {}
    for fields in csv.reader(raw.splitlines()):
        if not fields or fields[-1] not in requested:
            continue
        if len(fields) != 6 or fields[0] != '-' or re.fullmatch(r'0[0-7]{3,4}', fields[1]) is None:
            fail(f'unsafe guest file type or permissions: {fields}')
        _, permissions, size, uid, gid, name = fields
        if not all(value.isdigit() for value in (size, uid, gid)) or requested[name] in profiles:
            fail('untrusted guest ownership inventory')
        if int(permissions, 8) & 0o7000:
            fail('guest runtime has unsupported special mode bits')
        profiles[requested[name]] = (int(permissions, 8), int(uid), int(gid))
    if set(profiles) != set(paths):
        fail('guest ownership inventory does not cover each migration file')
    return profiles


def ensure_no_consumers(golden, timeout):
    service = (golden.ROOT / 'infra/workstation/systemd/gpt-trace-distributed-broker.service.in').name.removesuffix('.in')
    status = command('systemctl', 'show', '-p', 'ActiveState', '--value', service, timeout=timeout)
    pid = command('systemctl', 'show', '-p', 'MainPID', '--value', service, timeout=timeout)
    if status not in {'inactive', 'failed'} or pid != '0':
        fail('broker is still running; run sudo make down first')
    domains = command('virsh', '-c', 'qemu:///system', 'list', '--all', '--name', timeout=timeout)
    if any(name.startswith('gpt-trace-ws-') for name in domains.splitlines()):
        fail('project libvirt domains still exist')
    root = golden.DEST.parent
    attempts = root / 'attempts'
    if attempts.exists() or attempts.is_symlink():
        immutable(attempts, directory=True)
        if any(attempts.iterdir()):
            fail('attempt state is not empty; existing guests must be reconciled')
    templates = root / 'templates'
    if templates.exists() or templates.is_symlink():
        immutable(templates, directory=True)
        for path in templates.rglob('*'):
            if path.is_symlink():
                fail(f'unsafe template symlink: {path}')
            if path.is_file() and (path.suffix == '.qcow2' or path.name in {'registry.json', 'manifest.json'}):
                fail(f'existing template generation prevents changing the backing image: {path}')
    # This protects hidden producer state, including an already detached setup.
    for marker in (root / 'broker-drain.json',):
        if marker.is_symlink():
            fail(f'unsafe broker state marker: {marker}')


def immutable_original(golden, timeout):
    base = immutable(golden.DEST)
    proven = immutable(base.with_suffix('.provenance.json'))
    metadata = read_proof(golden, proven)
    golden.validate_provenance_fields(metadata)
    if (metadata['source'] != golden.SOURCE + golden.ARCHIVE
            or metadata['source_sha256'] != golden.ARCHIVE_SHA256
            or metadata['architecture'] != golden.SOURCE_ARCHITECTURE
            or metadata['python_lock_sha256'] != golden.versioned_digest(golden.HERE / 'requirements.lock')):
        fail('pinned Golden source/dependencies changed; runtime-only migration forbidden')
    base_sha = golden.digest(base)
    if base_sha != metadata['base_sha256']:
        fail('original installed Golden SHA-256 differs from its provenance')
    golden.image_info(base)
    for path, field in ((base.parent / 'kali-packages.txt', 'apt_package_manifest_sha256'),
                        (base.parent / 'kali-python-packages.txt', 'python_package_manifest_sha256')):
        if golden.digest(immutable(path)) != metadata[field]:
            fail('installed package manifest differs from signed provenance')
    journal = read_proof(golden, base.parent / 'golden-install.json', private=True)
    golden.validate_state(journal)
    if (journal['phase'] != 'installed' or journal['status'] != 'installed'
            or journal['repo_commit'] != metadata['repo_commit']
            or journal['fingerprint'] != metadata['build_input_sha256']):
        fail('installed journal does not identify the historical guest provisioning')
    stage = immutable(base.parent / journal['stage'], directory=True)
    stage_image = immutable(stage / base.name)
    if (base.stat().st_dev, base.stat().st_ino) != (stage_image.stat().st_dev, stage_image.stat().st_ino):
        fail('installed Golden/stage images are not the same authenticated inode')
    if base.stat().st_nlink != 2:
        fail('Golden has unexpected hardlinks; refusing to change a potentially shared backing')
    stage_state = read_proof(golden, stage / 'build-state.json', private=True)
    if stage_state != journal:
        fail('stage journal differs from installed journal')
    if read_proof(golden, stage / proven.name) != metadata:
        fail('stage provenance differs from installed provenance')
    for item in golden.artifact_paths():
        if golden.row(item) != journal['files'][item.name]:
            fail(f'installed checkpoint hash mismatch: {item.name}')
    original_proof = {'fingerprint': metadata['build_input_sha256'], 'repo_commit': metadata['repo_commit']}
    if not golden.guest_complete(base, original_proof):
        fail('original provisioning completion proof is missing')
    contract = json.loads(golden.guest_read(base, str(golden.guest_build.BUNDLE / 'guest-contract.json')))
    expected_contract = golden.guest_installation_contract()
    if not isinstance(contract, dict) or any(contract.get(key) != value for key, value in expected_contract.items()):
        fail('installed installation contract changed; runtime-only migration forbidden')
    for guest_target, source in ((golden.guest_build.BUNDLE / 'pyproject.toml',
                                  golden.ROOT / 'apps/kali-workstation/pyproject.toml'),
                                 (golden.guest_build.BUNDLE / 'requirements.lock', golden.HERE / 'requirements.lock'),
                                 (golden.guest_build.BUNDLE / 'python-lock.json', golden.HERE / 'python-lock.json')):
        if golden.guest_read(base, str(guest_target)) != source.read_bytes():
            fail(f'installed Python dependency definition changed: {guest_target}')
    return base, metadata, journal, stage, base_sha


def inspect(golden, timeout):
    ensure_no_consumers(golden, timeout)
    base, metadata, journal, stage, old_sha = immutable_original(golden, timeout)
    inputs = checked_paths(golden)
    units = checked_units(golden)
    before = {name: sha_bytes(golden.guest_read(base, guest_file(golden, name))) for name in inputs}
    current = {name: sha_bytes(path.read_bytes()) for name, path in inputs.items()}
    previous_units = {name: sha_bytes(golden.guest_read(base, unit_guest_file(name))) for name in units}
    current_units = {name: sha_bytes(path.read_bytes()) for name, path in units.items()}
    if 'runtime_migration' in metadata:
        previous = metadata['runtime_migration']
        common = {'schema', 'original_base_sha256', 'host_input_sha256', 'files'}
        if (not isinstance(previous, dict)
                or type(previous.get('schema')) is not int or previous['schema'] not in (1, 2)
                or set(previous) != common | ({'units'} if previous['schema'] == 2 else set())
                or previous['files'] != before
                or (previous['schema'] == 2 and previous['units'] != previous_units)
                or not all(re.fullmatch(r'[0-9a-f]{64}', str(previous[key])) is not None
                           for key in ('original_base_sha256', 'host_input_sha256'))):
            fail('prior runtime migration certificate does not match the actual Golden')
    elif not all(re.fullmatch(r"[0-9a-f]{64}", str(sha)) is not None for sha in before.values()):
        fail('invalid authenticated installed runtime contents')
    changed = {name: path for name, path in inputs.items() if before[name] != current[name]}
    changed_units = {name: path for name, path in units.items()
                     if previous_units[name] != current_units[name]}
    fingerprint = golden.golden_build_input_sha256()
    if not changed and not changed_units:
        if 'runtime_migration' in metadata and metadata['runtime_migration']['host_input_sha256'] != fingerprint:
            fail('non-runtime Golden build inputs changed; refusing metadata-only reattestation')
        if 'runtime_migration' not in metadata and metadata['build_input_sha256'] != fingerprint:
            fail('Golden build fingerprint differs without any changed runtime file')
    else:
        # Other host and guest-provisioning input changes remain forbidden.
        # This migration covers only runtime source files and installed
        # systemd unit inputs, measured directly from the original QCOW2.
        if 'runtime_migration' not in metadata:
            fail('no verified prior runtime migration proof; cannot establish the source-only delta')
    # Reconstruct the *preceding* versioned build fingerprint from the real
    # Golden files, not from a claimed metadata hash. This proves no other
    # Python, dependency, guest-build or injection input has changed.
    payloads = {path: path.read_bytes() for path in golden.input_files()}
    for name in changed:
        payloads[inputs[name]] = golden.guest_read(base, guest_file(golden, name))
    for name in changed_units:
        payloads[units[name]] = golden.guest_read(base, unit_guest_file(name))
    reconstructed = golden.golden_build_input_sha256(payloads)
    previous_input = (metadata['runtime_migration']['host_input_sha256']
                      if 'runtime_migration' in metadata else metadata['build_input_sha256'])
    if reconstructed != previous_input:
        fail('other Golden build inputs changed: reconstructed previous fingerprint differs '
             f'(measured={reconstructed}, recorded={previous_input}); no image mutation')
    profiles = guest_profile(golden, base, changed, timeout)
    unit_profiles = guest_profile(golden, base, changed_units, timeout, units=True)
    return {'base': base, 'metadata': metadata, 'journal': journal, 'stage': stage,
            'old_sha': old_sha, 'current': current, 'changed': changed,
            'units': current_units, 'changed_units': changed_units,
            'fingerprint': fingerprint, 'profiles': profiles,
            'unit_profiles': unit_profiles}


def validate_local_verifier(golden):
    # The checked-out build.py must actually enforce the migration attestations.
    import inspect as pyinspect
    source = pyinspect.getsource(golden.verify)
    if ('runtime_migration' not in source or 'host_input_sha256' not in source
            or 'golden migrated runtime file differs' not in source
            or 'golden migrated service unit differs' not in source):
        fail('local build.py must verify both migrated runtime files and installed service units; '
             'apply the corresponding verifier patch first')


def convert_with_progress(golden, source, dest, timeout):
    progress_command(['qemu-img', 'convert', '-p', '-f', 'qcow2', '-O', 'qcow2', str(source), str(dest)], timeout)

def progress_command(args, timeout):
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    observed = -1
    deadline = time.monotonic() + timeout
    last = bytearray()
    pending = b''
    try:
        while True:
            if process.poll() is not None:
                extra = process.stdout.read() or b''
                last.extend(extra[-2048:])
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fail('qemu-img made no measurable progress before the configured deadline')
            ready, _, _ = select.select([process.stdout], [], [], min(remaining, 1))
            if not ready:
                continue
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                break
            last.extend(chunk)
            if len(last) > 8192:
                del last[:-4096]
            # qemu-img prints progress with variable spaces and may split a
            # progress token across two pipe reads; retain a bounded tail.
            pending = (pending + chunk)[-512:]
            for value in re.findall(rb'\(\s*(\d+(?:\.\d+)?)/100%\)', pending):
                measured = float(value)
                if observed < measured <= 100:
                    observed = measured
                    deadline = time.monotonic() + timeout
        status = process.wait(timeout=timeout)
        if status:
            fail(f'qemu-img operation failed (exit {status}): {bytes(last)[-2000:]!r}')
        if observed < 0:
            fail('qemu-img did not publish a measurable progress record')
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=timeout)
        raise
    finally:
        process.stdout.close()


def compare_with_progress(original, copy, timeout):
    # qemu-img compare emits progress to stderr with -p. Report a stuck
    # comparison from measured progress, not from an arbitrary total duration.
    progress_command(['qemu-img', 'compare', '-p', '-f', 'qcow2', '-F', 'qcow2', str(original), str(copy)], timeout)

def update_guest(golden, clone, changes, profiles, units, unit_profiles, timeout):
    for candidates, properties, address in (
            (changes, profiles, lambda name: guest_file(golden, name)),
            (units, unit_profiles, unit_guest_file)):
        for name, source in candidates.items():
            target = address(name)
            mode, uid, gid = properties[name]
            if source.is_symlink() or not source.is_file():
                fail(f'migration source has become unsafe: {source}')
            # The original ownership and mode are preserved exactly.
            command('virt-customize', '--no-network', '--no-logfile', '-a', clone,
                    '--upload', f'{source}:{target}',
                    '--chmod', f'{mode:04o}:{target}',
                    '--chown', f'{uid}:{gid}:{target}', timeout=timeout)
        for name, source in candidates.items():
            if sha_bytes(source.read_bytes()) != sha_bytes(golden.guest_read(clone, address(name))):
                fail('new Golden guest file differs from the exact versioned source: ' + name)
    if guest_profile(golden, clone, changes, timeout) != profiles:
        fail('new Golden runtime file ownership or permission bits changed')
    if guest_profile(golden, clone, units, timeout, units=True) != unit_profiles:
        fail('new Golden systemd service ownership or permission bits changed')


def check_transaction_state(golden, txn, archive):
    if (not isinstance(txn, dict) or set(txn) != {'schema', 'old_sha', 'new_sha', 'fingerprint',
            'old_metadata', 'new_metadata', 'old_state', 'new_state', 'work'} or txn['schema'] != 1):
        fail('invalid durable Golden promotion record')
    if any(re.fullmatch(r'[0-9a-f]{64}', str(txn[key])) is None for key in ('old_sha', 'new_sha', 'fingerprint')):
        fail('promotion record contains invalid SHA-256')
    if archive.name != '.golden-runtime-archive-' + txn['old_sha']:
        fail('promotion record/archive identity mismatch')
    if re.fullmatch(r'\.golden-runtime-stage-[0-9a-f]{64}', str(txn['work'])) is None:
        fail('invalid promotion staging location')
    golden.validate_state(txn['old_state'])
    golden.validate_state(txn['new_state'])
    golden.validate_provenance_fields(txn['old_metadata'])
    golden.validate_provenance_fields(txn['new_metadata'])
    migration = txn['new_metadata'].get('runtime_migration')
    expected_units = {name: sha_bytes(path.read_bytes())
                      for name, path in checked_units(golden).items()}
    if (not isinstance(migration, dict) or migration.get('schema') != 2
            or migration.get('units') != expected_units
            or txn['new_metadata']['base_sha256'] != txn['new_sha']
            or txn['old_metadata']['base_sha256'] != txn['old_sha']
            or migration['host_input_sha256'] != txn['fingerprint']
            or txn['old_state']['stage'] != txn['new_state']['stage']
            or txn['old_state']['fingerprint'] != txn['new_state']['fingerprint']):
        fail('promotion record changes an immutable historical identity')
    immutable(archive, directory=True)
    old_archived = immutable(archive / golden.DEST.name)
    if golden.digest(old_archived) != txn['old_sha']:
        fail('archived original Golden image is no longer authentic')
    staging = immutable(golden.DEST.parent / txn['work'], directory=True)
    path = staging / golden.DEST.name
    if golden.digest(immutable(path)) != txn['new_sha']:
        fail('staged new Golden image is no longer authentic')
    if golden.golden_build_input_sha256() != txn['fingerprint']:
        fail('repository changed during Golden promotion; preserve transaction for recovery')
    return path


def publish(golden, archive, txn):
    # A crash between writing the durable intent and creating the archival
    # hardlink is recoverable while the old installed image is still intact.
    archived = archive / golden.DEST.name
    if not archived.exists() and not archived.is_symlink():
        if (golden.DEST.is_symlink() or not golden.DEST.is_file()
                or golden.digest(immutable(golden.DEST)) != txn['old_sha']):
            fail('missing original archive: refusing promotion without an authenticated original')
        os.link(golden.DEST, archived, follow_symlinks=False)
        durable_dir(archive)
    clone = check_transaction_state(golden, txn, archive)
    ensure_no_consumers(golden, golden.operation_timeout(golden._acquisition_controls()))
    base = golden.DEST
    stage = base.parent / txn['old_state']['stage']
    stage_image = stage / base.name
    # No step in a valid transaction can remove the original archive.
    for path in (base, stage_image):
        if path.exists() or path.is_symlink():
            if golden.digest(immutable(path)) not in {txn['old_sha'], txn['new_sha']}:
                fail(f'Golden promotion encountered an unrelated image: {path}')
    for path in (base.with_suffix('.provenance.json'), stage / base.with_suffix('.provenance.json').name):
        if read_proof(golden, immutable(path)) not in (txn['old_metadata'], txn['new_metadata']):
            fail(f'unrelated metadata during Golden promotion: {path}')
    for path in (base.parent / 'golden-install.json', stage / 'build-state.json'):
        if read_proof(golden, path, private=True) not in (txn['old_state'], txn['new_state']):
            fail(f'unrelated state during Golden promotion: {path}')
    for target in (stage_image, base):
        if golden.digest(immutable(target)) != txn['new_sha']:
            temporary = target.with_name('.' + target.name + '.promotion-' + txn['fingerprint'])
            if temporary.exists() or temporary.is_symlink():
                fail(f'unexpected promoted image link already exists: {temporary}')
            os.link(clone, temporary, follow_symlinks=False)
            durable_dir(temporary.parent)
            os.replace(temporary, target)
            durable_dir(target.parent)
    for target in (stage / base.with_suffix('.provenance.json').name, base.with_suffix('.provenance.json')):
        if read_proof(golden, target) != txn['new_metadata']:
            golden.atomic_json(target, txn['new_metadata'], 0o444)
    golden._save(txn['new_state'])
    golden.verify()
    if golden.digest(base) != txn['new_sha'] or golden.digest(stage_image) != txn['new_sha']:
        fail('post-commit stage/installed identity mismatch')
    if (base.stat().st_dev, base.stat().st_ino) != (stage_image.stat().st_dev, stage_image.stat().st_ino):
        fail('post-commit stage/installed Golden hardlinks differ')
    original = immutable(archive / base.name)
    if original.stat().st_ino == base.stat().st_ino:
        fail('archived original image has been overwritten')
    complete = {'schema': 1, 'old_sha256': txn['old_sha'], 'new_sha256': txn['new_sha'],
                'host_input_sha256': txn['fingerprint'], 'old_provenance': txn['old_metadata'],
                'new_provenance': txn['new_metadata']}
    golden.atomic_json(archive / 'completed.json', complete, 0o444)
    # Leave the staged clone/transaction as durable evidence rather than risking
    # deletion of evidence after an interruption. Neither is active as a backing.
    (archive / 'transaction.json').unlink()
    durable_dir(archive)
    print('MIGRATION COMPLETE: installed Golden verified, original image archived at ' + str(archive), flush=True)


def pending_transaction(golden):
    pending = []
    for path in golden.DEST.parent.glob('.golden-runtime-archive-*'):
        immutable(path, directory=True)
        ledger = path / 'transaction.json'
        if ledger.exists() or ledger.is_symlink():
            pending.append((path, read_proof(golden, ledger, private=True)))
    if len(pending) > 1:
        fail('multiple unfinished Golden migrations: cannot choose a transaction')
    return pending[0] if pending else None


def apply(golden, plan, timeout):
    if not plan['changed'] and not plan['changed_units']:
        golden.verify()
        print('Golden already current; no mutation performed')
        return
    old = plan['base']
    archive = old.parent / ('.golden-runtime-archive-' + plan['old_sha'])
    work = old.parent / ('.golden-runtime-stage-' + plan['fingerprint'])
    if archive.exists() or archive.is_symlink() or work.exists() or work.is_symlink():
        fail('Golden archive/staging location already exists: refusing to overwrite preserved bytes')
    # The conservative capacity check is intentional: never begin a copy which
    # could strand an immutable historical image without space for the clone.
    workspace = shutil.disk_usage(old.parent)
    reserve = golden._preparation_build_controls()['golden_qcow2_copy_mib'] * 1024 * 1024
    if workspace.free < old.stat().st_size + reserve:
        fail(f'insufficient free disk space for an independent Golden copy: free={workspace.free} required={old.stat().st_size + reserve}')
    work.mkdir(mode=0o700)
    durable_dir(work.parent)
    clone = work / old.name
    print('Creating independent QCOW2; original image remains untouched.', flush=True)
    convert_with_progress(golden, old, clone, timeout)
    golden.image_info(clone)
    # QEMU compares the logical guest blocks before any controlled file changes.
    compare_with_progress(old, clone, timeout)
    update_guest(golden, clone, plan['changed'], plan['profiles'],
                 plan['changed_units'], plan['unit_profiles'], timeout)
    for name, value in plan['current'].items():
        if sha_bytes(golden.guest_read(clone, guest_file(golden, name))) != value:
            fail('cloned Golden does not contain the complete current runtime: ' + name)
    for name, value in plan['units'].items():
        if sha_bytes(golden.guest_read(clone, unit_guest_file(name))) != value:
            fail('cloned Golden does not contain the current service unit: ' + name)
    guest_state = {'fingerprint': plan['metadata']['build_input_sha256'],
                   'repo_commit': plan['metadata']['repo_commit']}
    if not golden.guest_complete(clone, guest_state):
        fail('clone lost the historical guest completion proof')
    golden.image_info(clone)
    # Freeze exact image bytes before binding a SHA-256 provenance record.
    clone.chmod(0o444)
    with clone.open('rb') as stream:
        os.fsync(stream.fileno())
    new_sha = golden.digest(clone)
    if golden.digest(old) != plan['old_sha']:
        fail('installed original Golden changed during cloning')
    metadata = {**plan['metadata'], 'base_sha256': new_sha,
                'runtime_migration': {
                    'schema': 2, 'original_base_sha256': plan['old_sha'],
                    'host_input_sha256': plan['fingerprint'], 'files': plan['current'],
                    'units': plan['units']}}
    golden.validate_provenance_fields(metadata)
    new_meta_bytes = json.dumps(metadata, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
    provenance_name = old.with_suffix('.provenance.json').name
    new_state = {**plan['journal'], 'files': {**plan['journal']['files'],
        old.name: {'size': clone.stat().st_size, 'sha256': new_sha},
        provenance_name: {'size': len(new_meta_bytes), 'sha256': sha_bytes(new_meta_bytes)}}}
    golden.validate_state(new_state)
    txn = {'schema': 1, 'old_sha': plan['old_sha'], 'new_sha': new_sha,
           'fingerprint': plan['fingerprint'], 'old_metadata': plan['metadata'],
           'new_metadata': metadata, 'old_state': plan['journal'], 'new_state': new_state,
           'work': work.name}
    archive.mkdir(mode=0o700)
    golden.atomic_json(archive / 'old_provenance.json', plan['metadata'], 0o444)
    golden.atomic_json(archive / 'old_journal.json', plan['journal'], 0o400)
    golden.atomic_json(archive / 'transaction.json', txn, 0o600)
    os.link(old, archive / old.name, follow_symlinks=False)
    durable_dir(archive)
    publish(golden, archive, txn)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check', action='store_true', help='read-only preflight')
    group.add_argument('--apply', action='store_true', help='perform authenticated copy-and-promote migration')
    args = parser.parse_args()
    if os.geteuid() != 0:
        fail('root is required for the Golden integrity and libvirt checks')
    root = Path.cwd().resolve()
    golden = load_builder(root)
    golden.require_execution_role()
    golden._safe_parent()
    validate_local_verifier(golden)
    timeout = golden.operation_timeout(golden._acquisition_controls())
    flags = (os.O_RDONLY | os.O_NOFOLLOW) if args.check else (os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW)
    descriptor = os.open(golden.DEST.parent / 'golden-build.lock', flags, 0o600)
    try:
        state = os.fstat(descriptor)
        if not stat.S_ISREG(state.st_mode) or state.st_uid != 0 or state.st_mode & 0o077 or state.st_nlink != 1:
            fail('unsafe Golden build serialization lock')
        fcntl.flock(descriptor, (fcntl.LOCK_SH if args.check else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        golden.BUILD_LOCK = descriptor
        pending = pending_transaction(golden)
        if pending is not None:
            archive, txn = pending
            if args.check:
                check_transaction_state(golden, txn, archive)
                print('PENDING PROMOTION: authentic journal; --apply resumes existing promotion')
            else:
                publish(golden, archive, txn)
            return
        plan = inspect(golden, timeout)
        print('Original Golden SHA-256:', plan['old_sha'])
        print('Current source input SHA-256:', plan['fingerprint'])
        print('Verified runtime source differences:', ', '.join(plan['changed']) if plan['changed'] else 'none')
        print('Verified systemd service differences:', ', '.join(plan['changed_units']) if plan['changed_units'] else 'none')
        if args.apply:
            apply(golden, plan, timeout)
    finally:
        golden.BUILD_LOCK = None
        os.close(descriptor)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError) as exc:
        print(type(exc).__name__ + ': ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
