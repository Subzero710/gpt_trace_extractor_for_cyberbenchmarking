"""Two-phase APT closure resolution and network-disabled artifact replay."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import runpy
import signal
import subprocess
import shutil
import tempfile
from pathlib import Path

@contextlib.contextmanager
def _template_operation(name):
    if os.environ.get("GPTTRACE_TEMPLATE_TRACE") != "1":
        yield
        return
    with Path("/dev/ttyS0").open("w", buffering=1) as serial:
        serial.write("GPTTRACE_TEMPLATE begin " + name + "\n")
        try:
            yield
        finally:
            serial.write("GPTTRACE_TEMPLATE end " + name + "\n")


def _install_archives(command, log):
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    if env.get("GPTTRACE_TEMPLATE_TRACE") != "1":
        subprocess.run(command, env=env, check=True, stdout=log, stderr=subprocess.STDOUT)
        return
    bundle = Path("/opt/gpt-trace/bundle")
    limits = json.loads((bundle / "guest-contract.json").read_bytes())
    limit = int(env["GPTTRACE_TEMPLATE_TIMEOUT"])
    cleanup = limits["cleanup_timeout_seconds"]
    cadence = limits["progress_interval_seconds"]
    if not (type(cleanup) is type(cadence) is int and 1 <= cadence <= limit <= 180
            and 1 <= cleanup <= limit):
        raise RuntimeError("invalid offline APT package deadlines")

    def terminate(process):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=cleanup)

    run_install = runpy.run_path(str(bundle / "apt_downloads.py"))["run_install"]
    executable = command.index("apt-get")
    run_install(command[executable + 1:], launcher=command[:executable], limit=limit, cadence=cadence,
                observe=_template_operation, terminate=terminate, env=env, stdout=log, stderr=subprocess.STDOUT)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def installed():
    with _template_operation("apt-installed-inventory"):
        raw = subprocess.check_output(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\t${Status}\n"], text=True)
    result = {}
    for line in raw.splitlines():
        name, version, arch, status = line.split("\t", 3)
        if status == "install ok installed":
            result[name] = {"version": version, "architecture": arch}
    return result


def deb_identity(path):
    with _template_operation("apt-package-identity"):
        raw = subprocess.check_output(["dpkg-deb", "-f", str(path), "Package", "Version", "Architecture"], text=True)
    values = {}
    for line in raw.splitlines():
        key, value = line.split(": ", 1)
        values[key.lower()] = value
    if set(values) != {"package", "version", "architecture"}:
        raise RuntimeError("invalid resolved Debian artifact metadata")
    return values


def verify_artifacts(folder, manifest):
    folder = Path(folder)
    artifacts = manifest.get("artifacts")
    if manifest.get("schema_version") != 1 or not isinstance(artifacts, dict) or not artifacts:
        raise RuntimeError("missing resolved OS package artifacts")
    if set(path.name for path in folder.glob("*.deb")) != set(artifacts):
        raise RuntimeError("missing/extra resolved .deb artifact")
    for name, record in artifacts.items():
        if not re.fullmatch(r"[A-Za-z0-9+._:%~\-]+\.deb", name):
            raise RuntimeError("unsafe resolved .deb filename")
        path = folder / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size != record["size"] or digest(path) != record["sha256"]:
            raise RuntimeError("resolved .deb artifact integrity mismatch")
        if deb_identity(path) != {key: record[key] for key in ("package", "version", "architecture")}:
            raise RuntimeError("resolved .deb version/architecture mismatch")


def require_requested(requested, inventory):
    if (not isinstance(requested, list) or not requested or len(set(requested)) != len(requested)
            or not all(isinstance(name, str) and re.fullmatch(r'[a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?', name) for name in requested)):
        raise RuntimeError('invalid requested OS package roots')
    present = {identity for name, row in inventory.items()
               for identity in (name.split(':')[0], name.split(':')[0]+':'+row['architecture'])}
    missing = set(requested)-present
    if missing:
        raise RuntimeError('offline APT replay omitted requested packages: '+', '.join(sorted(missing)))


def native_requirement_paths(requirements):
    """Validate observed system-file lookup identities without accepting shell input."""
    if not isinstance(requirements, dict):
        raise RuntimeError('invalid native requirement set')
    result = {}
    for key, paths in requirements.items():
        if not isinstance(key, str) or ':' not in key:
            raise RuntimeError('invalid native requirement identity')
        kind, lookup = key.split(':', 1)
        name, separator, observation = lookup.partition('@')
        if (kind not in {'header', 'library', 'soname', 'tool'} or not name
                or not re.fullmatch(r'[A-Za-z0-9_.+/-]+', name)
                or name.startswith('/') or any(part in {'', '.', '..'} for part in name.split('/'))
                or (kind != 'header' and '/' in name)
                or not isinstance(paths, list) or not paths
                or not all(isinstance(path, str) for path in paths)):
            raise RuntimeError('invalid native requirement: ' + key)
        suffixes = {name} if kind != 'library' else {'lib' + name + '.so', 'lib' + name + '.a'}
        valid = set()
        roots = ('usr/bin/', 'bin/', 'usr/sbin/', 'sbin/') if kind == 'tool' else ('usr/include/', 'usr/lib/', 'lib/', 'lib64/', 'usr/lib64/')
        for path in paths:
            if (not re.fullmatch(r'[A-Za-z0-9_.+/-]+', path)
                    or path.startswith('/') or any(part in {'', '.', '..'} for part in path.split('/'))
                    or not path.startswith(roots)
                    or not any(path.endswith('/' + suffix) for suffix in suffixes)):
                raise RuntimeError('invalid native provider path: ' + path)
            valid.add(path)
        paths = sorted(valid)
        if separator:
            expected = hashlib.sha256(json.dumps(paths, separators=(',', ':')).encode()).hexdigest()
            if observation != expected:
                raise RuntimeError('native observation identity differs from its paths')
        result[key] = paths
    return dict(sorted(result.items()))

def report_native_requirements(requirements, root):
    requirements = native_requirement_paths(requirements)
    if not requirements:
        raise RuntimeError('empty target native requirement report')
    token = os.environ.get('GPT_TRACE_NATIVE_ROUND')
    if not isinstance(token, str) or not re.fullmatch(r'[a-f0-9]{64}', token):
        raise RuntimeError('native requirement observation outside a bound preparation round')
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink():
        raise RuntimeError('unsafe target native report directory')
    path = root / 'native-requirements.json'
    fd, temporary = tempfile.mkstemp(prefix='.native-requirements-', dir=root)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump({'schema': 1, 'round': token, 'requirements': requirements}, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(root, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)
    raise RuntimeError('target native dependency resolution required: ' + ', '.join(requirements))


def require_build_tools(root):
    requirements = {}
    for name in ('ccache',):
        if shutil.which(name) is not None:
            continue
        paths = set()
        for directory in os.environ['PATH'].split(os.pathsep):
            if not directory.startswith('/'):
                continue
            path = os.path.normpath(directory + '/' + name).lstrip('/')
            if path.startswith(('usr/bin/', 'bin/', 'usr/sbin/', 'sbin/')):
                paths.add(path)
                if path.startswith(('bin/', 'sbin/')):
                    paths.add('usr/' + path)
        paths = sorted(paths)
        identity = hashlib.sha256(json.dumps(paths, separators=(',', ':')).encode()).hexdigest()
        requirements['tool:' + name + '@' + identity] = paths
    if requirements:
        report_native_requirements(requirements, root)


def require_native_headers(providers, *, root=Path('/')):
    root = Path(root).resolve(strict=True)
    if not isinstance(providers, dict):
        raise RuntimeError('invalid native provider manifest')
    for identity, row in sorted(providers.items()):
        if not isinstance(row, dict):
            raise RuntimeError('invalid native provider: ' + identity)
        key = identity if ':' in identity else 'header:' + identity
        if '@' in key:
            observed = native_requirement_paths({key: row.get('observed_paths')})[key]
            unscoped = key.split('@', 1)[0]
            paths = native_requirement_paths({unscoped: row.get('paths')})[unscoped]
            if not set(paths) <= set(observed):
                raise RuntimeError('installed native provider paths exceed their observed search paths')
        else:
            paths = native_requirement_paths({key: row.get('paths')})[key]
        if not any((root / relative).is_file() and
                   (root / relative).resolve(strict=True).is_relative_to(root) and
                   (not key.startswith('tool:') or os.access(root / relative, os.X_OK)) for relative in paths):
            raise RuntimeError('installed native header unavailable: ' + identity + ' from ' + row['package']
                               + ' (' + ', '.join(paths) + ')')


def install(folder, manifest, *, compare_final=True):
    folder = Path(folder)
    verify_artifacts(folder, manifest)
    if installed() != manifest["installed_before"]:
        raise RuntimeError("OS artifact replay does not start from the exact golden package inventory")
    empty = folder / "empty-lists"
    empty.mkdir(exist_ok=True)
    # No lists and no network: APT may resolve only the exact local .debs and
    # already-installed golden packages. Missing closure fails, never downloads.
    command = ["unshare", "--net", "apt-get", "-y", "--no-download", "--no-remove",
               "-o", "Acquire::Retries=0", "-o", "Dir::State::Lists=" + str(empty),
               "-o", "Dir::Cache::Archives=" + str(folder), "install"]
    command += [str(folder / name) for name in sorted(manifest["artifacts"])]
    with (folder / "install.log").open("wb") as log:
        _install_archives(command, log)
    actual = installed()
    require_requested(manifest['requested'], actual)
    providers = manifest.get('native_headers', {})
    if not isinstance(providers, dict):
        raise RuntimeError('invalid native header provider manifest')
    identities = {(row['package'], row['sha256']) for row in manifest['artifacts'].values()}
    if any(not isinstance(row, dict) or (row.get('package'), row.get('archive_sha256')) not in identities
           for row in providers.values()):
        raise RuntimeError('native header provider is not part of the exact installed APT archive closure')
    require_native_headers(providers)
    if compare_final and actual != manifest["installed_after"]:
        raise RuntimeError("installed OS inventory differs from resolved artifact closure")
    return actual


def resolve_from_pool(folder, source):
    """Produce the exact Kali OS manifest from host-fetched packages, offline.

    The input is an immutable SHA-256 manifest issued by the host acquisition
    phase; installation in this disposable Kali guest is only for validation.
    """
    import shutil
    folder = Path(folder)
    source = Path(source)
    if folder.is_symlink() or source.is_symlink():
        raise RuntimeError('unsafe OS replay input')
    evidence = json.loads((source / 'acquired.json').read_text())
    requested = evidence.get('requested')
    records = evidence.get('artifacts')
    if (not isinstance(requested, list) or not requested
            or not isinstance(records, dict) or not records):
        raise RuntimeError('acquired OS closure is incomplete')
    folder.mkdir(parents=True, exist_ok=True)
    before = installed()
    for filename, record in sorted(records.items()):
        if (not re.fullmatch(r'[A-Za-z0-9+._:%~\-]+\.deb', filename) or
                not isinstance(record, dict) or not re.fullmatch(r'[a-f0-9]{64}',
                str(record.get('sha256','')))):
            raise RuntimeError('invalid downloaded OS package')
        original = source / filename
        if original.is_symlink() or not original.is_file() or digest(original) != record['sha256']:
            raise RuntimeError('downloaded OS bytes differ')
        if deb_identity(original) != {k:record[k] for k in ('package','version','architecture')}:
            raise RuntimeError('downloaded OS package identity differs')
        with _template_operation("apt-copy-package"):
            shutil.copyfile(original, folder / filename)
    manifest = {'schema_version': 1, 'requested': requested,
                'installed_before': before, 'artifacts': records,
                'repository_metadata': evidence.get('repository_metadata', {}),
                **({'native_headers': evidence['native_headers']} if 'native_headers' in evidence else {})}
    manifest['installed_after'] = install(folder, manifest, compare_final=False)
    (folder / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, separators=(',',':')))
    return manifest
