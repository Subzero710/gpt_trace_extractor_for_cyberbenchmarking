#!/usr/bin/env python3
"""Audited, explicit cleanup of obsolete offline dependency-fetch attempts.

Never runs while the broker/build slot is active. Preserves every staging tree
containing potentially reusable bytes unless a completed, published pool proves
that same operation no longer needs recovery. Keeps durable job journals.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tomllib
from pathlib import Path

HEX = re.compile(r'[0-9a-f]{64}\Z')
STAGE = re.compile(r'incoming-([0-9a-f]{64})-([1-9][0-9]*)\Z')
SOURCE = re.compile(r'source-([0-9a-f]{64})-([1-9][0-9]*)\Z')
TERMINAL = frozenset({'failed', 'interrupted', 'canceled'})
UNIT = Path('/sys/fs/cgroup/system.slice/gpt-trace-distributed-broker.service')


def verified_tree(folder, *, owner=None):
    if folder.is_symlink() or not folder.is_dir() or folder.is_mount():
        raise RuntimeError('unsafe cleanup directory: '+str(folder))
    if owner is not None and folder.stat().st_uid != owner:
        raise RuntimeError('unexpected cleanup directory owner: '+str(folder))
    for path in folder.rglob('*'):
        info=path.lstat()
        if (path.is_mount() or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                or stat.S_ISLNK(info.st_mode)):
            raise RuntimeError('unsafe entry in cleanup scope: '+str(path))


def sha256(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1048576),b''):h.update(block)
    return h.hexdigest()


def recoverable(stage):
    """Conservative: count all valid CAS/download objects and source/cache work."""
    for object_path in (stage/'objects'/'sha256').glob('*/*'):
        if (HEX.fullmatch(object_path.name) and object_path.parent.name==object_path.name[:2]
                and object_path.is_file() and sha256(object_path)==object_path.name):
            return True
    downloads=stage/'downloads'
    if downloads.is_dir():
        for path in downloads.iterdir():
            match=re.fullmatch(r'conda-([0-9a-f]{64})',path.name)
            if match and path.is_file() and sha256(path)==match.group(1):
                return True
    for directory in ('git', 'git-extra', 'wheels'):
        if any((stage/directory).rglob('*')) if (stage/directory).is_dir() else False:
            return True
    if any((stage/'metadata').glob('pip-plan-*.json')):
        return True
    if any((stage/'apt'/'archives').glob('*.deb')):
        return True
    return False


def has_running_owner(operation_id, record, *, stage=None, snapshot=None):
    """Reject active recorded processes, cgroups, source containers and path users."""
    worker=record.get('worker') or {}
    pid=worker.get('pid')
    if type(pid) is int and pid>0 and Path('/proc',str(pid)).exists():
        raise RuntimeError('recorded worker PID still exists: '+str(pid))
    scope=record.get('scope')
    if not isinstance(scope,dict) or scope.get('schema')!=1:
        raise RuntimeError('missing durable cgroup ownership record')
    expected='prep-'+operation_id+'-'+str(record['attempt'])
    if scope.get('name')!=expected:
        raise RuntimeError('untrusted preparation cgroup identity')
    cgroup=UNIT/expected
    if cgroup.exists():
        events=cgroup/'cgroup.events'
        if events.is_file():
            values=dict(row.split() for row in events.read_text().splitlines())
            if values.get('populated')!='0':
                raise RuntimeError('preparation cgroup still populated or unverifiable')
        else:
            raise RuntimeError('preparation cgroup has no empty-population proof')
    containers=subprocess.run(['docker','ps','-aq','--no-trunc','--filter',
                               'label=io.gpttrace.preparation='+operation_id],
                              check=True,capture_output=True,text=True,timeout=30)
    if containers.stdout.strip():
        raise RuntimeError('source containers remain for preparation '+operation_id)
    # Independently detect live readers/workers whose argv still references the
    # stage, including a worker that outlived its original preparation leader.
    paths=[str(x).encode() for x in (stage,snapshot) if x is not None]
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:argv=(proc/'cmdline').read_bytes()
        except (FileNotFoundError,ProcessLookupError):continue
        if argv and any(path in argv for path in paths):
            raise RuntimeError('running process still references fetch attempt: '+proc.name)


def journal_for(preparations, operation_id, attempt):
    directory=preparations/operation_id
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimeError('missing/untrusted preparation journal for '+operation_id)
    current=directory/'state.json'
    if current.is_symlink() or not current.is_file():
        raise RuntimeError('missing preparation state')
    latest=json.loads(current.read_bytes())
    if (latest.get('operation_id')!=operation_id or type(latest.get('attempt')) is not int
            or latest['attempt']<attempt):
        raise RuntimeError('untrusted preparation attempt journal')
    path=current if attempt==latest['attempt'] else directory/f'attempt-{attempt:04d}.json'
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('missing historical preparation attempt journal')
    record=json.loads(path.read_bytes())
    compatibility=record.get('compatibility')
    if (record.get('schema')!=1 or record.get('operation_id')!=operation_id
            or record.get('attempt')!=attempt or record.get('phase') not in TERMINAL
            or not isinstance(compatibility,dict)
            or compatibility.get('fetch_kind')!='download-only-pool-v2'):
        raise RuntimeError('preparation attempt is not a verified terminal fetch')
    return record


def published_for(ready, operation_id):
    if not ready.exists() and not ready.is_symlink():return False
    if ready.is_symlink() or not ready.is_dir() or ready.stat().st_uid!=0:
        raise RuntimeError('untrusted published pool')
    inventory=ready/'inventory.json'
    if inventory.is_symlink() or not inventory.is_file() or inventory.stat().st_uid!=0:
        raise RuntimeError('untrusted published pool inventory')
    record=json.loads(inventory.read_bytes())
    return (record.get('schema')==2 and record.get('complete') is True
            and record.get('operation_id')==operation_id)


def remove_verified_tree(path):
    # Only an already audited offline tree, never the published pool.
    for item in sorted(path.rglob('*'),key=lambda p:len(p.parts),reverse=True):
        if item.is_dir():item.chmod(0o700)
    path.chmod(0o700)
    shutil.rmtree(path)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--confirm',choices=['BURN_FETCH_ZOMBIES'])
    args=parser.parse_args(argv)
    if os.geteuid()!=0:
        raise RuntimeError('requires an explicit privileged admin session')
    root=Path(__file__).resolve().parents[1]
    conf=tomllib.loads((root/'config/distributed.toml').read_text())
    base=Path(conf['paths']['base_image'])
    if not base.is_absolute():raise RuntimeError('untrusted base_image storage path')
    parent=base.parent
    if any(item.is_symlink() for item in (parent,*parent.parents)):
        raise RuntimeError('symlink in configured storage root')
    mount=subprocess.run(['findmnt','-n','-o','TARGET','-T',str(parent)],
                         text=True,capture_output=True,check=True).stdout.strip()
    if Path(mount).resolve()!=parent.resolve():
        raise RuntimeError('storage disk is not mounted at its configured mount point')
    # All service states except a positive 'inactive'/'failed' are treated as unsafe.
    state=subprocess.run(['systemctl','show','--property=ActiveState','--value',
                          'gpt-trace-distributed-broker.service'],
                         text=True,capture_output=True,check=True).stdout.strip()
    if state not in {'inactive','failed'}:
        raise RuntimeError('stop execution broker before administrative cleanup')
    preparations=parent/'preparations'
    pool=parent/'dependency-pool'
    slot=preparations/'build-slot.lock'
    if slot.is_symlink() or not slot.is_file():
        raise RuntimeError('missing/unsafe build slot')
    fd=os.open(slot,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('preparation is still active') from exc
        if pool.is_symlink() or not pool.is_dir():
            raise RuntimeError('untrusted dependency pool root')
        fetch_uid=pwd.getpwnam('gpttrace-fetch').pw_uid
        snapshots={};stages={}
        for path in sorted(pool.iterdir()):
            if path.name in {'ready'}:continue
            stage_match=STAGE.fullmatch(path.name)
            source_match=SOURCE.fullmatch(path.name)
            if stage_match:stages[stage_match.group(1),int(stage_match.group(2))]=path
            elif source_match:snapshots[source_match.group(1),int(source_match.group(2))]=path
            elif path.name in {'incoming','source'}:
                print('Preserved ambiguous legacy path (requires separate provenance audit): '+str(path))
            elif path.name.startswith(('incoming-','source-')):
                raise RuntimeError('unrecognized dependency-pool attempt: '+str(path))
        selected=[];protected=[]
        for identity in sorted(set(stages)|set(snapshots)):
            operation_id,attempt=identity
            stage=stages.get(identity);snapshot=snapshots.get(identity)
            record=journal_for(preparations,operation_id,attempt)
            if stage is not None:
                verified_tree(stage,owner=fetch_uid)
                if (stage/'STAGING').is_symlink() or not (stage/'STAGING').is_file():
                    raise RuntimeError('missing staging identity marker')
            if snapshot is not None:verified_tree(snapshot,owner=0)
            has_running_owner(operation_id,record,stage=stage,snapshot=snapshot)
            if stage is not None and recoverable(stage) and not published_for(pool/'ready',operation_id):
                protected.append((identity,stage,'verified or reusable dependencies'))
                continue
            selected.extend(path for path in (stage,snapshot) if path is not None)
        for identity,path,reason in protected:
            print('Preserved recoverable attempt '+str(identity)+': '+str(path)+' ('+reason+')')
        if not selected:
            print('No obsolete, safely deletable fetch paths found.');return
        print('Proposed administrative deletion (durable journals are retained):')
        for path in selected:print(' ',path)
        if args.confirm!='BURN_FETCH_ZOMBIES':
            print('No files changed; rerun with --confirm BURN_FETCH_ZOMBIES')
            return
        for path in selected:remove_verified_tree(path)
        print('Removed '+str(len(selected))+' obsolete fetch paths; published pool and journals preserved.')
    finally:
        os.close(fd)

if __name__=='__main__':
    try:main()
    except (OSError,RuntimeError,ValueError,KeyError,subprocess.SubprocessError) as exc:
        print('admin cleanup rejected:',exc,file=sys.stderr)
        raise SystemExit(1)
