#!/usr/bin/env python3
"""Explicit offline ADMIN cleanup of failed SWE-Gym Lite fetch attempts.

Not a fetch operation. No retry/automatic cleanup. Requires a stopped broker,
exclusive preparation lock, validated paths and an explicit confirmation token.
Never touches a published pool, a guest disk or an unrelated preparation.
"""
from __future__ import annotations
import argparse
import fcntl
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tomllib
from pathlib import Path


def verified_tree(folder):
    if folder.is_symlink() or not folder.is_dir():
        raise RuntimeError('unsafe cleanup directory: '+str(folder))
    for path in folder.rglob('*'):
        if path.is_symlink() or path.is_mount() or not (path.is_file() or path.is_dir()):
            raise RuntimeError('unsafe entry in cleanup scope: '+str(path))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--confirm',choices=['BURN_FETCH_ZOMBIES'])
    args=parser.parse_args()
    if os.geteuid()!=0:raise RuntimeError('requires an explicit privileged admin session')
    root=Path(__file__).resolve().parents[1]
    conf=tomllib.loads((root/'config/distributed.toml').read_text())
    base=Path(conf['paths']['base_image'])
    if not base.is_absolute():raise RuntimeError('untrusted base_image storage path')
    parent=base.parent
    if any(item.is_symlink() for item in (parent,*parent.parents)):
        raise RuntimeError('symlink in configured storage root')
    mount=subprocess.run(['findmnt','-n','-o','TARGET','-T',str(parent)],text=True,capture_output=True,check=True).stdout.strip()
    if Path(mount).resolve()!=parent.resolve():
        raise RuntimeError('storage disk is not mounted at its configured mount point')
    active=subprocess.run(['systemctl','is-active','--quiet','gpt-trace-distributed-broker.service'],check=False).returncode
    if active==0:raise RuntimeError('stop execution broker before administrative cleanup')
    preparation=parent/'preparations'
    slot=preparation/'build-slot.lock'
    if slot.is_symlink() or not slot.is_file():raise RuntimeError('missing/unsafe build slot')
    fd=os.open(slot,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:raise RuntimeError('preparation is still active') from exc
        scope=[]
        for folder in sorted(preparation.iterdir()):
            if not folder.is_dir() or folder.is_symlink():continue
            state=folder/'state.json'
            if state.is_symlink() or not state.is_file():continue
            record=json.loads(state.read_bytes())
            if record.get('compatibility',{}).get('fetch_kind')!='download-only-pool-v2':continue
            if not re.fullmatch(r'[a-f0-9]{64}',folder.name) or record.get('operation_id')!=folder.name:
                raise RuntimeError('untrusted fetch journal')
            if record.get('phase') not in {'failed','interrupted','canceled'}:
                raise RuntimeError('fetch is not a terminal zombie; preserved')
            ident=record.get('worker') or {}
            pid=ident.get('pid')
            if type(pid)==int and pid>0 and Path('/proc',str(pid)).exists():
                raise RuntimeError('recorded preparation process may still exist; preserved')
            verified_tree(folder)
            scope.append(folder)
        stage=parent/'dependency-pool'/'incoming'
        ready=parent/'dependency-pool'/'ready'
        if ready.exists() or ready.is_symlink():
            raise RuntimeError('published dependency pool exists; refuse maintenance')
        if stage.exists() or stage.is_symlink():verified_tree(stage)
        if not scope and not stage.exists():
            print('No fetch zombies found.');return
        print('Proposed administrative deletion:')
        for path in ([stage] if stage.exists() else [])+scope:print(' ',path)
        if args.confirm!='BURN_FETCH_ZOMBIES':
            print('No files changed; rerun with --confirm BURN_FETCH_ZOMBIES')
            return
        if stage.exists():shutil.rmtree(stage)
        for path in scope:shutil.rmtree(path)
        print('Zombies removed by explicit administrator request.')
    finally:
        os.close(fd)

if __name__=='__main__':
    try:main()
    except (OSError,RuntimeError,ValueError,KeyError) as exc:
        print('admin cleanup rejected:',exc,file=sys.stderr)
        raise SystemExit(1)
