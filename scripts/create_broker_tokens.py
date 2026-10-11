#!/usr/bin/env python3
"""Create two independent broker bearer tokens once; transfer over authenticated SSH.

Create on the control host, copy identical tokens to the execution host.
The directory must not exist; existing credentials are never overwritten.
"""
from __future__ import annotations
import argparse
import os
import secrets
from pathlib import Path


def provision(directory: Path):
    directory = Path(directory).absolute()
    if directory.exists() or directory.is_symlink():
        raise ValueError('destination must be new; never overwrite live broker tokens')
    for parent in directory.parents:
        if parent.is_symlink(): raise ValueError('unsafe parent symlink')
    directory.mkdir(mode=0o700, parents=True)
    values = [secrets.token_urlsafe(48), secrets.token_urlsafe(48)]
    if values[0] == values[1]: raise RuntimeError('token generation collision')
    for scope, value in zip(('admin', 'controller'), values):
        path = directory / ('workstation_broker_' + scope + '_token')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as output:
            output.write(value + '\n'); output.flush(); os.fsync(output.fileno())
    return directory


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print('Broker bearer credentials created in:', provision(args.output))
