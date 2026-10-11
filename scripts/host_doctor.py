#!/usr/bin/env python3
"""Read-only Ubuntu/KVM prerequisites inspection before the runtime smoke."""
from __future__ import annotations
import os
import platform
import pwd
import shutil
import socket
import subprocess
import sys
import tomllib
from pathlib import Path

from host_requirements import verify_host_requirements

ROOT = Path(__file__).resolve().parents[1]
BASE = Path('/var/lib/libvirt/images/gpt-trace/kali-base.qcow2')


def check(label, success, detail):
    print(f'{"OK" if success else "FAIL"} {label}: {detail}')
    return success


def probe(*args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
        return result.returncode == 0, result.stderr.strip()[:240] or result.stdout.strip()[:240]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)



def broker_health(path: Path) -> tuple[bool, str]:
    if not path.is_socket():
        return False, 'broker socket absent; run make up'
    request = b'GET /healthz HTTP/1.1\r\nHost: broker\r\nConnection: close\r\n\r\n'
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(3)
            conn.connect(str(path))
            conn.sendall(request)
            response = conn.recv(4096)
    except OSError as exc:
        return False, f'broker socket unhealthy: {exc}'
    status = response.split(b'\r\n', 1)[0]
    return b' 200 ' in status, status.decode('ascii', errors='replace')


def accessible(path: Path, user, bit: int) -> bool:
    mode = path.stat().st_mode
    groups = {user.pw_gid}
    import grp
    groups.update(group.gr_gid for group in grp.getgrall() if user.pw_name in group.gr_mem)
    return bool(mode & (bit << (6 if path.stat().st_uid == user.pw_uid else
                                  3 if path.stat().st_gid in groups else 0)))


def main():
    import distributed
    distributed.main(["doctor"])
    return 0


if __name__ == '__main__':
    sys.exit(main())
