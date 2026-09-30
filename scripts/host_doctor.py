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
    cfg = tomllib.loads((ROOT/'config/runner.toml').read_text())['workstation']
    checks = [check('Linux host', platform.system() == 'Linux', platform.platform())]
    requirements_ok = verify_host_requirements(require_root=False, verbose=False)
    checks.append(check('host requirements', requirements_ok,
                        'requirements.txt + Python venv + Docker Engine/Compose/Buildx'))
    checks.append(check('broker privilege', os.geteuid() == 0,
                        'start the host broker as root (mount, nftables, libvirt system)'))
    kvm = Path('/dev/kvm')
    checks.append(check('/dev/kvm', kvm.exists() and os.access(kvm, os.R_OK | os.W_OK),
                        'enable VT-x/AMD-V and expose /dev/kvm' if not kvm.exists() else str(kvm)))
    cpu = Path('/proc/cpuinfo').read_text() if Path('/proc/cpuinfo').exists() else ''
    checks.append(check('hardware virtualization', 'vmx' in cpu or 'svm' in cpu,
                        'expose nested virtualization to Ubuntu when running in VMware'))
    if shutil.which('virsh'):
        ok, detail = probe('virsh', '-c', 'qemu:///system', 'list', '--all')
        checks.append(check('libvirt access', ok, detail))
    if shutil.which('nft'):
        ok, detail = probe('nft', 'list', 'tables')
        checks.append(check('nftables access', ok, detail))
    quota = cfg['overlay_quota_gb'] * 1024 ** 3
    disk = shutil.disk_usage(BASE.parent if BASE.parent.exists() else ROOT)
    needed = quota
    checks.append(check('attempt disk reservation', disk.free >= needed,
                        f'{disk.free // 1024**3} GiB free; {needed // 1024**3} GiB required by one attempt'))
    checks.append(check('golden image', BASE.is_file(), str(BASE)))
    for name in ('libvirt-qemu', 'qemu'):
        try:
            user = pwd.getpwnam(name)
        except KeyError:
            continue
        else:
            readable = BASE.is_file() and accessible(BASE, user, 4)
            traversable = BASE.is_file() and all(accessible(p, user, 1) for p in
                (BASE.parent, BASE.parent.parent, BASE.parent.parent.parent, BASE.parent.parent.parent.parent))
            checks.append(check('QEMU storage traversal', bool(readable and traversable),
                                f'{user.pw_name} must traverse {BASE.parent} and read the base image'))
            break
    else:
        checks.append(check('QEMU service account', False, 'libvirt-qemu or qemu user required'))
    broker_socket = ROOT/'state/broker/broker.sock'
    broker_ok, broker_detail = broker_health(broker_socket)
    checks.append(check('broker health', broker_ok, broker_detail))
    return 0 if all(checks) else 1


if __name__ == '__main__':
    sys.exit(main())
