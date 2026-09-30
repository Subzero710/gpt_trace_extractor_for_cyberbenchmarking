#!/usr/bin/env python3
"""Host lifecycle for the trusted project-owned broker."""
from __future__ import annotations
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
STATE=ROOT/'state/broker'
SOCKET=STATE/'broker.sock'
PID=STATE/'broker.pid'
BASE=Path('/var/lib/libvirt/images/gpt-trace/kali-base.qcow2')
ADMIN_TOKEN=ROOT/'.secrets/workstation_broker_admin_token'
CONTROLLER_TOKEN=ROOT/'.secrets/workstation_broker_controller_token'
PYTHON=ROOT/'.venv-workstation-broker/bin/python'

def send(action):
    payload=b'{}'
    token=ADMIN_TOKEN.read_text().strip()
    header=(f'POST /v1/{action} HTTP/1.1\r\nHost: broker\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n').encode()
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
        conn.settimeout(180);conn.connect(str(SOCKET));conn.sendall(header+payload)
        data=bytearray()
        while chunk:=conn.recv(65536):data.extend(chunk)
    status=data.split(b'\r\n',1)[0]
    if b' 200 ' not in status:raise RuntimeError(f'broker {action} failed: {data[:1000]!r}')
    return data

def start():
    if SOCKET.is_socket():
        send('probe')
        return
    if not BASE.is_file():raise RuntimeError('build Kali base image before make up')
    if not PYTHON.is_file():raise RuntimeError('build broker venv before make up')
    STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    (ROOT/'state').chmod(0o711)
    env={**os.environ,'WORKSTATION_BROKER_ADMIN_TOKEN_FILE':str(ADMIN_TOKEN),
         'WORKSTATION_BROKER_CONTROLLER_TOKEN_FILE':str(CONTROLLER_TOKEN),
         'WORKSTATION_BROKER_STATE':str(BASE.parent/'attempts'),
         'WORKSTATION_BASE_IMAGE':str(BASE),'WORKSTATION_BROKER_SOCKET':str(SOCKET),
         'WORKSTATION_CONFIG':str(ROOT/'config/runner.toml')}
    with (STATE/'broker.log').open('ab') as log:
        process=subprocess.Popen([str(PYTHON),'-m','workstation_broker.server'],env=env,stdout=log,stderr=log,start_new_session=True)
    PID.write_text(str(process.pid))
    # Broker initialization hashes/verifies the golden image and can take
    # longer than 10 seconds on nested-virtualization development hosts.
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if process.poll() is not None:
            tail = (STATE/'broker.log').read_text(errors='replace')[-4000:]
            PID.unlink(missing_ok=True)
            SOCKET.unlink(missing_ok=True)
            raise RuntimeError(f'broker exited during startup: {tail}')
        if SOCKET.is_socket():
            try:
                send('probe')
                return
            except (OSError, RuntimeError):
                pass
        time.sleep(.2)

    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    tail = (STATE/'broker.log').read_text(errors='replace')[-4000:]
    PID.unlink(missing_ok=True)
    SOCKET.unlink(missing_ok=True)
    raise RuntimeError(f'broker did not become ready within 120s: {tail}')

def stop():
    if SOCKET.is_socket():send('destroy_all')
    if PID.is_file():
        pid=int(PID.read_text())
        cmd=(Path('/proc')/str(pid)/'cmdline')
        if cmd.is_file() and b'workstation_broker.server' in cmd.read_bytes():
            os.kill(pid,signal.SIGTERM)
            for _ in range(50):
                if not cmd.exists():break
                time.sleep(.1)
        PID.unlink()
    SOCKET.unlink(missing_ok=True)

if __name__=='__main__':
    if len(sys.argv)!=2 or sys.argv[1] not in {'start','stop'}:raise SystemExit('usage: workstation_broker.py start|stop')
    {'start':start,'stop':stop}[sys.argv[1]]()
