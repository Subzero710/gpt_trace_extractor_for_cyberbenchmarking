#!/usr/bin/env python3
"""Build a verified immutable Kali qcow2, customized with the guest agent."""
from __future__ import annotations
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SOURCE = 'https://cdimage.kali.org/kali-2026.2/'
ARCHIVE = 'kali-linux-2026.2-qemu-amd64.7z'
ARCHIVE_SHA256 = 'c7c35588d05277c482c908bf7a136d348f76ffa68700b04ff53c0b217e6bd071'
DEST = Path('/var/lib/libvirt/images/gpt-trace/kali-base.qcow2')

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1048576), b''): h.update(block)
    return h.hexdigest()

def run(*cmd, **kw):
    subprocess.run(cmd,check=True,timeout=7200,**kw)

def build():
    if DEST.exists():
        verify();return
    for executable in ('curl','7z','qemu-img','virt-customize','virt-cat'):
        if not shutil.which(executable): raise RuntimeError(f'{executable} is required for the Kali image build')
    DEST.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='kali-build-',dir=DEST.parent) as tmp:
        temp=Path(tmp)
        expected=ARCHIVE_SHA256
        run('curl','--fail','--location','--retry','3','--output',str(temp/ARCHIVE),SOURCE+ARCHIVE)
        if digest(temp/ARCHIVE)!=expected: raise RuntimeError('Kali archive digest mismatch')
        run('7z','x',str(temp/ARCHIVE),'-o'+str(temp/'extracted'),'-y')
        images=list((temp/'extracted').rglob('*.qcow2'))
        if len(images)!=1: raise RuntimeError(f'expected one QEMU qcow2 in archive; found {len(images)}')
        image=temp/'base.qcow2'
        run('qemu-img','convert','-O','qcow2',str(images[0]),str(image))
        bundle=temp/'bundle';bundle.mkdir()
        (bundle/'src').mkdir()
        shutil.copytree(ROOT/'apps/kali-workstation/src/kali_workstation',bundle/'src/kali_workstation')
        shutil.copy(ROOT/'apps/kali-workstation/pyproject.toml',bundle/'pyproject.toml')
        shutil.copy(ROOT/'infra/workstation/image/requirements.lock',bundle/'requirements.lock')
        unit=ROOT/'infra/workstation/systemd/gpt-trace-workstation-agent.service'
        run('virt-customize','--network','-a',str(image),
            '--run-command',"printf 'deb https://http.kali.org/kali kali-last-snapshot main contrib non-free non-free-firmware\\n' > /etc/apt/sources.list && rm -f /etc/apt/sources.list.d/kali.sources",
            '--install','qemu-guest-agent,lightdm,xfce4,python3,python3-venv,python3-pip,git,build-essential,rustc,cargo,gdb,curl,wget,iproute2,iputils-ping,tcpdump,nmap',
            '--mkdir','/opt/gpt-trace',
            '--copy-in',str(bundle)+':/opt/gpt-trace',
            '--copy-in',str(unit)+':/etc/systemd/system',
            '--run-command','python3 -m venv /opt/gpt-trace/venv',
            '--run-command','/opt/gpt-trace/venv/bin/pip install --no-cache-dir --only-binary=:all: --require-hashes -r /opt/gpt-trace/bundle/requirements.lock',
            '--run-command',"CLOAKBROWSER_VERSION=146.0.7680.177.5 /opt/gpt-trace/venv/bin/python -m cloakbrowser install",
            '--run-command',"mkdir -p /opt/cloakbrowser && cp -a $(dirname $(CLOAKBROWSER_VERSION=146.0.7680.177.5 /opt/gpt-trace/venv/bin/python -c 'from cloakbrowser.download import ensure_binary; print(ensure_binary())')) /opt/cloakbrowser/chromium && chmod -R a+rX /opt/cloakbrowser && test -x /opt/cloakbrowser/chromium/chrome",
            '--run-command',"! ldd /opt/cloakbrowser/chromium/chrome | grep -q 'not found'",
            '--run-command','mkdir -p /etc/lightdm/lightdm.conf.d && printf "[Seat:*]\\nautologin-user=kali\\nautologin-user-timeout=0\\n" > /etc/lightdm/lightdm.conf.d/50-gpt-trace.conf',
            '--run-command','mkdir -p /home/kali/workspace /home/kali/Downloads && chown -R kali:kali /home/kali/workspace /home/kali/Downloads',
            '--run-command','systemctl enable lightdm qemu-guest-agent gpt-trace-workstation-agent',
            '--run-command',"dpkg-query -W -f='${Package} ${Version}\\n' > /etc/gpt-trace-packages.txt && /opt/gpt-trace/venv/bin/pip freeze --all > /etc/gpt-trace-python-packages.txt")
        packages=subprocess.check_output(['virt-cat','-a',str(image),'/etc/gpt-trace-packages.txt'])
        python_packages=subprocess.check_output(['virt-cat','-a',str(image),'/etc/gpt-trace-python-packages.txt'])
        (DEST.parent/'kali-packages.txt').write_bytes(packages)
        (DEST.parent/'kali-python-packages.txt').write_bytes(python_packages)
        shutil.copy(image,DEST.with_suffix('.tmp'))
        os.replace(DEST.with_suffix('.tmp'),DEST)
        DEST.chmod(0o444)
        metadata={'source':SOURCE+ARCHIVE,'source_sha256':expected,'base_sha256':digest(DEST),
                  'repo_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                  'guest_agent_version':'3.0.0','browser_runtime':'CloakBrowser 0.4.8 / 146.0.7680.177.5',
                  'apt_suite':'kali-last-snapshot', 'apt_package_manifest_sha256':hashlib.sha256(packages).hexdigest(),
                  'python_package_manifest_sha256':hashlib.sha256(python_packages).hexdigest(),
                  'python_lock_sha256':digest(ROOT/'infra/workstation/image/requirements.lock'),
                  'build_utc':datetime.now(timezone.utc).isoformat()}
        DEST.with_suffix('.provenance.json').write_text(json.dumps(metadata,indent=2)+'\n')
    verify()

def verify():
    metadata=json.loads(DEST.with_suffix('.provenance.json').read_text())
    if metadata['source_sha256'] != ARCHIVE_SHA256 or metadata['source'] != SOURCE+ARCHIVE:
        raise RuntimeError('Kali archive provenance differs from the pinned source')
    if metadata['python_lock_sha256'] != digest(ROOT/'infra/workstation/image/requirements.lock'):
        raise RuntimeError('Python dependency lock differs from the built image')
    for name,key in [('kali-packages.txt','apt_package_manifest_sha256'),
                     ('kali-python-packages.txt','python_package_manifest_sha256')]:
        if hashlib.sha256((DEST.parent/name).read_bytes()).hexdigest()!=metadata[key]:
            raise RuntimeError(f'{name} provenance differs from the built image')
    if metadata['base_sha256']!=digest(DEST): raise RuntimeError('Kali base image mutated')
    info=json.loads(subprocess.check_output(['qemu-img','info','--output=json',str(DEST)]))
    if info.get('format')!='qcow2' or info.get('backing-filename'): raise RuntimeError('base is not an independent qcow2')
    print('Kali image:',DEST,'sha256:',metadata['base_sha256'])

if __name__=='__main__':build()
