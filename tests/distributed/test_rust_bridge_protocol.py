"""Test the native resolver IPC oracle without PyPI, Conda, QEMU or network."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from packaging.requirements import Requirement


def test_verified_ipc_serves_real_candidate_then_returns_identity(monkeypatch, tmp_path):
    location=Path(__file__).resolve().parents[2]/'scripts/verified_resolver_bridge.py'
    spec=importlib.util.spec_from_file_location('verified_resolver_bridge_under_test',location)
    bridge=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    root=tmp_path
    (root/'scripts').mkdir()
    (root/'config').mkdir()
    (root/'config/preparation.toml').write_text('''[acquisition]
pip_solver_max_decisions = 1000
pip_solver_max_depth = 100
pip_solver_cache_max_bytes = 100000
pip_solver_max_frame_bytes = 100000
pip_total_timeout_seconds = 20
''')
    (root/'scripts/superbench_pool.py').write_text('# dummy module path\n')
    child=root/'rust-test-oracle'
    child.write_text('''#!'''+sys.executable+'''
import struct,sys
f=sys.stdin.buffer;o=sys.stdout.buffer
def read(n):
 b=f.read(n)
 assert len(b)==n
 return b
def num(n=4):return int.from_bytes(read(n),'big')
def string():return read(num()).decode()
def strings():return [string() for _ in range(num())]
def sendnum(x,n=4):o.write(x.to_bytes(n,'big'))
def sendstr(x):
 raw=x.encode();sendnum(len(raw));o.write(raw)
limit=num(8);max_decisions=num(8);depth=num(8);cache=num(8);deadline=num(8);prefetch=num(8);no_deps=num(1)
roots=[(string(),string(),strings()) for _ in range(num())]
assert roots==[('demo','demo==1.0',[])]
o.write(b'D');sendstr('demo');sendnum(1);sendstr('demo==1.0');o.flush()
assert read(1)==b'\\x01'
assert num()==1
candidate=num(); assert string()=='wheel';assert string()=='1.0';assert string()=='demo-1.0.whl'
o.write(b'M');sendnum(1);sendnum(candidate);o.flush()
assert read(1)==b'\\x01'
o.write(b'S');sendnum(1);sendnum(candidate);sendstr('solver decisions=0');o.flush()
''')
    child.chmod(0o755)
    monkeypatch.setattr(bridge,'_binary',lambda _:child)
    artifact={'kind':'wheel','name':'demo','version':'1.0','filename':'demo-1.0.whl',
              'item':{'url':'https://files.pythonhosted.org/demo.whl','digests':{'sha256':'a'*64}}}
    result={**artifact,'sha256':'a'*64,'url':'https://files.pythonhosted.org/demo.whl',
            'requirements':[],'provides_extra':[]}
    host={
        '__file__':str(root/'scripts/superbench_pool.py'),
        '_coerce_target':lambda v:v,
        '_constraint_map':lambda c,t:{},
        '_SingleFlightCache':lambda :{},
        '_parse_registry_requirement':Requirement,
        '_marker_active':lambda *args:True,
        '_normalized_package_name':lambda name:name.lower(),
        '_candidate_versions':lambda *args,**kwargs:[artifact],
        '_candidate_artifact_identity':lambda v:(v['item']['digests']['sha256'],v['item']['url']),
        '_candidate_release_metadata':lambda *args,**kwargs:result,
        '_candidate_satisfies':lambda candidate,reqs,constraints: all(
            not r.specifier or r.specifier.contains(candidate['version'],prereleases=True)
            for r in [*reqs,*constraints]),
        '_POOL_PROGRESS':True,
    }
    target=SimpleNamespace(python_artifact_sha256='a'*64)
    assert bridge.solve(host,None,target,{'demo==1.0'},set(),'group',materialize=False)==[result]
