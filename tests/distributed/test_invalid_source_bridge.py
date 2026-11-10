"""Offline Rust-wire bridge regression for a verified target syntax rejection."""
from __future__ import annotations
import hashlib
import importlib.util
import io
import os
from pathlib import Path
from types import SimpleNamespace

from packaging.requirements import Requirement
from packaging.version import Version, InvalidVersion

import superbench_pool as pool

spec = importlib.util.spec_from_file_location(
    'verified_resolver_bridge_reject_source_test',
    Path(__file__).resolve().parents[2] / 'scripts/verified_resolver_bridge.py')
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


def test_syntax_rejection_is_distinct_from_metadata_infrastructure_error():
    child=SimpleNamespace(stdin=io.BytesIO(),stdout=io.BytesIO())
    wire=bridge._Wire(child,1000)
    rejection=pool._IncompatibleSourceSyntax('target syntax error')
    wire.rejected_source(rejection)
    output=child.stdin.getvalue()
    assert output[:1] == b'\x02'
    length=int.from_bytes(output[1:5],'big')
    assert output[5:5+length] == b'target syntax error'
    child.stdin=io.BytesIO()
    wire=bridge._Wire(child,1000)
    wire.error(RuntimeError('network unavailable'))
    assert child.stdin.getvalue()[0:1] == b'\x00'


def test_bridge_rejects_bad_source_and_returns_verified_wheel(tmp_path,monkeypatch):
    (tmp_path/'scripts').mkdir()
    (tmp_path/'config').mkdir()
    (tmp_path/'config/preparation.toml').write_text('''[acquisition]
pip_solver_max_decisions = 1000
pip_solver_max_depth = 100
pip_solver_cache_max_bytes = 100000
pip_solver_max_frame_bytes = 100000
pip_total_timeout_seconds = 20
''')
    source=tmp_path/'scripts/superbench_pool.py'
    source.write_text('# offline host fixture\n')
    worker=tmp_path/'fake-worker'
    worker.write_text('''#!'''+os.fspath(Path(os.sys.executable))+'''
import sys
inp=sys.stdin.buffer;out=sys.stdout.buffer
def read(n):
 d=inp.read(n); assert len(d)==n;return d
def num(n=4):return int.from_bytes(read(n),'big')
def string():
 length=num()
 assert length <= frame_limit, 'fake Rust worker received an oversized IPC string'
 return read(length).decode()
def strings():return [string() for _ in range(num())]
def sendnum(n,size=4):out.write(n.to_bytes(size,'big'))
def sendstr(s):
 b=s.encode();sendnum(len(b));out.write(b)
_=[num(8) for _ in range(6)]
frame_limit=_[0]
no_deps=num(1)
assert no_deps==1
assert num()==1
assert (string(),string(),strings())==('demo','demo>=0.5',[])
out.write(b'D');sendstr('demo');sendnum(1);sendstr('demo>=0.5');out.flush()
assert read(1)==b'\\x01'
assert num()==2
old=num();assert num(1)==1;assert string()=='sdist';assert string()=='0.5';assert string()=='demo-0.5.tar.gz'
new=num();assert num(1)==1;assert string()=='wheel';assert string()=='1';assert string()=='demo-1-py3-none-any.whl'
out.write(b'M');sendnum(1);sendnum(old);out.flush()
status=read(1)
assert status==b'\\x02', (status, string())
assert 'setup.py' in string()
out.write(b'M');sendnum(1);sendnum(new);out.flush()
assert read(1)==b'\\x01'
out.write(b'S');sendnum(1);sendnum(new);sendstr('solver decisions=2');out.flush()
''')
    worker.chmod(0o755)
    monkeypatch.setattr(bridge,'_binary',lambda root:worker)
    sha = lambda version: hashlib.sha256(version.encode()).hexdigest()
    old = {'name':'demo','version':'0.5','kind':'sdist','filename':'demo-0.5.tar.gz',
           'item':{'url':'https://files.pythonhosted.org/demo-0.5.tar.gz', 'digests':{'sha256':sha('0.5')}}}
    new = {'name':'demo','version':'1','kind':'wheel','filename':'demo-1-py3-none-any.whl',
           'item':{'url':'https://files.pythonhosted.org/demo-1-py3-none-any.whl','digests':{'sha256':sha('1')}}}
    metadata={'name':'demo','version':'1','kind':'wheel','filename':new['filename'],
              'sha256':sha('1'),'url':new['item']['url'],'requirements':[],'provides_extra':[]}
    def probe(_pool,candidate,key,target):
        assert candidate is old
        raise pool._IncompatibleSourceSyntax('source setup.py cannot compile on target Python')
    host={'__file__':str(source), '_coerce_target':lambda target:target,
          '_packaging_symbols':lambda: (Requirement,None,Version,InvalidVersion,None),
          '_constraint_map':lambda c,t:{},'_SingleFlightCache':dict,
          '_parse_registry_requirement':Requirement,
          '_marker_active':lambda *args:True,
          '_normalized_package_name':lambda name:name.lower(),
          '_candidate_versions':lambda *args,**kwargs:[old,new],
          '_candidate_artifact_identity':lambda c:(c['item']['digests']['sha256'],c['item']['url']),
          '_candidate_probe_identity':lambda c,target,no_deps:(c['version'],no_deps),
          '_target_fingerprint':lambda target:'offline',
          '_candidate_release_metadata':lambda *args,**kwargs:metadata,
          '_memo_get_or_compute':lambda cache,key,fn:fn(),
          '_candidate_satisfies':lambda c,reqs,cons:all(
               not r.specifier or r.specifier.contains(Version(c['version']),prereleases=True)
               for r in [*reqs,*cons]),
          '_IncompatibleSourceSyntax':pool._IncompatibleSourceSyntax,
          '_POOL_PROGRESS':True}
    target=SimpleNamespace(python_artifact_sha256='b'*64)
    result=bridge.solve(host,None,target,{'demo>=0.5'},[], 'offline-test',no_deps=True,
                        resolver_cache={'native_source_probe':probe,'sources_require_locked_python':True},
                        materialize=False)
    assert result==[metadata]
