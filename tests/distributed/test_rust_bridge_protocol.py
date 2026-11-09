"""Test the native resolver IPC oracle without PyPI, Conda, QEMU or network."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from packaging.requirements import Requirement
from packaging.version import Version, InvalidVersion


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
        '_packaging_symbols':lambda :(None, None, Version, InvalidVersion, None),
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


def test_bridge_versions_use_pep440_not_string_spelling():
    from packaging.version import Version, InvalidVersion
    import importlib.util
    source = Path(__file__).resolve().parents[2] / 'scripts/verified_resolver_bridge.py'
    spec = importlib.util.spec_from_file_location('resolver_pep440_policy_test', source)
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    host = {'_packaging_symbols': lambda: (None, None, Version, InvalidVersion, None)}
    assert bridge._same_pep440_version(host, '1.0', '1.0.0')
    assert not bridge._same_pep440_version(host, '1.0', '1.0.1')
    assert not bridge._same_pep440_version(host, 'invalid', '1.0')


def test_adaptive_prefetch_preserves_running_work_without_unbounded_queue():
    import concurrent.futures
    class DeferredExecutor:
        def __init__(self):
            self.submitted = {}
        def submit(self, fn, ref):
            future = concurrent.futures.Future()
            self.submitted[ref] = future
            return future
    location = Path(__file__).resolve().parents[2] / 'scripts/verified_resolver_bridge.py'
    spec = importlib.util.spec_from_file_location('resolver_bounded_prefetch_test', location)
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    executor = DeferredExecutor()
    prefetch = bridge._BoundedPrefetch(executor, lambda ref: ref)
    verified = {}
    prefetch.schedule((1, 2), 2, verified)
    assert set(prefetch.futures) == {1, 2}
    assert executor.submitted[1].set_running_or_notify_cancel()
    prefetch.schedule((3, 4), 2, verified)
    assert executor.submitted[2].cancelled()
    assert set(prefetch.futures) == {1, 3}
    assert 4 not in executor.submitted
    assert prefetch.take(1) is executor.submitted[1]
    executor.submitted[3].set_result('verified')
    verified[3] = 'verified'
    prefetch.schedule((3, 4), 2, verified)
    assert 4 in prefetch.futures
    assert prefetch.take(4) is executor.submitted[4]
    prefetch.close()


def test_adaptive_prefetch_retains_current_completed_failure_until_consumed():
    import concurrent.futures
    location = Path(__file__).resolve().parents[2] / 'scripts/verified_resolver_bridge.py'
    spec = importlib.util.spec_from_file_location('resolver_prefetch_failure_test', location)
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    class DeferredExecutor:
        def submit(self, fn, ref):
            return concurrent.futures.Future()
    prefetch = bridge._BoundedPrefetch(DeferredExecutor(), lambda ref: ref)
    prefetch.schedule((1,), 1, {})
    pending = prefetch.futures[1]
    pending.set_exception(RuntimeError('metadata error'))
    prefetch.schedule((1,), 1, {})
    import pytest
    with pytest.raises(RuntimeError, match='metadata error'):
        prefetch.take(1).result()
    prefetch.close()


def test_nested_prefetch_preserves_live_parent_siblings_and_prioritizes_child():
    import concurrent.futures
    class DeferredExecutor:
        def __init__(self):
            self.futures = {}
        def submit(self, fn, ref):
            future = concurrent.futures.Future()
            self.futures[ref] = future
            return future
    source = Path(__file__).resolve().parents[2] / 'scripts/verified_resolver_bridge.py'
    spec = importlib.util.spec_from_file_location('resolver_nested_prefetch_test', source)
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    executor = DeferredExecutor()
    prefetch = bridge._BoundedPrefetch(executor, lambda ref: ref)
    prefetch.schedule((1, 2), 3, {}, depth=1)
    assert set(prefetch.futures) == {1, 2}
    prefetch.schedule((3,), 3, {}, depth=2)
    assert set(prefetch.futures) == {1, 2, 3}
    # Returning from a child invalidates its pending probe, not the parent's.
    prefetch.schedule((2,), 3, {}, depth=1)
    assert set(prefetch.futures) == {2}
    assert executor.futures[1].cancelled()
    assert executor.futures[3].cancelled()
    prefetch.close()


def test_nested_prefetch_prioritizes_child_without_canceling_running_probes():
    import concurrent.futures
    class DeferredExecutor:
        def __init__(self):
            self.futures = {}
        def submit(self, fn, ref):
            future = concurrent.futures.Future()
            self.futures[ref] = future
            return future
    source = Path(__file__).resolve().parents[2] / 'scripts/verified_resolver_bridge.py'
    spec = importlib.util.spec_from_file_location('resolver_child_priority_prefetch_test', source)
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    executor = DeferredExecutor()
    prefetch = bridge._BoundedPrefetch(executor, lambda ref: ref)
    prefetch.schedule((1, 2), 2, {}, depth=0)
    assert executor.futures[1].set_running_or_notify_cancel()
    prefetch.schedule((3,), 2, {}, depth=1)
    assert set(prefetch.futures) == {1, 3}
    assert executor.futures[2].cancelled()
    assert not executor.futures[1].cancelled()
    prefetch.close()


def test_compiled_resolver_avoids_quadratic_python_callbacks(monkeypatch, tmp_path):
    import collections
    from packaging.requirements import Requirement
    from packaging.version import Version, InvalidVersion

    source = Path(__file__).resolve().parents[2] / 'scripts/verified_resolver_bridge.py'
    spec = importlib.util.spec_from_file_location('resolver_ipc_scaling_test', source)
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    # The distributed CI job already built and sealed the release binary.
    # Use that exact identity-verified artifact, not a second compilation.
    binary = bridge._binary(source.parents[1])
    monkeypatch.setattr(bridge, '_binary', lambda _: binary)
    (tmp_path / 'scripts').mkdir()
    (tmp_path / 'config').mkdir()
    (tmp_path / 'config/preparation.toml').write_text('''[acquisition]
pip_solver_max_decisions = 1000000
pip_solver_max_depth = 1024
pip_solver_cache_max_bytes = 67108864
pip_solver_max_frame_bytes = 16777216
pip_total_timeout_seconds = 900
''')
    (tmp_path / 'scripts/superbench_pool.py').write_text('# fixture path\n')
    names = {f'pkg{index:05d}' for index in range(80)}
    candidates = {name: {'name': name, 'kind': 'wheel', 'version': '1.0',
                         'filename': f'{name}-1.0.whl', 'item': {'url': f'https://example.org/{name}.whl',
                         'digests': {'sha256': 'a' * 64}}} for name in names}
    inspected = collections.Counter()
    original = bridge._Wire.exact
    def track(self, count):
        value = original(self, count)
        if count == 1 and value in (b'C', b'K', b'B', b'M', b'P'):
            inspected[value] += 1
        return value
    monkeypatch.setattr(bridge._Wire, 'exact', track)
    host = {
        '__file__': str(tmp_path / 'scripts/superbench_pool.py'),
        '_coerce_target': lambda target: target,
        '_packaging_symbols': lambda: (None, None, Version, InvalidVersion, None),
        '_constraint_map': lambda constraints, target: {},
        '_SingleFlightCache': lambda: {},
        '_parse_registry_requirement': Requirement,
        '_marker_active': lambda *args: True,
        '_normalized_package_name': lambda name: name.lower(),
        '_candidate_versions': lambda _pool, name, *_args, **_kwargs: [candidates[name]],
        '_candidate_artifact_identity': lambda candidate: (candidate['item']['digests']['sha256'], candidate['item']['url']),
        '_candidate_probe_identity': lambda candidate, target, no_deps: (candidate['name'], candidate['version'], no_deps),
        '_candidate_release_metadata': lambda _pool, candidate, *_args, **_kwargs: {**candidate, 'requirements': []},
        '_candidate_satisfies': lambda candidate, requirements, constraints: all(
            not req.specifier or req.specifier.contains(candidate['version'], prereleases=True)
            for req in [*requirements, *constraints]),
        '_POOL_PROGRESS': True,
    }
    target = SimpleNamespace(python_artifact_sha256='a' * 64)
    result = bridge.solve(host, None, target, {name + '==1.0' for name in names}, [],
                          'ipc-budget-test', materialize=False)
    assert len(result) == len(names)
    # Originally: 6,480 C and 3,240 K round trips for 80 roots.
    assert inspected[b'C'] == len(names)
    assert inspected[b'K'] == len(names)
    assert inspected[b'B'] == 1
    assert inspected[b'M'] == len(names)
    assert inspected[b'P'] == len(names)
