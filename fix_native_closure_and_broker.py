#!/usr/bin/env python3
"""Apply the verified artifact resolver + native sdist hooks and visible broker monitoring.

Run at the repository root. The GitHub connector is read-only; this script edits
only its explicit local paths, checks the expected function contracts and never
starts, stops, removes, or retries any workload.
"""
from __future__ import annotations

import argparse
import ast
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

SCRIPT = Path('scripts/superbench_pool.py')
CLIENT = Path('scripts/distributed.py')
POLICY = Path('config/preparation.toml')
TESTS = Path('tests/distributed/test_verified_closure_and_broker.py')


def ensure(condition, detail):
    if not condition:
        raise RuntimeError('refusing to patch changed/unsupported source: ' + detail)


def replace_function(source, name, replacement):
    module = ast.parse(source)
    matches = [node for node in module.body if isinstance(node, (ast.FunctionDef,ast.AsyncFunctionDef)) and node.name == name]
    ensure(len(matches) == 1, 'function ' + name)
    node = matches[0]
    lines = source.splitlines(keepends=True)
    start = node.lineno - 1
    # Preserve surrounding explanatory comments, which are not part of ast nodes.
    lines[start:node.end_lineno] = [replacement.strip('\n') + '\n']
    return ''.join(lines)


def replace_once(source, old, new, label):
    ensure(source.count(old) == 1, label)
    return source.replace(old,new,1)


def patch_pool(source):
    ensure('native-pip-target-lock-build-closure-v2' in source, 'native resolver policy')
    ensure('PIP_PLAN_SCHEMA = 18' in source, 'plan schema')
    ensure('def _resolve_registry_plan(' in source and 'class _SingleFlightCache:' in source, 'verified backjump resolver')
    source = replace_once(source,'PIP_PLAN_SCHEMA = 18','PIP_PLAN_SCHEMA = 19','plan schema')
    source = replace_once(source, "PIP_RESOLVER_POLICY = 'native-pip-target-lock-build-closure-v2'",
        "PIP_RESOLVER_POLICY = 'verified-registry-backjump-native-sdist-metadata-v3'",'resolver policy')

    # Native build hooks are run per *selected source candidate*, never on a
    # giant mixed wheel/source graph. Every release is still immutable/SHA bound.
    helper = '''
def _native_source_candidate_metadata(pool, candidate, key, target):
    """Read the *real target* PEP 517 metadata for one SHA-verified sdist.

    This path is used for every sdist under the verified graph solver. Wheels
    instead use PyPI's hash-verified core-metadata sidecars or their own METADATA.
    Neither the metadata hook nor the installer gets an unbounded mixed graph.
    """
    target = _coerce_target(target)
    if candidate['kind'] != 'sdist':
        raise RuntimeError('native source hook requires a source distribution')
    sha, url = _candidate_artifact_identity(candidate)
    filename = candidate['filename']
    parsed = urllib.parse.urlsplit(url)
    if (not isinstance(filename, str) or Path(filename).name != filename
            or filename in {'.', '..'}
            or not filename.endswith(('.tar.gz', '.tar.bz2', '.zip'))
            or parsed.scheme != 'https' or parsed.hostname != 'files.pythonhosted.org'
            or urllib.parse.unquote(parsed.path.rsplit('/', 1)[-1]) != filename
            or parsed.username or parsed.password or parsed.fragment):
        raise RuntimeError('untrusted native source archive identity')
    # The CAS is authoritative: pip never gets a downloaded archive without
    # verifying its expected digest and exact PyPI distribution provenance.
    actual = pool.download(url, 'python-source', key, sha=sha)
    if actual != sha:
        raise RuntimeError('native source artifact identity differs')
    pool.verify_object(sha)
    runtime = _native_pool_runtime(pool)
    python = _native_locked_python(pool, target)
    if python is None:
        raise RuntimeError('source metadata requires a locked target Python')
    root = (runtime['root'] / 'source-metadata' /
            _target_fingerprint(target) / sha)
    root.mkdir(parents=True, exist_ok=True)
    source = pool.objects / sha[:2] / sha
    archive = root / filename
    if not archive.exists():
        os.link(source, archive)
    if archive.is_symlink() or not archive.is_file() or not archive.samefile(source):
        raise RuntimeError('native source archive was replaced')
    report = root / 'pip-report.json'
    command = [python, '-m', 'pip', 'install', '--use-pep517', '--dry-run',
               '--ignore-installed', '--no-deps', '--report', report,
               archive]
    observed_builds = _native_metadata_command(command, runtime, root)
    data = json.loads(report.read_bytes())
    installs = data.get('install')
    if not isinstance(installs, list) or len(installs) != 1:
        raise RuntimeError('native single-source PEP 517 report is incomplete')
    installed = installs[0]
    metadata = installed.get('metadata')
    download = installed.get('download_info') or {}
    if not isinstance(metadata, dict) or not isinstance(download, dict):
        raise RuntimeError('native single-source report has invalid metadata')
    origin = download.get('url')
    location = urllib.parse.urlsplit(origin) if isinstance(origin, str) else None
    if (location is None or location.scheme != 'file' or location.netloc
            or location.query or location.fragment
            or Path(urllib.parse.unquote(location.path)) != archive):
        raise RuntimeError('native single-source report differs from verified CAS input')
    name = metadata.get('name')
    version = metadata.get('version')
    requirements = metadata.get('requires_dist') or []
    extras = metadata.get('provides_extra') or []
    if (not isinstance(name, str) or not isinstance(version, str)
            or _normalized_package_name(name) != _normalized_package_name(candidate['name'])
            or _packaging_symbols()[2](version) != _packaging_symbols()[2](candidate['version'])
            or not isinstance(requirements, list) or not all(isinstance(item, str) for item in requirements)
            or not isinstance(extras, list) or not all(isinstance(item, str) for item in extras)):
        raise RuntimeError('native single-source package identity/requirements differ')
    # The selected package's PEP 517 build environments were inspected before
    # TMPDIR cleanup. Their exact distributions are recursively acquired later.
    return {'kind': 'sdist', 'name': name, 'version': version,
            'filename': filename, 'url': url, 'sha256': sha,
            'requirements': sorted(set(normalize_legacy_source_requirement(row)
                                       for row in requirements)),
            'provides_extra': sorted(set(extras)),
            'build_requirements': observed_builds,
            **_candidate_yank_provenance(candidate)}


def _native_solver_cache(pool):
    """Share single-flight PyPI metadata and verified source results across groups."""
    with pool._state_lock:
        cache = getattr(pool, '_native_verified_solver_cache', None)
        if cache is None:
            cache = {'release_metadata': _SingleFlightCache(),
                     'artifact_metadata': _SingleFlightCache(),
                     'releases': _SingleFlightCache(),
                     'native_source_probe': _native_source_candidate_metadata,
                     'sources_require_locked_python': True}
            pool._native_verified_solver_cache = cache
        return cache
'''
    source = replace_once(source,'def _native_resolve_registry(',helper+'\n\ndef _native_resolve_registry(', 'insert native per-source metadata resolver')

    replacement = '''
def _native_resolve_registry(pool, target, reqs, constraints, key, *, no_deps=False):
    """Resolve the whole graph using verified PyPI metadata, not pip backtracking.

    The existing conflict-directed backjump solver chooses one globally valid
    candidate per distribution. Wheels are inspected without installation, and
    each source distribution uses one isolated PEP 517 --no-deps metadata hook.
    Large transitive graphs are never passed to a single pip install command.
    The completed artifact graph is independently validated by _write_pip_plan.
    """
    target = _coerce_target(target)
    if _POOL_PROGRESS is None:
        print('[pool] verified registry graph: ' + key + ' (' +
              str(len(set(reqs))) + ' direct requirements)', flush=True)
    cache = _native_solver_cache(pool)
    activity = cache.get('prefetch_controller')
    if activity is not None:
        activity.enter()
    try:
        return _resolve_registry_plan(pool, target, reqs, constraints, key,
                                      no_deps=no_deps, resolver_cache=cache,
                                      materialize=True)
    finally:
        if activity is not None:
            activity.leave()
'''
    source = replace_function(source, '_native_resolve_registry', replacement)

    needle = "    prefetch_controller=resolver_cache.get('prefetch_controller')\n"
    source = replace_once(source, needle, needle + "    source_probe=resolver_cache.get('native_source_probe')\n    wheel_only=(resolver_cache.get('sources_require_locked_python') is True\n                and not target.python_artifact_sha256)\n", 'solver source probe config')
    source = replace_once(source,
        "                if not candidates:\n                    for pending in domain_futures.values():pending.cancel()",
        "                if wheel_only:\n"
        "                    candidates=[row for row in candidates if row['kind']=='wheel']\n"
        "                if not candidates:\n                    for pending in domain_futures.values():pending.cancel()",
        'golden wheel-only candidate domain')

    old = '''        record=_candidate_release_metadata(
            pool,candidate,key,target,probe_cache,artifact_cache,no_deps=no_deps)
'''
    new = '''        if candidate['kind'] == 'sdist' and source_probe is not None:
            # Source metadata is always obtained from the selected target's
            # actual PEP 517 hooks. No static approximation or silent fallback.
            identity=('native-source',_candidate_probe_identity(candidate,target,no_deps))
            artifact_identity=('native-source-artifact',_target_fingerprint(target),
                               _candidate_artifact_identity(candidate)[0],candidate['filename'])
            record=_memo_get_or_compute(probe_cache,identity,
                lambda:_memo_get_or_compute(artifact_cache,artifact_identity,
                    lambda:source_probe(pool,candidate,key,target)))
        else:
            record=_candidate_release_metadata(
                pool,candidate,key,target,probe_cache,artifact_cache,no_deps=no_deps)
'''
    source = replace_once(source, old, new, 'solver source probe branch')
    source = replace_once(source,
        'def _materialize_solution(pool,records,key,target,artifact_cache,executor=None):',
        'def _materialize_solution(pool,records,key,target,artifact_cache,executor=None,source_probe=None):',
        'solution materializer signature')
    source = replace_once(source,
        '''        actual=_materialize_candidate_metadata(pool,candidate,key,target,artifact_cache)
''',
        '''        if expected['kind']=='sdist' and source_probe is not None:
            # One verified source/target result is reused across solver probes
            # and checkpoint materialization, without re-running build hooks.
            identity=('native-source-artifact',_target_fingerprint(target),
                      expected['sha256'],expected['filename'])
            actual=_memo_get_or_compute(artifact_cache,identity,
                lambda:source_probe(pool,candidate,key,target))
            size=pool.verify_object(actual['sha256'])
            pool.reference(actual['sha256'],'python-source',key,size)
        else:
            actual=_materialize_candidate_metadata(pool,candidate,key,target,artifact_cache)
''', 'solution source materialization')
    # Ensures source build requirements also agree: comparing only runtime deps
    # would silently weaken the observed PEP 517 closure during checkpointing.
    source = replace_once(source,
        '''                or _candidate_yank_provenance(candidate)!={
''',
        '''                or (expected['kind']=='sdist' and source_probe is not None
                    and actual.get('build_requirements')!=expected.get('build_requirements'))
                or _candidate_yank_provenance(candidate)!={
''','source build requirement invariant')
    source = replace_once(source,
        '''    return (_materialize_solution(pool,solved,key,target,artifact_cache,executor=metadata_executor)
            if materialize else solved)''',
        '''    return (_materialize_solution(pool,solved,key,target,artifact_cache,
                                  executor=metadata_executor,source_probe=source_probe)
            if materialize else solved)''', 'solver source materializer propagation')
    source = replace_function(source, 'acquire_pip_groups', '''
def acquire_pip_groups(pool, groups):
    """Share bounded metadata I/O across concurrent verified closure solvers."""
    ordered=sorted(groups.items())
    if not ordered:
        return
    closure_workers, metadata_workers = _pip_worker_controls()
    if (type(closure_workers) is not int or closure_workers < 1
            or type(metadata_workers) is not int or metadata_workers < 1):
        raise RuntimeError('invalid configured pip solver concurrency')
    workers=min(closure_workers,len(ordered))
    if _POOL_PROGRESS is None:
        print('[pool] verified Pip graph solver: '+str(len(ordered))+
              ' closures, '+str(workers)+' closure workers, '+str(metadata_workers)+
              ' shared metadata workers; host-only', flush=True)
    _pool_progress('Pip closures',0,len(ordered),'closures',f'{workers} workers')
    cache=_native_solver_cache(pool)
    with concurrent.futures.ThreadPoolExecutor(max_workers=metadata_workers,
            thread_name_prefix='verified-pypi-metadata') as io_executor:
        with pool._state_lock:
            cache['metadata_executor']=io_executor
            cache['metadata_prefetch']=_metadata_prefetch_width(workers,metadata_workers)
            cache['prefetch_controller']=_ResolverActivity(metadata_workers)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers,
                    thread_name_prefix='verified-pip-closure') as executor:
                futures={executor.submit(acquire_pip_group,pool,key,group):key
                         for key,group in ordered}
                errors=[];done=0
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                        done+=1
                        _pool_progress('Pip closures',done,len(ordered),'closures',
                                       f'{workers} workers')
                    except BaseException as exc:
                        errors.append((futures[future],exc))
                        for other in futures:
                            if not other.done():other.cancel()
                if errors:
                    key,exc=min(errors,key=lambda row:row[0])
                    raise RuntimeError('verified pip closure '+key+' failed: '+str(exc)) from exc
        finally:
            with pool._state_lock:
                cache.pop('metadata_executor',None)
                cache.pop('metadata_prefetch',None)
                cache.pop('prefetch_controller',None)
''')
    return source


def patch_client(source):
    replacement = '''
def broker_read_resilient(cfg, action, payload=None, *, outage_seconds=None):
    """Read-only recovery with bounded latency and visible, actual outage time.

    A lost read may be repeated. Mutations (e.g. prepare_templates) are never
    replayed. An unreachable broker is not mistaken for a running worker or
    a successful fetch, even when its Cloudflare tunnel container is healthy.
    """
    controls_path = ROOT / 'config/preparation.toml'
    if controls_path.is_symlink() or not controls_path.is_file():
        raise RuntimeError('missing versioned broker monitoring policy')
    with controls_path.open('rb') as handle:
        controls = tomllib.load(handle).get('acquisition')
    if not isinstance(controls, dict):
        raise RuntimeError('invalid broker monitoring policy')
    request_limit = controls.get('broker_read_timeout_seconds')
    report_interval = controls.get('broker_outage_report_seconds')
    deadline = controls.get('broker_outage_timeout_seconds') if outage_seconds is None else outage_seconds
    if (type(request_limit) is not int or request_limit < 1
            or type(report_interval) is not int or report_interval < 1
            or type(deadline) not in (int, float) or deadline <= 0
            or report_interval >= deadline):
        raise RuntimeError('invalid configured broker monitoring timeouts')
    started = time.monotonic()
    last_report = started
    retries = 0
    last_error = ''
    while True:
        elapsed = time.monotonic() - started
        remaining = deadline - elapsed
        if remaining <= 0:
            raise RuntimeError('broker read link unavailable for %.0f seconds during %s '
                               '(last error: %s); preparation outcome unconfirmed; '
                               'state and workers retained; rerun the explicit fetch '
                               'only after checking broker health' %
                               (elapsed, action, last_error))
        try:
            result = broker(cfg, action, payload, timeout=min(request_limit,remaining))
        except (TransportFailure, RemoteFailure) as exc:
            if isinstance(exc, IdentityFailure):
                raise
            if (isinstance(exc, RemoteFailure) and getattr(exc, 'status', None)
                    not in {502, 503, 504, 520, 521, 522, 523, 524}):
                raise
            last_error = ('HTTP ' + str(exc.status) if isinstance(exc, RemoteFailure)
                          else type(exc).__name__ + ': ' + str(exc))
            elapsed = time.monotonic() - started
            if retries == 0 or elapsed - (last_report-started) >= report_interval:
                print('[broker] connexion interrompue pendant %.0fs | requête %s '
                      '| essai %s | %s | aucune VM relancée' %
                      (elapsed, action, retries+1, last_error), flush=True)
                last_report = time.monotonic()
            retries += 1
            remaining = deadline - (time.monotonic() - started)
            if remaining <= 0:
                continue
            time.sleep(min(remaining, request_limit, 2**min(retries,5)))
        else:
            if retries:
                print('[broker] connexion rétablie après %.0fs | %s | %s essais' %
                      (time.monotonic()-started, action, retries), flush=True)
            return result
'''
    source = replace_function(source, 'broker_read_resilient', replacement)
    # The unit's WantedBy target is inert until enabled. `make up` previously
    # started it transiently, so after a host reboot Cloudflare's Docker tunnel
    # restarted but the native broker did not.
    source = replace_once(source,
        'run(["systemctl", "start", "gpt-trace-distributed-broker.service"])',
        'run(["systemctl", "enable", "--now", "gpt-trace-distributed-broker.service"])',
        'make up enable persistent broker')
    # Global/local shutdown must remain intentional after the next reboot.
    source = replace_once(source,
        "        result = local_down(cfg)\n        execution_tunnel(cfg, 'down')",
        "        result = local_down(cfg)\n"
        "        run(['systemctl', 'disable', 'gpt-trace-distributed-broker.service'])\n"
        "        execution_tunnel(cfg, 'down')",
        'make down disable broker')
    return source


def patch_policy(source):
    marker = 'pip_stall_timeout_seconds = 120\n'
    ensure(source.count(marker) == 1, 'versioned pip controls')
    return source.replace(marker, marker + '''# All broker reads are read-only and bounded; tunnel outages are visible.
broker_read_timeout_seconds = 15
broker_outage_report_seconds = 30
broker_outage_timeout_seconds = 180
''',1)


TEST_SOURCE = r'''"""No network/KVM: regression tests for verified graph + broker outages."""
from __future__ import annotations
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[2]

def load(relative, name):
    spec=importlib.util.spec_from_file_location(name,ROOT/relative)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_large_group_never_calls_monolithic_pip():
    pool=load('scripts/superbench_pool.py','verified_group_under_test')
    from test_superbench_pool import fixture_target
    actual_target=fixture_target('3.8.20').as_dict()
    expected=[{'kind':'wheel','name':'demo','version':'1.0',
               'filename':'demo-1.0-py3-none-any.whl',
               'sha256':'f'*64,'url':'https://files.pythonhosted.org/demo.whl',
               'requirements':[],'provides_extra':[]}]
    with tempfile.TemporaryDirectory() as temp:
        candidate=pool.Pool(Path(temp))
        with patch.object(pool,'_resolve_registry_plan',return_value=expected) as graph, \
             patch.object(pool,'_native_metadata_command',side_effect=AssertionError('whole-group pip forbidden')), \
             patch.object(pool,'_native_locked_python',side_effect=AssertionError('no target install required')):
            result=pool._native_resolve_registry(candidate,actual_target,{'demo==1.0'},(), 'one')
        assert result==expected
        assert graph.call_args.kwargs['materialize'] is True
        assert graph.call_args.kwargs['resolver_cache']['native_source_probe'] is pool._native_source_candidate_metadata


def test_sdist_is_hash_bound_and_native_pep517_is_no_deps():
    pool=load('scripts/superbench_pool.py','verified_sdist_under_test')
    from test_superbench_pool import fixture_target
    target=fixture_target('3.8.20').as_dict()
    body=b'verified source archive'
    sha=hashlib.sha256(body).hexdigest()
    candidate={'kind':'sdist','name':'source-demo','version':'1.0',
               'filename':'source_demo-1.0.tar.gz',
               'item':{'url':'https://files.pythonhosted.org/packages/source_demo-1.0.tar.gz',
                       'digests':{'sha256':sha}}}
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp)
        candidate_pool=pool.Pool(root/'stage')
        source=candidate_pool.objects/sha[:2]/sha
        source.parent.mkdir(parents=True,exist_ok=True)
        source.write_bytes(body)
        runtime_root=root/'runtime';runtime_root.mkdir()
        runtime={'root':runtime_root,'env':{'PATH':'/usr/bin:/bin'}}
        python_path=Path('/usr/bin/python3')
        def metadata(argv,runtime,directory):
            assert '--no-deps' in argv and '--use-pep517' in argv
            assert '--report' in argv and '--requirement' not in argv
            archive=Path(argv[-1]);assert archive.read_bytes()==body
            report=Path(argv[argv.index('--report')+1])
            report.write_text(json.dumps({'install':[{'download_info':{'url':archive.as_uri()},
                'metadata':{'name':'source-demo','version':'1.0',
                'requires_dist':['dependency>=2'],'provides_extra':['tests']}}]}))
            return [['setuptools==70.0.0']]
        with patch.object(candidate_pool,'download',return_value=sha), \
             patch.object(pool,'_native_pool_runtime',return_value=runtime), \
             patch.object(pool,'_native_locked_python',return_value=python_path), \
             patch.object(pool,'_native_metadata_command',side_effect=metadata):
            result=pool._native_source_candidate_metadata(candidate_pool,candidate,'grp',target)
        assert result['requirements']==['dependency>=2']
        assert result['build_requirements']==[['setuptools==70.0.0']]
        assert result['sha256']==sha
        assert result['url']==candidate['item']['url']


def test_source_probe_participates_in_full_graph_and_materializes():
    pool=load('scripts/superbench_pool.py','verified_graph_integration_under_test')
    from test_superbench_pool import fixture_target
    target=fixture_target('3.8.20').as_dict()
    from packaging.version import Version
    sha=hashlib.sha256(b'package').hexdigest()
    selected={'kind':'sdist','name':'demo','version':'1.0',
              'filename':'demo-1.0.tar.gz',
              'item':{'url':'https://files.pythonhosted.org/packages/demo-1.0.tar.gz',
                      'digests':{'sha256':sha}}}
    row={'kind':'sdist','name':'demo','version':'1.0',
         'filename':selected['filename'],'sha256':sha,
         'url':selected['item']['url'],'requirements':[],
         'provides_extra':[],'build_requirements':[['setuptools==70']]}
    with tempfile.TemporaryDirectory() as temp:
        candidate=pool.Pool(Path(temp))
        path=candidate.objects/sha[:2]/sha
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'package')
        calls=[]
        def source_probe(*args):calls.append(args);return row
        cache={'native_source_probe':source_probe,'release_metadata':pool._SingleFlightCache(),
               'artifact_metadata':pool._SingleFlightCache(),
               'releases':pool._SingleFlightCache()}
        with patch.object(pool,'_candidate_versions',return_value=[selected]), \
             patch.object(pool,'_candidate_release_metadata',side_effect=AssertionError('sdist static approximation forbidden')):
            solved=pool._resolve_registry_plan(candidate,target,{'demo==1.0'},(), 'native',resolver_cache=cache)
        assert solved==[row]
        assert len(calls)==1  # Same source candidate never rebuilt during finalization.



def test_golden_target_never_selects_source_without_locked_python():
    pool=load('scripts/superbench_pool.py','verified_wheel_only_under_test')
    from test_superbench_pool import fixture_target
    target=fixture_target('3.8.20').as_dict()
    target['python_artifact_sha256']=None
    target['source']='verified-target-interpreter'
    target['interpreter_sha256']='f'*64
    artifact=lambda kind, version: {'kind':kind,'name':'demo','version':version,
        'filename':'demo-'+version+('.tar.gz' if kind=='sdist' else '-py3-none-any.whl'),
        'item':{'url':'https://files.pythonhosted.org/demo',
                'digests':{'sha256':hashlib.sha256(version.encode()).hexdigest()}}}
    source=artifact('sdist','2.0');wheel=artifact('wheel','1.0')
    def metadata(_pool,row,*_args,**_kwargs):
        assert row['kind']=='wheel'
        return {'kind':'wheel','name':'demo','version':row['version'],
                'filename':row['filename'], 'sha256':row['item']['digests']['sha256'],
                'url':row['item']['url'], 'requirements':[], 'provides_extra':[]}
    with tempfile.TemporaryDirectory() as temp:
        candidate=pool.Pool(Path(temp))
        with patch.object(pool,'_candidate_versions',return_value=[source,wheel]), \
             patch.object(pool,'_candidate_release_metadata',side_effect=metadata):
            resolved=pool._resolve_registry_plan(candidate,target,{'demo>=1'},(), 'golden',
                resolver_cache={'sources_require_locked_python':True},materialize=False)
    assert len(resolved)==1 and resolved[0]['version']=='1.0'


def test_execution_enables_broker_on_up_and_disables_on_down(monkeypatch,tmp_path):
    client=load('scripts/distributed.py','broker_boot_semantics_under_test')
    commands=[]
    cfg={'paths':{'base_image':tmp_path/'base.qcow2'},'deployment':{'role':'execution'}}
    monkeypatch.setattr(client,'host',lambda *_args,**_kwargs:None)
    monkeypatch.setattr(client,'install_unit',lambda *_args:None)
    monkeypatch.setattr(client,'execution_environment',lambda *_args:None)
    monkeypatch.setattr(client,'run',lambda argv,**_kwargs:commands.append(argv))
    monkeypatch.setattr(client,'broker',lambda *_args,**_kwargs:{'status':'ok'})
    monkeypatch.setattr(client,'execution_tunnel',lambda *_args:None)
    monkeypatch.setattr(client,'local_down',lambda *_args:{'stopped':True})
    client.execution(cfg,'up',None)
    client.execution(cfg,'down',None)
    assert ['systemctl','enable','--now','gpt-trace-distributed-broker.service'] in commands
    assert ['systemctl','disable','gpt-trace-distributed-broker.service'] in commands

def test_broker_outage_reports_without_silent_hour(monkeypatch,capsys):
    client=load('scripts/distributed.py','verified_client_under_test')
    clock=[0.0]
    monkeypatch.setattr(client.time,'monotonic',lambda:clock[0])
    monkeypatch.setattr(client.time,'sleep',lambda amount:clock.__setitem__(0,clock[0]+amount))
    monkeypatch.setattr(client,'ROOT',ROOT)
    calls=[]
    def broken(*args,**kwargs):
        calls.append(kwargs['timeout'])
        raise client.TransportFailure('synthetic closed tunnel')
    monkeypatch.setattr(client,'broker',broken)
    with pytest.raises(RuntimeError,match='outcome unconfirmed'):
        client.broker_read_resilient({},'template_preparation_status',{})
    assert calls and all(0 < value <= 15 for value in calls)
    logged=capsys.readouterr().out
    assert 'connexion interrompue' in logged and 'aucune VM relancée' in logged
    assert len(logged.splitlines())<=8


def test_broker_recovery_is_read_only(monkeypatch,capsys):
    client=load('scripts/distributed.py','verified_client_recovery_under_test')
    monkeypatch.setattr(client,'ROOT',ROOT)
    calls=[]
    def once(*args,**kwargs):
        calls.append(args[1])
        if len(calls)==1: raise client.TransportFailure('transient')
        return {'phase':'running'}
    monkeypatch.setattr(client,'broker',once)
    monkeypatch.setattr(client.time,'sleep',lambda _seconds:None)
    assert client.broker_read_resilient({},'template_preparation_status',{})=={'phase':'running'}
    assert calls==['template_preparation_status','template_preparation_status']
    assert 'connexion rétablie' in capsys.readouterr().out
'''


def write_atomic(path, data):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.'+path.name+'-', dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        if path.exists():
            os.chmod(temp,path.stat().st_mode & 0o777)
        os.replace(temp,path)
    finally:
        Path(temp).unlink(missing_ok=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root',type=Path,nargs='?',default=Path('.'))
    parser.add_argument('--check',action='store_true',help='validate the source/patch without writing')
    args=parser.parse_args()
    root=args.root.resolve(strict=True)
    inputs=(SCRIPT,CLIENT,POLICY)
    for path in inputs:
        file=root/path
        ensure(file.is_file() and not file.is_symlink() and file.resolve().is_relative_to(root),
               'unsafe or absent repository input '+str(path))
    ensure(not (root/TESTS).is_symlink(),'test output path is a symlink')
    originals={path:(root/path).read_text(encoding='utf-8') for path in inputs}
    ensure(not (root/TESTS).exists(),'test output already exists')
    changes={SCRIPT:patch_pool(originals[SCRIPT]),CLIENT:patch_client(originals[CLIENT]),
             POLICY:patch_policy(originals[POLICY]),TESTS:TEST_SOURCE}
    for path,data in changes.items():
        if path.suffix=='.py':
            ast.parse(data,filename=str(path))
    if args.check:
        for path,data in changes.items():
            print(f'OK {path}: {len(data)} bytes')
        print('READY; no files changed')
        return
    for path in originals:
        ensure((root/path).read_text(encoding='utf-8')==originals[path],
               'source changed during patch: '+str(path))
    written=[]
    try:
        for path,text in changes.items():
            write_atomic(root/path,text)
            written.append(path)
            print('UPDATED',path)
    except BaseException:
        # Never leave a half-applied resolver/broker contract if a write fails.
        for path in reversed(written):
            if path in originals:
                write_atomic(root/path,originals[path])
            else:
                (root/path).unlink()
        raise
    print('Run: python3 -m pytest -q tests/distributed/test_verified_closure_and_broker.py')


if __name__=='__main__':
    try: main()
    except (OSError,ValueError,RuntimeError,SyntaxError) as exc:
        print('patch refused: '+str(exc),file=sys.stderr)
        raise SystemExit(1)
