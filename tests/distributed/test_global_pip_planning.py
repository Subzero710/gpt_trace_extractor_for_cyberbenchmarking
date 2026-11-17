"""Global verified Pip planner, mocked at the external Rust/network boundary."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
from unittest.mock import patch

import pytest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('global_pip_under_test',ROOT/'scripts/superbench_pool.py')
pool=importlib.util.module_from_spec(spec)
spec.loader.exec_module(pool)


def target():
    model=pool._target_environment_module()
    import hashlib
    base=model.TargetEnvironment(
        markers={'implementation_name':'cpython','implementation_version':'3.10.14',
                 'os_name':'posix','platform_machine':'x86_64','platform_release':'test',
                 'platform_system':'Linux','platform_version':'test',
                 'python_full_version':'3.10.14','python_version':'3.10',
                 'platform_python_implementation':'CPython','sys_platform':'linux'},
        tags=('cp310-cp310-manylinux_2_17_x86_64','py3-none-any'), implementation='cpython',abi='cp310',architecture='x86_64',
        source='verified-target-interpreter',interpreter_sha256='f'*64)
    return model.conda_target(full_version='3.10.14',base_target=base,
        python_artifact_sha256=hashlib.sha256(b'python').hexdigest(),source='test')


def record(name,version,requires=()):
    raw=f'{name}=={version}'.encode()
    sha=hashlib.sha256(raw).hexdigest()
    return {'kind':'wheel','name':name,'version':str(version),
            'filename':f'{name}-{version}-py3-none-any.whl',
            'sha256':sha,'url':f'https://files.pythonhosted.org/{name}-{version}-py3-none-any.whl',
            'requirements':list(requires),'provides_extra':[]}


def group(env,name):
    return {'target':env.as_dict(), 'requirements':[name+'>=1'],
            'constraints':[], 'no_deps':False, 'required':True,
            'tasks':[name], 'steps':['install']}


@pytest.fixture
def candidate(tmp_path):
    selected=pool.Pool(tmp_path)
    yield selected
    selected._pip_cache_context.cleanup()


def test_global_minimizes_distinct_sha_without_mutating_requirements(candidate):
    left0={'status':'planned','packages':[record('common','1'),record('left','1')]}
    left1={'status':'planned','packages':[record('common','2'),record('left','1')]}
    right={'status':'planned','packages':[record('common','2'),record('right','1')]}
    chosen=pool._global_pip_choose(candidate,{'left':[left0,left1],'right':[right]})
    assert chosen['left'] is left1
    assert len(set().union(*(pool._global_pip_artifacts(x) for x in chosen.values()))) == 3
    assert pool._global_pip_choose(candidate,{'left':[left0,left1],'right':[right]},locked={'left':left0})['left'] is left0


def test_global_plans_all_before_materialization_and_coalesces_hashes(tmp_path, candidate):
    env=target()
    (tmp_path/'metadata').mkdir()
    initial={'left':group(env,'left'),'right':group(env,'right')}
    events=[]
    mutex=threading.Lock()
    def resolve(_pool,_target,reqs,_constraints,key,*,preferred_versions=None,materialize=True,**kw):
        assert materialize is False, 'planning must never materialize winner wheels'
        with mutex:events.append(('plan',key))
        name=next(iter(reqs)).split('>=')[0]
        version=('1' if name=='left' else '2')
        if preferred_versions and 'common' in preferred_versions:
            version=preferred_versions['common'][0]
        return sorted([record(name,'1',['common>=1']),record('common',version)],key=lambda x:x['name'])
    def materialize(_pool,rows,key,_target,_cache,**kw):
        with mutex:
            assert sum(1 for e in events if e[0]=='plan') >= len(initial)
            events.append(('download',key))
        for row in rows:
            blob=f"{row['name']}=={row['version']}".encode()
            folder=_pool.objects/row['sha256'][:2]
            folder.mkdir(exist_ok=True)
            output=folder/row['sha256']
            with mutex:
                if not output.exists():output.write_bytes(blob)
            _pool.reference(row['sha256'],'python',key,len(blob))
        return rows
    with patch.object(pool,'_pip_worker_controls',return_value=(2,2)), \
         patch.object(pool,'_native_resolve_registry',side_effect=resolve), \
         patch.object(pool,'_materialize_solution',side_effect=materialize), \
         patch.object(pool,'_resolver_runtime_identity',return_value={'test':'sealed'}):
        pool.acquire_pip_groups(candidate,initial)
    assert sum(1 for event in events if event[0]=='download') == 2
    plans=[json.loads((tmp_path/'metadata'/('pip-plan-'+key+'.json')).read_text()) for key in initial]
    versions=[{row['name']:row['version'] for row in plan['packages']} for plan in plans]
    assert versions[0]['common']==versions[1]['common']
    assert len({row['sha256'] for plan in plans for row in plan['packages']}) == 3
    assert len(list(candidate.objects.glob('*/*'))) == 3


def test_failed_required_planning_publishes_nothing(tmp_path, candidate):
    env=target()
    (tmp_path/'metadata').mkdir()
    groups={'broken':group(env,'broken'),'working':group(env,'working')}
    calls=[]
    def resolve(_pool,_target,reqs,_constraints,key,**kwargs):
        calls.append(key)
        if key=='broken':raise RuntimeError('registry metadata corrupt')
        return [record('working','1')]
    with patch.object(pool,'_pip_worker_controls',return_value=(2,2)), \
         patch.object(pool,'_native_resolve_registry',side_effect=resolve), \
         pytest.raises(RuntimeError, match='registry metadata corrupt'):
        pool.acquire_pip_groups(candidate,groups)
    assert not list((tmp_path/'metadata').glob('pip-plan-*.json'))
    assert not list(candidate.objects.glob('*/*'))


def test_build_graph_cycle_refused_before_materialization():
    with pytest.raises(RuntimeError,match='cyclic'):
        pool._global_pip_levels({'a':{},'b':{}},{'a':{'b'},'b':{'a'}})


def test_source_build_closures_become_required_and_preserve_target():
    env=target()
    main=group(env,'main')
    row=record('main','1')
    row.update(kind='sdist',filename='main-1.tar.gz',
               build_requirements=[['build-backend>=1','wheel>=1'],['wheel>=1']])
    with patch.object(pool,'_resolver_runtime_identity',return_value={'test':'sealed'}):
        children=pool._global_pip_child_groups('main',main,{'status':'planned','packages':[row]})
    assert len(children)==2
    assert all(info['required'] and info['target']==env.as_dict() for info in children.values())
    assert all(info['constraints']==[] for info in children.values())


def test_incompatible_literal_pin_has_empty_domain_without_pypi(candidate):
    env=target()
    reqs=[pool._parse_registry_requirement('botocore==1.25.7'),
          pool._parse_registry_requirement('botocore>=1.36.10,<1.37.0')]
    with patch.object(pool,'_registry_release_candidates',side_effect=AssertionError('unexpected full PyPI index')), \
         patch.object(pool,'_registry_exact_release_candidate',side_effect=AssertionError('unexpected exact PyPI query')):
        assert pool._candidate_versions(candidate,'botocore',reqs,[],env)==[]


def test_size_hint_breaks_equal_archive_count_ties(candidate):
    small=record('shared','1'); small['download_size']=123
    large=record('shared','2'); large['download_size']=5000
    unique=record('unique','1'); unique['download_size']=100
    choices={'left':[{'status':'planned','packages':[large]},
                     {'status':'planned','packages':[small]}],
             'right':[{'status':'planned','packages':[unique]}]}
    assert pool._global_pip_choose(candidate,choices)['left']['packages'][0]['version']=='1'


def test_recursive_build_dependency_resolved_before_parent_publication(tmp_path, candidate):
    env=target()
    (tmp_path/'metadata').mkdir()
    groups={'root':group(env,'root')}
    events=[]
    lock=threading.Lock()
    build_rows=['builder>=1']
    with patch.object(pool,'_resolver_runtime_identity',return_value={'test':'sealed'}):
        child_key=pool.pip_group_key(env,build_rows)
        def solve(_pool,_target,reqs,_constraints,key,*,materialize,**kwargs):
            assert materialize is False
            with lock:events.append(('plan',key))
            if key=='root':
                row=record('root','1')
                row['kind']='sdist'
                row['filename']='root-1.tar.gz'
                row['build_requirements']=[build_rows]
                return [row]
            assert key==child_key
            return [record('builder','1')]
        def materialize(_pool,rows,key,_target,_cache,**kwargs):
            with lock:events.append(('materialize',key))
            for row in rows:
                body=f"{row['name']}=={row['version']}".encode()
                path=_pool.objects/row['sha256'][:2]/row['sha256']
                path.parent.mkdir(exist_ok=True)
                if not path.exists():path.write_bytes(body)
                _pool.reference(row['sha256'],'python',key,len(body))
            return rows
        with patch.object(pool,'_pip_worker_controls',return_value=(2,2)), \
             patch.object(pool,'_native_resolve_registry',side_effect=solve), \
             patch.object(pool,'_materialize_solution',side_effect=materialize):
            pool.acquire_pip_groups(candidate,groups)
    assert ('plan',child_key) in events
    assert ('materialize',child_key) in events
    assert events.index(('plan',child_key)) < events.index(('materialize',child_key))
    assert (tmp_path/'metadata'/('pip-plan-'+child_key+'.json')).exists()
    parent=json.loads((tmp_path/'metadata/pip-plan-root.json').read_text())
    assert child_key in parent['build_plans']


def test_total_bytes_precede_number_of_archives_when_sizes_verified(candidate):
    huge=record('huge','1'); huge['download_size']=30000
    little1=record('little1','1'); little1['download_size']=100
    little2=record('little2','1'); little2['download_size']=200
    alternatives={'one':[{'status':'planned','packages':[huge]},
                         {'status':'planned','packages':[little1,little2]}]}
    assert len(pool._global_pip_choose(candidate,alternatives)['one']['packages'])==2
