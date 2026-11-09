"""Actual compiled Rust worker + Python oracle integration; offline fixture only."""
from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path
from unittest.mock import patch

import superbench_pool as pool
from test_superbench_pool import fixture_target


def _versioned(name, version):
    identity=hashlib.sha256(f'{name}/{version}'.encode()).hexdigest()
    return {'name':name,'version':version,'kind':'wheel',
            'filename':f'{name}-{version}-py3-none-any.whl',
            'item':{'url':f'https://files.pythonhosted.org/{name}-{version}.whl',
                    'digests':{'sha256':identity}}}


def test_compiled_rust_backtracks_to_compatible_version():
    # root>=1 initially chooses 2, but dep==1 is already a required root.
    universes={'root':[_versioned('root','2'),_versioned('root','1')],
               'dep':[_versioned('dep','2'),_versioned('dep','1')]}
    deps={('root','2'):['dep==2'],('root','1'):['dep==1']}
    def domain(_pool,name,requirements,constraints,target,**_kwargs):
        from packaging.version import Version
        return [c for c in universes[name]
                if all(not req.specifier or req.specifier.contains(Version(c['version']),prereleases=True)
                       for req in [*requirements,*constraints])]
    def metadata(_pool,candidate,key,target,*_args,**_kwargs):
        return {**candidate, 'sha256':candidate['item']['digests']['sha256'],
                'url':candidate['item']['url'],'requirements':deps.get((candidate['name'],candidate['version']),[]),
                'provides_extra':[]}
    with tempfile.TemporaryDirectory() as temp, \
         patch.object(pool,'_candidate_versions',side_effect=domain), \
         patch.object(pool,'_candidate_release_metadata',side_effect=metadata):
        plan=pool._resolve_registry_plan(
            pool.Pool(Path(temp)),fixture_target().as_dict(),{'root>=1','dep==1'},[],
            'native-rust-graph-test',materialize=False)
    assert [(row['name'],row['version']) for row in plan]==[('dep','1'),('root','1')]


def test_compiled_rust_unsat_cannot_claim_success():
    candidate=_versioned('root','1')
    def domain(_pool,name,requirements,constraints,target,**_kwargs):
        if name=='root':return [candidate]
        return []
    def metadata(_pool,item,key,target,*_args,**_kwargs):
        return {**item,'sha256':item['item']['digests']['sha256'],
                'url':item['item']['url'],'requirements':['missing==1'],
                'provides_extra':[]}
    import pytest
    with tempfile.TemporaryDirectory() as temp, \
         patch.object(pool,'_candidate_versions',side_effect=domain), \
         patch.object(pool,'_candidate_release_metadata',side_effect=metadata), \
         pytest.raises(RuntimeError,match='unsatisfiable'):
        pool._resolve_registry_plan(
            pool.Pool(Path(temp)),fixture_target().as_dict(),{'root==1'},[],
            'native-rust-unsat-test',materialize=False)



def _offline_graph(name_versions, dependencies, roots, target):
    """Run the real mandatory Rust search over a fully deterministic PyPI oracle."""
    from packaging.version import Version
    universes={name:[_versioned(name,str(index)) for index in range(count)]
               for name,count in name_versions.items()}

    def domain(_pool,name,requirements,constraints,_target,**_kwargs):
        return [candidate for candidate in universes[name]
                if all(not req.specifier or req.specifier.contains(
                    Version(candidate['version']),prereleases=True)
                    for req in [*requirements,*constraints])]

    def metadata(_pool,candidate,key,_target,probe_cache,artifact_cache,*,no_deps=False):
        identity=pool._candidate_probe_identity(candidate,_target,no_deps)
        def compute():
            return {**candidate, 'sha256':candidate['item']['digests']['sha256'],
                    'url':candidate['item']['url'],
                    'requirements':dependencies.get((candidate['name'],candidate['version']),[]),
                    'provides_extra':[]}
        return pool._memo_get_or_compute(probe_cache,identity,compute)

    with tempfile.TemporaryDirectory() as temp, \
         patch.object(pool,'_candidate_versions',side_effect=domain), \
         patch.object(pool,'_candidate_release_metadata',side_effect=metadata):
        solution=pool._resolve_registry_plan(
            pool.Pool(Path(temp)),target.as_dict(),roots,[],
            'native-rust-learned-clause-provenance-test',materialize=False)
    return {candidate['name']:int(candidate['version']) for candidate in solution}


def test_compiled_rust_keeps_causes_of_forward_pruned_alternatives():
    # A previously inspected candidate may be ruled out by the current B.
    # Discarding its conflict while exploring the surviving A releases makes
    # the old Rust code incorrectly backjump past B==0 and report global UNSAT.
    deps={
        ('a','0'):['b==1'],
        ('a','1'):['a<2','c>=1'],
        ('c','0'):['c>=1'],
        ('c','1'):['b==1'],
        ('c','2'):['a<2','b==1','c!=1'],
    }
    result=_offline_graph({'a':3,'b':2,'c':3},deps,{'a','b','c'},fixture_target())
    assert result['b']==1 and result['c']==1
    assert result['a'] in (0,1,2)


def test_compiled_rust_preserves_guards_of_skipped_learned_clauses():
    # Two learned exclusions under B==0 must NOT become unconditional when
    # this package is revisited under another unrelated decision.
    deps={
        ('a','0'):['a<=1','b>=1'],
        ('a','1'):['a>=9','b>=1','d==2'],
        ('b','1'):['a<=1'],
        ('c','0'):['a<=1','c<=1','d>=1'],
        ('c','1'):['a>=9','b==0'],
        ('d','0'):['c==0'],
        ('e','0'):['c==0','d!=1','e==1'],
        ('e','1'):['c<=1'],
        ('e','2'):['a==0'],
    }
    result=_offline_graph({'a':2,'b':3,'c':2,'d':3,'e':3},deps,
                          {'b','d','e'},fixture_target())
    assert result['b'] in (0,1,2)
    for (name,version), requirements in deps.items():
        if result.get(name)!=int(version):
            continue
        from packaging.requirements import Requirement
        for raw in requirements:
            req=Requirement(raw)
            assert req.name in result and req.specifier.contains(str(result[req.name]))


def test_compiled_rust_backtracks_after_proven_invalid_target_source():
    # An old cached sdist with Python-2-only setup.py cannot be used by the
    # locked target. Its exact syntax rejection must not abort the whole graph.
    bad = _versioned('example', '0.5')
    bad['kind'] = 'sdist'
    bad['filename'] = 'example-0.5.tar.gz'
    good = _versioned('example', '1')
    probed = []

    def domain(_pool, name, requirements, constraints, target, **_kwargs):
        from packaging.version import Version
        assert name == 'example'
        return [candidate for candidate in (bad, good)
                if all(not req.specifier or req.specifier.contains(Version(candidate['version']), prereleases=True)
                       for req in [*requirements, *constraints])]

    def source(_pool, candidate, key, target):
        probed.append(candidate['version'])
        raise pool._IncompatibleSourceSyntax('verified setup.py is Python 2 syntax under target Python 3')

    def wheel(_pool, candidate, key, target, *_args, **_kwargs):
        assert candidate is good
        return {**candidate, 'sha256': candidate['item']['digests']['sha256'],
                'url': candidate['item']['url'], 'requirements': [], 'provides_extra': []}

    with tempfile.TemporaryDirectory() as temp, \
         patch.object(pool, '_candidate_versions', side_effect=domain), \
         patch.object(pool, '_native_source_candidate_metadata', side_effect=source), \
         patch.object(pool, '_candidate_release_metadata', side_effect=wheel):
        plan = pool._resolve_registry_plan(
            pool.Pool(Path(temp)), fixture_target().as_dict(), {'example>=0.5'}, [],
            'invalid-target-source-regression', materialize=False,
            resolver_cache={'native_source_probe': pool._native_source_candidate_metadata})

    assert [(row['name'], row['version']) for row in plan] == [('example', '1')]
    assert probed == ['0.5']


def test_compiled_rust_does_not_reinterpret_metadata_infrastructure_failure():
    bad = _versioned('example', '0.5')
    bad['kind'] = 'sdist'
    bad['filename'] = 'example-0.5.tar.gz'
    good = _versioned('example', '1')

    def domain(_pool, name, requirements, constraints, target, **_kwargs):
        return [bad, good]

    def source(_pool, candidate, key, target):
        raise RuntimeError('verified metadata network unavailable')

    import pytest
    with tempfile.TemporaryDirectory() as temp, \
         patch.object(pool, '_candidate_versions', side_effect=domain), \
         patch.object(pool, '_native_source_candidate_metadata', side_effect=source), \
         pytest.raises(RuntimeError, match='verified metadata network unavailable'):
        pool._resolve_registry_plan(
            pool.Pool(Path(temp)), fixture_target().as_dict(), {'example>=0.5'}, [],
            'invalid-target-source-infra-regression', materialize=False,
            resolver_cache={'native_source_probe': pool._native_source_candidate_metadata})
