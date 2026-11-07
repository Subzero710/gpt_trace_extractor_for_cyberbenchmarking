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
            pool.Pool(Path(temp)),fixture_target(),{'root>=1','dep==1'},[],
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
            pool.Pool(Path(temp)),fixture_target(),{'root==1'},[],
            'native-rust-unsat-test',materialize=False)
