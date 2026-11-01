"""Regression tests for durable Conda acquisition and safe offline recovery."""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT=Path(__file__).resolve().parents[2]


def load_script(relative):
    path=ROOT/relative
    spec=importlib.util.spec_from_file_location('test_'+path.stem,path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pool_stage(stage):
    for name in ('downloads','objects','metadata','git','git-extra'):
        (stage/name).mkdir(parents=True,exist_ok=True)
    (stage/'STAGING').write_text('test staging')
    return stage


def fake_lock(blobs):
    artifacts={hashlib.sha256(data).hexdigest():{'url':'https://conda.anaconda.org/test/'+str(i),'sha256':hashlib.sha256(data).hexdigest()} for i,data in enumerate(blobs)}
    return {'artifacts':artifacts,'environments':{'test':{'transactions':[{'key':'env-test','python':'3.11','packages':sorted(artifacts)}]}}}


def test_archive_is_durable_before_later_failure(tmp_path,monkeypatch,capsys):
    module=load_script('scripts/superbench_pool.py')
    lock=fake_lock([b'alpha',b'beta',b'gamma'])
    ordered=sorted(lock['artifacts'])
    raw={sha:next(data for data in (b'alpha',b'beta',b'gamma') if hashlib.sha256(data).hexdigest()==sha)
         for sha in ordered}
    path=pool_stage(tmp_path/'stage')
    pool=module.Pool(path)
    monkeypatch.setattr(module,'_acquisition_workers',lambda:1)
    monkeypatch.setattr(module,'_conda_progress_interval',lambda:1)
    def fake_fetch(url,target,*,sha,on_block=None,**kwargs):
        if sha==ordered[-1]:raise ConnectionError('synthetic interruption')
        with target.open('xb') as out:out.write(raw[sha]);out.flush()
        if on_block is not None:on_block(len(raw[sha]))
        return sha
    monkeypatch.setattr(module,'fetch',fake_fetch)
    try:
        with pytest.raises(ConnectionError,match='synthetic interruption'):
            module.acquire_locked_conda(pool,lock)
        for sha in ordered[:-1]:
            target=path/'objects'/'sha256'/sha[:2]/sha
            assert target.is_file()
            assert target.read_bytes()==raw[sha]
            assert not (path/'downloads'/('conda-'+sha)).exists()
        assert 'Conda progress:' in capsys.readouterr().out
    finally:
        pool._pip_cache_context.cleanup()


def test_salvages_legacy_complete_archives_but_rejects_partial(tmp_path):
    module=load_script('scripts/superbench_pool.py')
    old=pool_stage(tmp_path/'old');new=pool_stage(tmp_path/'new')
    content=b'verified historical archive'
    sha=hashlib.sha256(content).hexdigest()
    other=b'partial archive'
    partial_sha=hashlib.sha256(other+b'not-present').hexdigest()
    (old/'downloads'/('conda-'+sha)).write_bytes(content)
    (old/'downloads'/('conda-'+partial_sha)).write_bytes(other)
    verified=module.salvage_verified_stage(old,new,conda_artifacts={sha:{},partial_sha:{}})
    assert sha in verified
    assert partial_sha not in verified
    assert (new/'objects'/'sha256'/sha[:2]/sha).read_bytes()==content
    assert not (new/'objects'/'sha256'/partial_sha[:2]/partial_sha).exists()
    assert (old/'downloads'/('conda-'+sha)).read_bytes()==content


def test_recovered_conda_download_requires_current_lock_identity(tmp_path):
    module=load_script('scripts/superbench_pool.py')
    old=pool_stage(tmp_path/'old');new=pool_stage(tmp_path/'new')
    content=b'valid but not in the current lock'
    sha=hashlib.sha256(content).hexdigest()
    (old/'downloads'/('conda-'+sha)).write_bytes(content)
    assert module.salvage_verified_stage(old,new,conda_artifacts={})==set()
    assert not (new/'objects'/'sha256'/sha[:2]/sha).exists()


def test_cleanup_protects_recoverable_stage(tmp_path):
    module=load_script('scripts/burn_fetch_zombies.py')
    stage=pool_stage(tmp_path/'stage')
    payload=b'complete hashed archive'
    sha=hashlib.sha256(payload).hexdigest()
    (stage/'downloads'/('conda-'+sha)).write_bytes(payload)
    assert module.recoverable(stage)
    (stage/'downloads'/('conda-'+sha)).write_bytes(b'partial')
    assert not module.recoverable(stage)
    (stage/'objects'/'sha256'/sha[:2]).mkdir(parents=True)
    (stage/'objects'/'sha256'/sha[:2]/sha).write_bytes(payload)
    assert module.recoverable(stage)


def test_cleanup_rejects_nonterminal_journal(tmp_path):
    module=load_script('scripts/burn_fetch_zombies.py')
    operation='a'*64
    directory=tmp_path/operation
    directory.mkdir()
    (directory/'state.json').write_text(json.dumps({
        'schema':1,'operation_id':operation,'attempt':1,'phase':'running',
        'compatibility':{'fetch_kind':'download-only-pool-v2'},
    }))
    with pytest.raises(RuntimeError,match='not a verified terminal'):
        module.journal_for(tmp_path,operation,1)


def test_admin_cleanup_requires_confirmation_and_retains_journal(tmp_path,monkeypatch,capsys):
    import os
    import types
    module=load_script('scripts/burn_fetch_zombies.py')
    checkout=tmp_path/'checkout';(checkout/'scripts').mkdir(parents=True)
    (checkout/'config').mkdir()
    storage=tmp_path/'storage';storage.mkdir()
    (checkout/'config'/'distributed.toml').write_text(
        '[paths]\nbase_image = '+json.dumps(str(storage/'base.qcow2'))+'\n')
    monkeypatch.setattr(module,'__file__',str(checkout/'scripts'/'burn_fetch_zombies.py'))
    monkeypatch.setattr(module.os,'geteuid',lambda:0)
    monkeypatch.setattr(module.pwd,'getpwnam',lambda name:types.SimpleNamespace(pw_uid=os.getuid()))
    monkeypatch.setattr(module,'has_running_owner',lambda *args,**kwargs:None)
    def command(args,**kwargs):
        if args[0]=='findmnt':return types.SimpleNamespace(stdout=str(storage)+'\n')
        if args[0]=='systemctl':return types.SimpleNamespace(stdout='inactive\n')
        raise AssertionError('unexpected external command')
    monkeypatch.setattr(module.subprocess,'run',command)
    preparations=storage/'preparations';preparations.mkdir()
    (preparations/'build-slot.lock').write_text('')
    operation=hashlib.sha256(b'fixture-operation').hexdigest()
    journal=preparations/operation;journal.mkdir()
    (journal/'state.json').write_text(json.dumps({
        'schema':1,'operation_id':operation,'attempt':1,'phase':'interrupted',
        'compatibility':{'fetch_kind':'download-only-pool-v2'},
        'scope':{'schema':1,'name':'prep-'+operation+'-1'},
    }))
    pool=storage/'dependency-pool';pool.mkdir()
    stage=pool/('incoming-'+operation+'-1')
    pool_stage(stage)
    module.main([])
    assert stage.is_dir()
    assert 'No files changed' in capsys.readouterr().out
    module.main(['--confirm','BURN_FETCH_ZOMBIES'])
    assert not stage.exists()
    assert (journal/'state.json').is_file()


def test_admin_cleanup_never_deletes_recoverable_without_published_proof(tmp_path,monkeypatch):
    import os
    import types
    module=load_script('scripts/burn_fetch_zombies.py')
    checkout=tmp_path/'checkout';(checkout/'scripts').mkdir(parents=True)
    (checkout/'config').mkdir()
    storage=tmp_path/'storage';storage.mkdir()
    (checkout/'config'/'distributed.toml').write_text(
        '[paths]\nbase_image = '+json.dumps(str(storage/'base.qcow2'))+'\n')
    monkeypatch.setattr(module,'__file__',str(checkout/'scripts'/'burn_fetch_zombies.py'))
    monkeypatch.setattr(module.os,'geteuid',lambda:0)
    monkeypatch.setattr(module.pwd,'getpwnam',lambda name:types.SimpleNamespace(pw_uid=os.getuid()))
    monkeypatch.setattr(module,'has_running_owner',lambda *args,**kwargs:None)
    def command(args,**kwargs):
        if args[0]=='findmnt':return types.SimpleNamespace(stdout=str(storage)+'\n')
        if args[0]=='systemctl':return types.SimpleNamespace(stdout='inactive\n')
        raise AssertionError('unexpected external command')
    monkeypatch.setattr(module.subprocess,'run',command)
    preparations=storage/'preparations';preparations.mkdir()
    (preparations/'build-slot.lock').write_text('')
    operation=hashlib.sha256(b'recoverable-operation').hexdigest()
    journal=preparations/operation;journal.mkdir()
    (journal/'state.json').write_text(json.dumps({
        'schema':1,'operation_id':operation,'attempt':1,'phase':'interrupted',
        'compatibility':{'fetch_kind':'download-only-pool-v2'},
        'scope':{'schema':1,'name':'prep-'+operation+'-1'},
    }))
    pool=storage/'dependency-pool';pool.mkdir()
    stage=pool/('incoming-'+operation+'-1')
    pool_stage(stage)
    content=b'verified dependency'
    sha=hashlib.sha256(content).hexdigest()
    (stage/'downloads'/('conda-'+sha)).write_bytes(content)
    module.main(['--confirm','BURN_FETCH_ZOMBIES'])
    assert stage.is_dir()
    assert (stage/'downloads'/('conda-'+sha)).read_bytes()==content
