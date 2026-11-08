"""Architecture invariants: no legacy graph search, no unverified Rust binary."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]


def test_native_engine_is_the_only_graph_search_path():
    source=(ROOT/'scripts/superbench_pool.py').read_text()
    body=source.split('def _resolve_registry_plan(',1)[1].split('\ndef _pip_plan_path(',1)[0]
    assert 'module.solve(globals(),' in body
    assert 'def search(' not in body
    assert 'ThreadPoolExecutor' not in body
    assert 'native_solver_source_sha256' in source


def test_worker_snapshot_includes_executable_binary_and_source_contract():
    contract=(ROOT/'shared/gpt_trace_transport/local_templates.py').read_text()
    staging=(ROOT/'apps/workstation-broker/src/workstation_broker/preparation.py').read_text()
    assert 'def fetch_runtime_executables(' in contract
    assert 'def fetch_runtime_build_inputs(' in contract
    assert 'def verify_fetch_runtime_build_identity(' in contract
    assert 'verify_fetch_runtime_build_identity(repository)' in staging
    assert 'verify_fetch_runtime_build_identity(snapshot)' in staging
    assert 'target.chmod(0o555 if is_binary else 0o444)' in staging
    assert 'expected_sources=current[\'fetch_sources\']' in staging


def test_build_is_offline_and_mandatory():
    source=(ROOT/'scripts/build.py').read_text()
    dispatch=(ROOT/'scripts/distributed.py').read_text()
    assert 'def build_verified_resolver(' in source
    assert "'--locked', '--offline'" in source
    assert 'build.build_verified_resolver(ROOT)' in dispatch
    assert dispatch.index('build.build_verified_resolver(ROOT)') < dispatch.index('build.build_host_broker(ROOT)')
