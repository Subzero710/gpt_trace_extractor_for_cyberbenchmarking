from __future__ import annotations

from types import SimpleNamespace

import pytest

from gpt_trace_runner.exceptions import RecoveryIncomplete
from gpt_trace_runner.manual_kali import (
    MANUAL_ATTEMPT,
    MANUAL_TASK_ID,
    ManualKaliState,
    ManualKaliStore,
    require_manual_kali_stopped,
)


def state() -> ManualKaliState:
    return ManualKaliState(
        schema_version=1,
        phase="running",
        task_id=MANUAL_TASK_ID,
        attempt=MANUAL_ATTEMPT,
        task_fingerprint="a" * 64,
        environment_id="manual-env",
        started_at="2026-10-05T00:00:00Z",
    )


def test_manual_kali_store_roundtrip_and_clear(tmp_path):
    store = ManualKaliStore(tmp_path / "manual-kali.json")
    assert store.load() is None
    store.write(state())
    assert store.load() == state()
    assert not (tmp_path / "manual-kali.json.tmp").exists()
    store.clear()
    assert store.load() is None


def test_manual_kali_store_rejects_invalid_state(tmp_path):
    target = tmp_path / "manual-kali.json"
    target.write_text('{"schema_version":999}', encoding="utf-8")
    with pytest.raises(RecoveryIncomplete):
        ManualKaliStore(target).load()


def test_benchmark_guard_rejects_manual_state(tmp_path):
    target = tmp_path / "manual-kali.json"
    ManualKaliStore(target).write(state())
    settings = SimpleNamespace(manual_kali_state_path=target)
    with pytest.raises(RecoveryIncomplete, match="manual Kali"):
        require_manual_kali_stopped(settings)
