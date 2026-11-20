"""The installed guest fingerprint excludes preparation-only runtime controls."""
from __future__ import annotations

from pathlib import Path

from scripts.build import _workstation_image_builder


def test_operational_controls_do_not_change_golden_input_fingerprint(monkeypatch):
    root = Path(__file__).resolve().parents[2]
    golden = _workstation_image_builder(root)
    original = golden._acquisition_controls()
    baseline = golden.golden_build_input_sha256()
    installed_payload = golden.guest_installation_contract()
    existing_contract = golden.guest_contract()

    changed = dict(original)
    changed["network_attempts"] += 1
    changed["progress_interval_seconds"] += 1
    changed["broker_read_timeout_seconds"] += 1
    changed["golden_download_attempts"] += 1
    changed["golden_download_retry_backoff_seconds"] = [
        *changed["golden_download_retry_backoff_seconds"],
        changed["golden_download_retry_backoff_seconds"][-1],
    ]
    monkeypatch.setattr(golden, "_acquisition_controls", lambda: changed)

    assert golden.guest_installation_contract() == installed_payload
    assert golden.guest_contract() != existing_contract
    assert golden.golden_build_input_sha256() == baseline
    assert golden.guest_contract().keys() == existing_contract.keys()
