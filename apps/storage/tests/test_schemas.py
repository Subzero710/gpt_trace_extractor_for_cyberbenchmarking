import pytest
from pydantic import ValidationError

from gpt_trace_storage.schemas import CompleteRunRequest, StartRunRequest


def provenance(app_id="browser"):
    import hashlib
    import json
    manifest = {"app_id": app_id, "version": "1.0.0", "tools": []}
    digest = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "app_id": app_id,
        "ui_name": "Browser",
        "kind": "local_mcp",
        "version": "1.0.0",
        "tool_manifest_sha256": digest,
        "tool_manifest": manifest,
    }


def start_request(**overrides):
    values = {
        "task_id": "cyber_1",
        "runner_id": "r",
        "expected_attempt": 1,
        "task_fingerprint": "a" * 64,
        "app_provenance": [],
    }
    values.update(overrides)
    return StartRunRequest(**values)


def test_start_request_requires_attempt_identity_and_provenance() -> None:
    request = start_request()
    assert request.expected_attempt == 1
    assert request.app_provenance == []
    with pytest.raises(ValidationError):
        StartRunRequest(task_id="x", runner_id="r", expected_attempt=1, task_fingerprint="a" * 64)


def test_start_request_validates_manifest_hash_and_unique_apps() -> None:
    item = provenance()
    request = start_request(app_provenance=[item])
    assert request.app_provenance[0].app_id == "browser"
    changed = {**item, "tool_manifest_sha256": "f" * 64}
    with pytest.raises(ValidationError, match="SHA-256"):
        start_request(app_provenance=[changed])
    with pytest.raises(ValidationError, match="duplicate"):
        start_request(app_provenance=[item, item])


def test_start_attempt_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        start_request(expected_attempt=0)


def test_complete_requires_message_list_and_identity() -> None:
    with pytest.raises(ValidationError):
        CompleteRunRequest(conversation_id="abc", messages="wrong", attempt=1, runner_id="r")


def test_complete_runtime_metadata_defaults_empty() -> None:
    request = CompleteRunRequest(conversation_id="abc", messages=[{"id": "u"}, {"id": "a"}], attempt=1, runner_id="r")
    assert request.runtime_metadata == {}


def test_complete_rejects_empty_dataset_messages() -> None:
    with pytest.raises(ValidationError):
        CompleteRunRequest(conversation_id="abc", messages=[], attempt=1, runner_id="r")


def test_reserved_dot_task_id_is_rejected() -> None:
    with pytest.raises(ValidationError):
        start_request(task_id="..")
