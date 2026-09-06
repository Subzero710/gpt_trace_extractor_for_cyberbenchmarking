import pytest
from pydantic import ValidationError

from gpt_trace_storage.schemas import CompleteRunRequest, StartRunRequest


def test_start_request_requires_attempt_identity() -> None:
    request = StartRunRequest(task_id="cyber_1", runner_id="r", expected_attempt=1, task_fingerprint="a" * 64)
    assert request.expected_attempt == 1


def test_start_attempt_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        StartRunRequest(task_id="cyber_1", runner_id="r", expected_attempt=0, task_fingerprint="a" * 64)


def test_complete_requires_message_list_and_identity() -> None:
    with pytest.raises(ValidationError):
        CompleteRunRequest(conversation_id="abc", messages="wrong", attempt=1, runner_id="r")


def test_complete_runtime_metadata_defaults_empty() -> None:
    request = CompleteRunRequest(conversation_id="abc", messages=[{"id":"u"},{"id":"a"}], attempt=1, runner_id="r")
    assert request.runtime_metadata == {}


def test_complete_rejects_empty_dataset_messages() -> None:
    with pytest.raises(ValidationError):
        CompleteRunRequest(conversation_id="abc", messages=[], attempt=1, runner_id="r")


def test_reserved_dot_task_id_is_rejected() -> None:
    with pytest.raises(ValidationError):
        StartRunRequest(task_id="..", runner_id="r", expected_attempt=1, task_fingerprint="a" * 64)
