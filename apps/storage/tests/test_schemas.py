import pytest
from pydantic import ValidationError
from gpt_trace_storage.schemas import CompleteRunRequest, StartRunRequest

def test_start_request() -> None:
    assert StartRunRequest(task_id="cyber_1", runner_id="r").task_id == "cyber_1"

def test_complete_requires_message_list() -> None:
    with pytest.raises(ValidationError):
        CompleteRunRequest(conversation_id="abc", messages="wrong")
