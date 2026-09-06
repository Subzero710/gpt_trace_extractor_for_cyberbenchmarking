import pytest

from gpt_trace_runner.chatgpt import ChatGPTClient
from gpt_trace_runner.exceptions import ModelMismatch


class FakePage:
    def on(self, name, callback):
        pass


def make_client():
    return ChatGPTClient(
        FakePage(), base_url="https://chatgpt.com", conversation_turns=1000,
        turn_timeout_seconds=1, stream_start_timeout_seconds=1,
        tool_select_timeout_seconds=1, upload_timeout_seconds=1,
        site_ready_timeout_seconds=1, challenge_timeout_seconds=1,
        natural_snapshot_wait_seconds=0,
        clipboard_url="http://browser:8765/clipboard",
        expected_model_slug="gpt-5-6-thinking",
    )


def assistant(slug):
    return {"author": {"role": "assistant"}, "metadata": {"model_slug": slug}}


def test_all_observed_assistant_models_must_match_expected() -> None:
    client = make_client()
    assert client._validate_message_models([assistant("gpt-5-6-thinking")]) == {"gpt-5-6-thinking"}
    with pytest.raises(ModelMismatch):
        client._validate_message_models([
            assistant("gpt-5-6-thinking"), assistant("unexpected-model")
        ])


def test_absent_message_model_slug_does_not_invent_one() -> None:
    client = make_client()
    assert client._validate_message_models([{"author": {"role": "assistant"}, "metadata": {}}]) == set()


class Request:
    url = "https://chatgpt.com/backend-api/f/conversation"
    method = "POST"
    def __init__(self, model, timezone="Europe/Zurich"):
        self.post_data_json = {"model": model, "timezone": timezone}


class EventPage(FakePage):
    def __init__(self):
        self.handlers = {}
    def on(self, name, callback):
        self.handlers[name] = callback


def make_event_client():
    page = EventPage()
    client = ChatGPTClient(
        page, base_url="https://chatgpt.com", conversation_turns=100,
        turn_timeout_seconds=1, stream_start_timeout_seconds=1,
        tool_select_timeout_seconds=1, upload_timeout_seconds=1,
        site_ready_timeout_seconds=1, challenge_timeout_seconds=1,
        natural_snapshot_wait_seconds=0,
        clipboard_url="http://browser:8765/clipboard",
        expected_model_slug="gpt-5-6-thinking",
    )
    client._environment_baseline = {"timezone": "Europe/Zurich"}
    client._traffic.begin_task()
    return page, client


def test_frontend_submitted_model_must_match_expected() -> None:
    page, client = make_event_client()
    page.handlers["request"](Request("unexpected"))
    with pytest.raises(ModelMismatch):
        client._validate_submitted_model()


def test_frontend_timezone_must_match_browser_environment() -> None:
    from gpt_trace_runner.exceptions import EnvironmentDrift
    page, client = make_event_client()
    page.handlers["request"](Request("gpt-5-6-thinking", "UTC"))
    with pytest.raises(EnvironmentDrift):
        client._validate_submitted_model()
