from gpt_trace_runner.models import BenchmarkTask, BenchmarkTool, CapturedConversation
from gpt_trace_runner.provenance import enrich_capture


def test_capture_maps_observed_runtime_tool_to_canonical_identity() -> None:
    manifest = {
        "app_id": "browser",
        "version": "1.0.0",
        "tools": [{
            "name": "navigate",
            "description": "Navigate.",
            "inputSchema": {"type": "object", "properties": {}},
        }],
    }
    tool = BenchmarkTool(
        "app", "browser", "Configured Browser", "local_mcp", "1.0.0",
        "a" * 64, manifest,
    )
    task = BenchmarkTask("t", "p", (), (tool,))
    captured = CapturedConversation(
        "c",
        [{
            "author": {"role": "tool"},
            "metadata": {
                "invoked_resource": {
                    "app_name": "Configured Browser",
                    "tool_name": "navigate",
                }
            },
        }],
        {},
    )
    result = enrich_capture(captured, task=task, app_environments={"browser": "env"})
    assert result.runtime_metadata["used_tool_calls"] == [{
        "call_id": "observed:0",
        "call_message_id": None,
        "result_message_id": None,
        "app_id": "browser",
        "canonical_tool_name": "navigate",
        "ui_app_name": "Configured Browser",
        "runtime_tool_name": "navigate",
        "recipient": None,
    }]
    assert result.runtime_metadata["app_environments"] == {"browser": "env"}


def _app_task() -> BenchmarkTask:
    manifest = {
        "app_id": "browser",
        "version": "1.0.0",
        "tools": [{
            "name": "navigate",
            "description": "Navigate.",
            "inputSchema": {"type": "object", "properties": {}},
        }],
    }
    tool = BenchmarkTool(
        "app", "browser", "Configured Browser", "local_mcp", "1.0.0",
        "a" * 64, manifest,
    )
    return BenchmarkTask("t", "p", (), (tool,))


def test_capture_does_not_report_incident_when_app_is_not_called() -> None:
    captured = CapturedConversation(
        "c",
        [{
            "id": "final",
            "author": {"role": "assistant"},
            "channel": "final",
            "end_turn": True,
            "content": {"content_type": "text", "parts": ["answer"]},
        }],
        {},
    )

    result = enrich_capture(
        captured,
        task=_app_task(),
        app_environments={"browser": "env"},
    )

    assert result.runtime_metadata["infrastructure_incidents"] == []


def test_api_tool_app_call_with_correlated_result_has_no_incident() -> None:
    captured = CapturedConversation(
        "c",
        [
            {
                "id": "call-1",
                "author": {"role": "assistant"},
                "recipient": "api_tool.call_tool",
                "content": {
                    "content_type": "code",
                    "language": "python3",
                    "text": (
                        '{"path":"/Configured Browser/link_abc/navigate",'
                        '"args":{"url":"https://example.test"}}'
                    ),
                },
            },
            {
                "id": "result-1",
                "author": {"role": "tool", "name": "api_tool.call_tool"},
                "metadata": {
                    "parent_id": "call-1",
                    "invoked_resource": {
                        "resource_uri": "/Configured Browser/link_abc/navigate",
                    },
                },
                "content": {"content_type": "text", "parts": ["ok"]},
            },
        ],
        {},
    )

    result = enrich_capture(
        captured,
        task=_app_task(),
        app_environments={"browser": "env"},
    )

    calls = [
        call
        for call in result.runtime_metadata["used_tool_calls"]
        if call.get("app_id") == "browser"
    ]
    assert len(calls) == 1
    assert calls[0]["canonical_tool_name"] == "navigate"
    assert calls[0]["call_message_id"] == "call-1"
    assert calls[0]["result_message_id"] == "result-1"
    assert result.runtime_metadata["infrastructure_incidents"] == []


def test_api_tool_app_call_without_result_is_infrastructure_incident() -> None:
    captured = CapturedConversation(
        "c",
        [{
            "id": "call-1",
            "author": {"role": "assistant"},
            "recipient": "api_tool.call_tool",
            "content": {
                "content_type": "code",
                "language": "python3",
                "text": (
                    '{"path":"/Configured Browser/link_abc/navigate",'
                    '"args":{"url":"https://example.test"}}'
                ),
            },
        }],
        {},
    )

    result = enrich_capture(
        captured,
        task=_app_task(),
        app_environments={"browser": "env"},
    )

    assert result.runtime_metadata["infrastructure_incidents"] == [{
        "type": "app_call_without_result",
        "app_id": "browser",
        "tool_name": "navigate",
        "call_id": "call-1",
        "call_message_id": "call-1",
    }]

