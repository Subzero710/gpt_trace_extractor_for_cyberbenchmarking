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
        "app", "browser", "Configured Browser", True, "local_mcp", "1.0.0",
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
        "app_id": "browser",
        "canonical_tool_name": "navigate",
        "ui_app_name": "Configured Browser",
        "runtime_tool_name": "navigate",
        "recipient": None,
    }]
    assert result.runtime_metadata["app_environments"] == {"browser": "env"}
