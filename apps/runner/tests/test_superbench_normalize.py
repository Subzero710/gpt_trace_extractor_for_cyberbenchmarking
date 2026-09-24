from gpt_trace_runner.tool_identity import stable_tool_name
from gpt_trace_runner.superbench.normalize import normalize_messages, tools_from_provenance


def test_chatgpt_raw_message_normalization():
    raw = {
        "author": {"role": "user", "name": "human"},
        "content": {"content_type": "text", "parts": ["hello", {"text": "world"}]},
        "metadata": {"x": 1},
    }
    message = normalize_messages([raw])[0]
    assert message["role"] == "user"
    assert message["content"] == "hello\nworld"
    assert message["name"] == "human"


def test_tool_schemas_are_arrow_strings():
    tools = tools_from_provenance([
        {
            "app_id": "a",
            "tool_manifest": {
                "tools": [{
                    "name": "x",
                    "inputSchema": {"type": "object"},
                    "outputSchema": {"type": "string"},
                }]
            },
        }
    ])
    assert isinstance(tools[0]["input_schema"], str)
    assert isinstance(tools[0]["output_schema"], str)


def test_parent_id_wins_for_tool_result_pairing():
    raw = [
        {"id": "call-a", "author": {"role": "assistant"}, "content": {"content_type": "code", "text": "{}"}, "recipient": "x.tool"},
        {"id": "call-b", "author": {"role": "assistant"}, "content": {"content_type": "code", "text": "{}"}, "recipient": "x.tool"},
        {"id": "result-a", "author": {"role": "tool", "name": "x.tool"}, "metadata": {"parent_id": "call-a"}, "content": {"content_type": "text", "parts": ["ok"]}},
    ]
    assert normalize_messages(raw)[2]["tool_call_id"] == "call-a"


def test_global_tool_identity_and_multi_call_pairing():
    apps = [{"app_id": "code-workspace", "tool_manifest": {"tools": [{"name": "read_file"}]}}]
    used = [{"app_id": "code-workspace", "canonical_tool_name": "read_file", "runtime_tool_name": "read_file", "recipient": "code_workspace.read_file"}]
    raw = [
        {"id": "m", "author": {"role": "assistant"}, "tool_calls": [{"id": "a", "name": "code_workspace.read_file", "arguments": {}}, {"id": "b", "name": "code_workspace.read_file", "arguments": {}}], "content": {"content_type": "text", "parts": []}},
        {"author": {"role": "tool", "name": "code_workspace.read_file"}, "tool_call_id": "a", "content": {"content_type": "text", "parts": ["A"]}},
        {"author": {"role": "tool", "name": "code_workspace.read_file"}, "metadata": {"parent_id": "m"}, "content": {"content_type": "text", "parts": ["B"]}},
    ]
    messages = normalize_messages(raw, used_tool_calls=used, app_provenance=apps)
    assert [call["name"] for call in messages[0]["tool_calls"]] == ["code_workspace__read_file", "code_workspace__read_file"]
    assert messages[1]["tool_call_id"] == "a"
    assert messages[2]["tool_call_id"] == "b"


def test_exported_tool_name_uses_shared_global_identity():
    apps = [{"app_id": "code-workspace", "tool_manifest": {"tools": [{"name": "read_file"}]}}]
    assert tools_from_provenance(apps)[0]["name"] == stable_tool_name("code-workspace", "read_file")
