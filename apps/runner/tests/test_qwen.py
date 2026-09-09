from gpt_trace_runner.qwen import flatten_app_provenance


def app(app_id, tool_name):
    return {
        "app_id": app_id,
        "ui_name": app_id,
        "kind": "local_mcp",
        "version": "1.0.0",
        "tool_manifest_sha256": ("a" if app_id == "browser" else "b") * 64,
        "tool_manifest": {
            "app_id": app_id,
            "version": "1.0.0",
            "tools": [{
                "name": tool_name,
                "description": "Read a value.",
                "inputSchema": {"type": "object", "properties": {}},
            }],
        },
    }


def test_unique_tools_flatten_to_qwen_function_format() -> None:
    result = flatten_app_provenance([app("browser", "navigate")])
    assert result["tools"] == [{
        "type": "function",
        "function": {
            "name": "navigate",
            "description": "Read a value.",
            "parameters": {"type": "object", "properties": {}},
        },
    }]
    assert result["tool_identity"][0]["app_id"] == "browser"


def test_collisions_use_documented_canonical_app_namespace() -> None:
    result = flatten_app_provenance([
        app("browser", "read_item"),
        app("code-workspace", "read_item"),
    ])
    assert [item["function"]["name"] for item in result["tools"]] == [
        "browser__read_item",
        "code_workspace__read_item",
    ]
    assert {(item["app_id"], item["tool_name"]) for item in result["tool_identity"]} == {
        ("browser", "read_item"),
        ("code-workspace", "read_item"),
    }


def test_natural_name_cannot_collide_with_generated_namespace() -> None:
    result = flatten_app_provenance([
        app("browser", "read_item"),
        app("code-workspace", "read_item"),
        app("audit", "browser__read_item"),
    ])
    assert [item["function"]["name"] for item in result["tools"]] == [
        "browser__read_item",
        "code_workspace__read_item",
        "audit__browser__read_item",
    ]


def test_long_collision_namespace_is_bounded_and_deterministic() -> None:
    long_name = "x" * 120
    first = flatten_app_provenance([app("code-workspace", long_name), app("browser", long_name)])
    second = flatten_app_provenance([app("code-workspace", long_name), app("browser", long_name)])
    names = [item["function"]["name"] for item in first["tools"]]
    assert first == second
    assert len(names) == len(set(names)) == 2
    assert all(len(name) <= 128 for name in names)
