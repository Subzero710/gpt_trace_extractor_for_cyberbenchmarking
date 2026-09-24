from gpt_trace_runner.tool_identity import flatten_app_provenance, stable_tool_name


def app(app_id: str, *names: str):
    return {
        "app_id": app_id,
        "tool_manifest_sha256": "a" * 64,
        "tool_manifest": {
            "tools": [
                {
                    "name": name,
                    "description": f"{name} description",
                    "inputSchema": {"type": "object", "properties": {}},
                }
                for name in names
            ]
        },
    }


def test_global_tool_names_are_always_app_namespaced() -> None:
    result = flatten_app_provenance([app("browser", "navigate")])
    assert result["tools"][0]["function"]["name"] == "browser__navigate"
    assert result["tool_identity"][0]["function_name"] == "browser__navigate"


def test_same_tool_name_in_multiple_apps_is_unambiguous() -> None:
    result = flatten_app_provenance([
        app("browser", "read"),
        app("code-workspace", "read"),
    ])
    names = [row["function"]["name"] for row in result["tools"]]
    assert names == ["browser__read", "code_workspace__read"]
    assert len(names) == len(set(names))


def test_long_names_are_bounded_and_deterministic() -> None:
    name = "x" * 127
    first = stable_tool_name("code-workspace", name)
    second = stable_tool_name("code-workspace", name)
    assert first == second
    assert len(first) <= 128
