from pathlib import Path


def _source(name: str) -> str:
    return (
        Path(__file__).parents[1]
        / "src"
        / "gpt_trace_runner"
        / name
    ).read_text(encoding="utf-8")


def test_app_selection_uses_keyboard_enter_not_popup_dom() -> None:
    source = _source("tools.py")
    assert 'await page.keyboard.type("@")' in source
    assert "await page.keyboard.type(tool.name)" in source
    assert 'await page.keyboard.press("Enter")' in source
    assert "_find_mention_result" not in source
    assert "_POPUP_ROOTS" not in source
    assert "_MENTION_ITEMS" not in source
    assert "delay=20" not in source


def test_app_selection_requires_raw_to_structured_mention_transition() -> None:
    source = _source("tools.py")
    assert 'raw_mention = f"@{tool.name}"' in source
    assert "typed_rendered.rstrip().endswith(raw_mention)" in source
    assert "rendered != typed_rendered" in source
    assert "tail.endswith(tool.name)" in source
    assert "not tail.endswith(raw_mention)" in source


def test_chatgpt_compose_types_prompt_before_app_mentions() -> None:
    source = _source("chatgpt.py")
    compose = source.split("async def _compose", 1)[1].split(
        "async def prepare_task", 1
    )[0]
    assert "self._interaction.type_text(editor, task.prompt)" in compose
    assert "await select_apps(" in compose
    assert compose.index("type_text") < compose.index("select_apps")
    assert "paste_text(editor, task.prompt)" not in compose
