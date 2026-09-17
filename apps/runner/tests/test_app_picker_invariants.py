from pathlib import Path


def _source(name: str) -> str:
    return (
        Path(__file__).parents[1]
        / "src"
        / "gpt_trace_runner"
        / name
    ).read_text(encoding="utf-8")


def test_app_probe_diagnostics_are_popup_scoped() -> None:
    source = _source("tools.py")
    assert "async def _visible_popup_snapshot" in source
    diagnostic = source.split("async def _visible_popup_snapshot", 1)[1].split(
        "async def _find_app_from_open_menu", 1
    )[0]
    assert '_POPUP_ROOTS' in source
    assert 'page.locator(", ".join(_POPUP_ROOTS))' in diagnostic
    assert "_visible_menu_labels" not in source


def test_app_picker_opening_selectors_are_not_rewritten() -> None:
    source = _source("tools.py")
    block = source.split("_TOOL_MENU_BUTTONS =", 1)[1].split(")", 1)[0]
    assert 'composer-tools-menu-button' in block
    assert 'composer-plus-btn' in block
    assert 'aria-label*="Tools"' in block
    assert 'aria-label*="Add"' in block


def test_app_selection_is_confirmed_in_composer() -> None:
    tools = _source("tools.py")
    chatgpt = _source("chatgpt.py")
    assert "editor: Locator" in tools
    assert "tool.name in rendered" in tools
    assert "rendered != before" in tools
    assert "editor=editor" in chatgpt
    assert "confirmation = await _find_menu_item" not in tools
