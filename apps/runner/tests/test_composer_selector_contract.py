from pathlib import Path


def _source(name: str) -> str:
    return (
        Path(__file__).parents[1]
        / "src"
        / "gpt_trace_runner"
        / name
    ).read_text(encoding="utf-8")


def test_current_role_textbox_composer_shape_is_supported_everywhere() -> None:
    fallback = '[contenteditable="true"][role="textbox"]'
    site_guard = _source("site_guard.py")
    tools = _source("tools.py")

    assert fallback in site_guard
    assert tools.count(fallback) >= 3
