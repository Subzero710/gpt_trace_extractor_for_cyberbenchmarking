from pathlib import Path


SRC = Path(__file__).parents[1] / "src" / "gpt_trace_runner"


def test_cdp_browser_applies_cloakbrowser_humanize_layer() -> None:
    text = (SRC / "browser.py").read_text()
    assert "patch_browser_async" in text
    assert "resolve_config(self._humanize_preset)" in text
    assert "connect_over_cdp" in text


def test_clipboard_never_uses_chatgpt_javascript_permissions() -> None:
    text = (SRC / "interaction.py").read_text()
    assert "navigator.clipboard" not in text
    assert "grant_permissions" not in text
    assert "Control+V" in text
    assert "_set_system_clipboard" in text
