from gpt_trace_runner.tools import _composer_text_is_empty


def test_visually_empty_composer_text_is_empty() -> None:
    for value in ("", " ", "\n", "\r\n", "\t", "\u00a0", "\u200b", "\ufeff", "\n\u200b\t"):
        assert _composer_text_is_empty(value)


def test_real_or_structured_content_is_not_empty() -> None:
    assert not _composer_text_is_empty("Kali Workstation")
    assert not _composer_text_is_empty("@Kali Workstation")
    # Do not silently classify an embedded-object marker as empty: it can
    # represent a structured node even when it has no ordinary text.
    assert not _composer_text_is_empty("\ufffc")
