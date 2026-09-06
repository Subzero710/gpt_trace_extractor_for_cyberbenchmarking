from __future__ import annotations

from gpt_trace_runner.conversation import (
    extract_dataset_messages,
    invoked_app_names,
    is_complete,
)


def test_extract_filters_explicit_raw_cot() -> None:
    visible = {
        "id": "visible",
        "author": {"role": "assistant"},
        "end_turn": True,
        "metadata": {},
    }
    hidden = {
        "id": "hidden",
        "author": {"role": "assistant"},
        "metadata": {"summary_type": "raw_cot"},
    }

    messages = extract_dataset_messages(
        {"messages": [hidden, visible]}
    )
    assert messages == [visible]
    assert is_complete(messages)


def test_invoked_app_names_reads_tool_metadata() -> None:
    messages = [
        {
            "author": {"role": "tool"},
            "metadata": {
                "invoked_resource": {
                    "app_name": "Github (mosaic)",
                }
            },
        },
        {
            "author": {"role": "tool"},
            "metadata": {
                "invoked_resource": {
                    "app_name": "Zotero",
                }
            },
        },
    ]

    assert invoked_app_names(messages) == {
        "Github (mosaic)",
        "Zotero",
    }
