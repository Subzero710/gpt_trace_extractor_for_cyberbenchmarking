from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from gpt_trace_runner.conversation import (
    ConversationClient,
    extract_dataset_messages,
    invoked_app_names,
    is_complete,
)
from gpt_trace_runner.exceptions import AuthenticationRequired, ConversationNotFound


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
    messages = extract_dataset_messages({"messages": [hidden, visible]})
    assert messages == [visible]
    assert is_complete(messages)


def test_invoked_app_names_reads_runtime_metadata_without_vendor_assumptions() -> None:
    messages = [
        {
            "author": {"role": "tool"},
            "metadata": {"invoked_resource": {"app_name": "GitHub Connector"}},
        },
        {
            "author": {"role": "tool"},
            "metadata": {"invoked_resource": {"app_name": "Browser"}},
        },
    ]
    assert invoked_app_names(messages) == {"GitHub Connector", "Browser"}

@pytest.mark.asyncio
async def test_conversation_fetch_classifies_401_as_authentication_failure() -> None:
    page = type("PageDouble", (), {})()
    page.evaluate = AsyncMock(
        return_value={"status": 401, "ok": False, "statusText": "Unauthorized", "text": ""}
    )
    client = ConversationClient(page)

    with pytest.raises(AuthenticationRequired, match="HTTP 401"):
        await client.fetch("conv")


@pytest.mark.asyncio
async def test_conversation_fetch_classifies_404_as_missing_conversation() -> None:
    page = type("PageDouble", (), {})()
    page.evaluate = AsyncMock(
        return_value={"status": 404, "ok": False, "statusText": "Not Found", "text": ""}
    )
    client = ConversationClient(page)

    with pytest.raises(ConversationNotFound, match="HTTP 404"):
        await client.fetch("deleted-conv")

