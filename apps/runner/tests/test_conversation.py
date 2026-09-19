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
        return_value={
            "sessionStatus": 200,
            "tokenPresent": True,
            "status": 401,
            "ok": False,
            "statusText": "Unauthorized",
            "text": "",
        }
    )
    client = ConversationClient(page)

    with pytest.raises(AuthenticationRequired, match="HTTP 401"):
        await client.fetch("conv")


@pytest.mark.asyncio
async def test_conversation_fetch_uses_in_page_bearer_without_returning_token() -> None:
    page = type("PageDouble", (), {})()
    page.evaluate = AsyncMock(
        return_value={
            "sessionStatus": 200,
            "tokenPresent": True,
            "status": 200,
            "ok": True,
            "statusText": "OK",
            "text": '{"messages":[]}',
        }
    )
    client = ConversationClient(page)

    payload = await client.fetch("conv")
    assert payload == {"messages": []}

    javascript, endpoint = page.evaluate.await_args.args
    assert endpoint.startswith("/backend-api/conversations/conv?")
    assert "/api/auth/session" in javascript
    assert "payload.accessToken" in javascript
    assert "authorization: `Bearer ${accessToken}`" in javascript
    assert "accessToken:" not in javascript
    assert "tokenPresent: true" in javascript


@pytest.mark.asyncio
async def test_conversation_fetch_requires_session_access_token() -> None:
    page = type("PageDouble", (), {})()
    page.evaluate = AsyncMock(
        return_value={
            "sessionStatus": 200,
            "tokenPresent": False,
            "status": 0,
            "ok": False,
            "statusText": "",
            "text": "",
        }
    )
    client = ConversationClient(page)

    with pytest.raises(AuthenticationRequired, match="did not yield a backend access token"):
        await client.fetch("conv")


@pytest.mark.asyncio
async def test_conversation_fetch_classifies_404_as_missing_conversation() -> None:
    page = type("PageDouble", (), {})()
    page.evaluate = AsyncMock(
        return_value={
            "sessionStatus": 200,
            "tokenPresent": True,
            "status": 404,
            "ok": False,
            "statusText": "Not Found",
            "text": "",
        }
    )
    client = ConversationClient(page)

    with pytest.raises(ConversationNotFound, match="HTTP 404"):
        await client.fetch("deleted-conv")

