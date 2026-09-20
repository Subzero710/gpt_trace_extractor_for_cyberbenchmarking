import pytest

from gpt_trace_runner.conversation import (
    assistant_model_slugs,
    validate_conversation_identity,
)
from gpt_trace_runner.exceptions import ConversationError


def user_message(message_id: str):
    return {
        "id": message_id,
        "author": {"role": "user"},
        "content": {"parts": ["frontend representation is intentionally irrelevant"]},
    }


def assistant(model="gpt-5-6-thinking", end=True):
    return {
        "id": "assistant-1",
        "author": {"role": "assistant"},
        "content": {"parts": ["ok"]},
        "metadata": {"model_slug": model},
        "end_turn": end,
    }


def test_conversation_identity_uses_user_message_id_not_serialized_text() -> None:
    messages = [
        {
            "id": "user-123",
            "author": {"role": "user"},
            "content": {
                "parts": [
                    {"type": "someFutureUiNode", "text": "anything"},
                    " transformed frontend text",
                ]
            },
            "metadata": {
                "serialization_metadata": {
                    "custom_symbol_offsets": [
                        {"symbol": "futureUnknownSymbol", "startIndex": 0, "endIndex": 7}
                    ]
                }
            },
        },
        assistant(),
    ]
    validate_conversation_identity(messages, "user-123")


def test_conversation_identity_rejects_wrong_or_missing_user_message_id() -> None:
    messages = [user_message("user-123"), assistant()]
    with pytest.raises(ConversationError, match="does not match"):
        validate_conversation_identity(messages, "user-456")
    with pytest.raises(ConversationError, match="expected user_message_id is missing"):
        validate_conversation_identity(messages, "")


def test_conversation_identity_requires_exactly_one_user_message() -> None:
    messages = [user_message("u1"), user_message("u2"), assistant()]
    with pytest.raises(ConversationError, match="exactly one user message"):
        validate_conversation_identity(messages, "u1")


def test_conversation_identity_requires_final_assistant() -> None:
    with pytest.raises(ConversationError, match="end_turn=true"):
        validate_conversation_identity([user_message("u1")], "u1")


def test_assistant_model_slugs_collect_all_observed() -> None:
    assert assistant_model_slugs([assistant("a"), assistant("b")]) == {"a", "b"}
