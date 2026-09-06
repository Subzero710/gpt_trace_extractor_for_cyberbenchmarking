import pytest

from gpt_trace_runner.conversation import (
    assistant_model_slugs,
    conversation_matches_task,
    message_plain_text,
    validate_task_conversation,
)
from gpt_trace_runner.exceptions import ConversationError


def user_message(parts):
    return {"author": {"role": "user"}, "content": {"parts": parts}}


def assistant(model="gpt-5-6-thinking", end=True):
    return {"author": {"role": "assistant"}, "content": {"parts": ["ok"]}, "metadata": {"model_slug": model}, "end_turn": end}


def test_ecosystem_mention_is_ignored_when_matching_prompt() -> None:
    msg = user_message([{"type": "ecosystemMention", "name": "Github"}, "inspect this"])
    assert message_plain_text(msg) == "inspect this"
    assert conversation_matches_task([msg], "inspect this")


def test_prompt_match_is_exact_including_spaces() -> None:
    messages = [user_message([" x "]), assistant()]
    validate_task_conversation(messages, " x ")
    with pytest.raises(ConversationError):
        validate_task_conversation(messages, "x")


def test_conversation_requires_final_assistant() -> None:
    with pytest.raises(ConversationError):
        validate_task_conversation([user_message(["x"])], "x")


def test_assistant_model_slugs_collect_all_observed() -> None:
    assert assistant_model_slugs([assistant("a"), assistant("b")]) == {"a", "b"}


def test_ecosystem_mention_from_real_har_is_removed_only_by_declared_span():
    from gpt_trace_runner.conversation import benchmark_text_matches

    message = {
        "author": {"role": "user"},
        "content": {"content_type": "text", "parts": ["@Github (mosaic) tu vois combien de repo?"]},
        "metadata": {
            "serialization_metadata": {
                "custom_symbol_offsets": [
                    {
                        "id": "plugin:test",
                        "symbol": "ecosystemMention",
                        "startIndex": 0,
                        "endIndex": 16,
                    }
                ]
            }
        },
    }
    assert benchmark_text_matches(message, "tu vois combien de repo?") is True
    assert benchmark_text_matches(message, " tu vois combien de repo?") is True
    assert benchmark_text_matches(message, "tu vois  combien de repo?") is False


def test_ecosystem_mention_does_not_hide_unrelated_prompt_whitespace_change():
    from gpt_trace_runner.conversation import benchmark_text_matches

    message = {
        "author": {"role": "user"},
        "content": {"parts": ["hello  world @App"]},
        "metadata": {
            "serialization_metadata": {
                "custom_symbol_offsets": [
                    {"symbol": "ecosystemMention", "startIndex": 13, "endIndex": 17}
                ]
            }
        },
    }
    assert benchmark_text_matches(message, "hello world") is False
