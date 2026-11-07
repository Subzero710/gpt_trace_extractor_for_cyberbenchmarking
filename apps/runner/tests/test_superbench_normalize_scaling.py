"""Regression coverage for linear tool-call pairing (including duplicates)."""

from gpt_trace_runner.superbench.normalize import normalize_messages


def test_results_after_many_calls_preserve_declared_identity():
    calls = [
        {"id": "assistant-" + str(i), "role": "assistant",
         "tool_calls": [{"id": "call-" + str(i), "name": "tool"}]}
        for i in range(2000)
    ]
    responses = [
        {"id": "response-" + str(i), "role": "tool", "name": "tool",
         "tool_call_id": "call-" + str(i)}
        for i in range(2000)
    ]
    normalized = normalize_messages(calls + responses)
    assert [row["tool_call_id"] for row in normalized[len(calls):]] == [
        "call-" + str(i) for i in range(2000)
    ]


def test_parent_ambiguity_with_duplicate_call_ids_is_retained():
    data = [
        {"id": "assistant", "role": "assistant", "tool_calls": [
            {"id": "duplicate", "name": "same"},
            {"id": "duplicate", "name": "same"},
        ]},
        {"id": "other", "role": "assistant", "tool_calls": [
            {"id": "other-id", "name": "other"},
        ]},
        {"id": "result", "role": "tool", "name": "same",
         "metadata": {"parent_id": "assistant"}},
    ]
    normalized = normalize_messages(data)
    # Two identical parent candidates are still ambiguous. The globally most
    # recent unmatched call of the matching name resolves the response.
    assert normalized[-1]["tool_call_id"] == "duplicate"


def test_anonymous_results_pair_last_unconsumed():
    calls = [
        {"id": "m1", "role": "assistant", "tool_calls": [{"id": "c1", "name": "tool"}]},
        {"id": "m2", "role": "assistant", "tool_calls": [{"id": "c2", "name": "tool"}]},
        {"id": "r1", "role": "tool", "name": "tool"},
        {"id": "r2", "role": "tool", "name": "tool"},
    ]
    normalized = normalize_messages(calls)
    assert [row["tool_call_id"] for row in normalized[2:]] == ["c2", "c1"]
