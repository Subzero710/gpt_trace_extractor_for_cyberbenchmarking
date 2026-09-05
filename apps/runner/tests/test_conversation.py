from gpt_trace_runner.conversation import conversation_id_from_url, extract_dataset_messages, is_complete

def test_conversation_id() -> None:
    assert conversation_id_from_url("https://chatgpt.com/c/abc-123") == "abc-123"

def test_visible_trace_filter() -> None:
    hidden = {"id":"h","author":{"role":"assistant"},"metadata":{"summary_type":"raw_cot"}}
    visible = {"id":"v","author":{"role":"assistant"},"metadata":{},"end_turn":True,"content":{"content_type":"text","parts":["ok"]}}
    messages = extract_dataset_messages({"messages":[hidden, visible]})
    assert messages == [visible]
    assert is_complete(messages)
