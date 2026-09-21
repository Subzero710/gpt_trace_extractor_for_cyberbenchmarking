from gpt_trace_runner.superbench.normalize import normalize_messages,sanitize,tools_from_provenance

def test_chatgpt_raw_message_normalization():
    raw={"author":{"role":"user","name":"human"},"content":{"content_type":"text","parts":["hello",{"text":"world"}]},"metadata":{"x":1}}
    m=normalize_messages([raw])[0]; assert m["role"]=="user"; assert m["content"]=="hello\nworld"; assert m["name"]=="human"
def test_benchmark_secrets_survive_but_infra_secrets_do_not():
    clean,n=sanitize({"password":"challenge-password","token":"challenge-jwt","app_control_token":"operator-secret"}); assert clean["password"]=="challenge-password"; assert clean["token"]=="challenge-jwt"; assert clean["app_control_token"]=="[REDACTED]"; assert n==1
def test_tool_schemas_are_arrow_strings():
    tools=tools_from_provenance([{"app_id":"a","tool_manifest":{"tools":[{"name":"x","inputSchema":{"type":"object"},"outputSchema":{"type":"string"}}]}}]); assert isinstance(tools[0]["input_schema"],str); assert isinstance(tools[0]["output_schema"],str)
