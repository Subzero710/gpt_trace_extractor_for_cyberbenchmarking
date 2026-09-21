from gpt_trace_runner.superbench.normalize import normalize_messages,sanitize,tools_from_provenance

def test_chatgpt_raw_message_normalization():
    raw={"author":{"role":"user","name":"human"},"content":{"content_type":"text","parts":["hello",{"text":"world"}]},"metadata":{"x":1}}
    m=normalize_messages([raw])[0]; assert m["role"]=="user"; assert m["content"]=="hello\nworld"; assert m["name"]=="human"
def test_benchmark_secrets_survive_but_infra_secrets_do_not():
    clean,n=sanitize({"password":"challenge-password","token":"challenge-jwt","app_control_token":"operator-secret"}); assert clean["password"]=="challenge-password"; assert clean["token"]=="challenge-jwt"; assert clean["app_control_token"]=="[REDACTED]"; assert n==1
def test_tool_schemas_are_arrow_strings():
    tools=tools_from_provenance([{"app_id":"a","tool_manifest":{"tools":[{"name":"x","inputSchema":{"type":"object"},"outputSchema":{"type":"string"}}]}}]); assert isinstance(tools[0]["input_schema"],str); assert isinstance(tools[0]["output_schema"],str)


def test_captured_tool_messages_pair_result_to_call():
    raw=[
      {"id":"tool-call-1","author":{"role":"assistant"},"content":{"content_type":"code","text":"{\"path\":\"README.md\"}"},"recipient":"code_workspace.read_file"},
      {"id":"tool-result-1","author":{"role":"tool","name":"code_workspace.read_file"},"content":{"content_type":"code","text":"{\"content\":\"hello\"}"}},
    ]
    m=normalize_messages(raw)
    assert m[0]["tool_calls"]==[{"id":"tool-call-1","name":"code_workspace.read_file","arguments":"{\"path\":\"README.md\"}"}]
    assert m[1]["tool_call_id"]=="tool-call-1"

def test_parent_id_wins_for_tool_result_pairing():
    raw=[
      {"id":"call-a","author":{"role":"assistant"},"content":{"content_type":"code","text":"{}"},"recipient":"x.tool"},
      {"id":"call-b","author":{"role":"assistant"},"content":{"content_type":"code","text":"{}"},"recipient":"x.tool"},
      {"id":"result-a","author":{"role":"tool","name":"x.tool"},"metadata":{"parent_id":"call-a"},"content":{"content_type":"text","parts":["ok"]}},
    ]
    assert normalize_messages(raw)[2]["tool_call_id"]=="call-a"

def test_sanitize_preserves_benchmark_http_auth_and_redacts_infra_context():
    value={"authorization":"Bearer benchmark-token","cookie":"challenge=abc","chatgpt_session":{"authorization":"Bearer operator-secret","cookie":"session=secret"},"app_control_token":"control-secret"}
    cleaned,count=sanitize(value)
    assert cleaned["authorization"]=="Bearer benchmark-token"
    assert cleaned["cookie"]=="challenge=abc"
    assert cleaned["chatgpt_session"]["authorization"]=="[REDACTED]"
    assert cleaned["chatgpt_session"]["cookie"]=="[REDACTED]"
    assert cleaned["app_control_token"]=="[REDACTED]"
    assert count==3


def test_v32_global_tool_identity_and_multi_call_pairing():
 apps=[{"app_id":"code-workspace","tool_manifest":{"tools":[{"name":"read_file"}]}}]; used=[{"app_id":"code-workspace","canonical_tool_name":"read_file","runtime_tool_name":"read_file","recipient":"code_workspace.read_file"}]; raw=[{"id":"m","author":{"role":"assistant"},"tool_calls":[{"id":"a","name":"code_workspace.read_file","arguments":{}},{"id":"b","name":"code_workspace.read_file","arguments":{}}],"content":{"content_type":"text","parts":[]}},{"author":{"role":"tool","name":"code_workspace.read_file"},"tool_call_id":"a","content":{"content_type":"text","parts":["A"]}},{"author":{"role":"tool","name":"code_workspace.read_file"},"metadata":{"parent_id":"m"},"content":{"content_type":"text","parts":["B"]}}]; m=normalize_messages(raw,used_tool_calls=used,app_provenance=apps); assert [c["name"] for c in m[0]["tool_calls"]]==["code_workspace__read_file","code_workspace__read_file"]; assert m[1]["tool_call_id"]=="a"; assert m[2]["tool_call_id"]=="b"; assert m[1]["name"]=="code_workspace__read_file"
