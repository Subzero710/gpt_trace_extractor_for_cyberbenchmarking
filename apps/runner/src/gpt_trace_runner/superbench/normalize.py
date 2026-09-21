from __future__ import annotations
import json
from typing import Any

# Only explicit operator/infrastructure credentials are redacted. Generic HTTP
# fields are benchmark data unless provenance explicitly marks infrastructure.
INFRA_SECRET_KEYS={"app_control_token","cloakbrowser_license_key","openai_session_token","chatgpt_session_token","operator_token","operator_password"}
INFRA_CONTEXT_KEYS={"chatgpt_session","operator_credentials","runner_credentials","control_credentials","infrastructure_credentials"}
GENERIC_HTTP_SECRET_KEYS={"authorization","cookie","set-cookie"}
def sanitize(value: Any):
    count=0
    def walk(v: Any,key: str="",infra_context: bool=False):
        nonlocal count
        lowered=key.lower(); here=infra_context or lowered in INFRA_CONTEXT_KEYS
        if (lowered in INFRA_SECRET_KEYS or (here and lowered in GENERIC_HTTP_SECRET_KEYS)) and v not in (None,""):
            count+=1; return "[REDACTED]"
        if isinstance(v,dict): return {str(k):walk(x,str(k),here) for k,x in v.items()}
        if isinstance(v,list): return [walk(x,"",here) for x in v]
        return v
    return walk(value),count

def _role(raw: dict)->str:
    author=raw.get("author"); role=author.get("role") if isinstance(author,dict) else raw.get("role"); role=str(role or "assistant")
    return role if role in {"user","assistant","tool","system"} else "assistant"
def _text(value: Any)->str:
    if value is None:return ""
    if isinstance(value,str):return value
    if isinstance(value,list):return "\n".join(x for x in (_text(v) for v in value) if x)
    if isinstance(value,dict):
        if isinstance(value.get("text"),str):return value["text"]
        if "parts" in value:return _text(value.get("parts"))
        if isinstance(value.get("content"),str):return value["content"]
        return ""
    return str(value)
def _stable_tool_name(app_id: str,canonical_name: str)->str:
    clean=lambda v:"".join(ch if ch.isalnum() else "_" for ch in str(v)).strip("_")
    app,tool=clean(app_id),clean(canonical_name); return f"{app}__{tool}" if app and tool else tool or app
def _tool_aliases(used_tool_calls,app_provenance):
    aliases={}
    for app in app_provenance or []:
        if not isinstance(app,dict):continue
        app_id=str(app.get("app_id") or "")
        for tool in (app.get("tool_manifest") or {}).get("tools",[]):
            if isinstance(tool,dict) and tool.get("name"):
                canonical=str(tool["name"]); aliases.setdefault(canonical,_stable_tool_name(app_id,canonical))
    for call in used_tool_calls or []:
        if not isinstance(call,dict):continue
        app_id=str(call.get("app_id") or ""); canonical=str(call.get("canonical_tool_name") or "")
        if not app_id or not canonical:continue
        stable=_stable_tool_name(app_id,canonical)
        for key in (canonical,call.get("runtime_tool_name"),call.get("recipient")):
            if isinstance(key,str) and key:aliases[key]=stable
    return aliases

def normalize_messages(messages:list[dict],*,used_tool_calls=None,app_provenance=None):
    aliases=_tool_aliases(used_tool_calls,app_provenance); canonical=lambda n:aliases.get(str(n or ""),str(n or ""))
    by_message:dict[str,list[dict[str,str]]]={}; by_index={}
    for index,raw in enumerate(messages):
        if not isinstance(raw,dict):continue
        metadata=raw.get("metadata") if isinstance(raw.get("metadata"),dict) else {}; content=raw.get("content"); calls=[]
        for offset,call in enumerate(raw.get("tool_calls") or metadata.get("tool_calls") or []):
            if not isinstance(call,dict):continue
            fn=call.get("function") if isinstance(call.get("function"),dict) else {}; args=call.get("arguments",fn.get("arguments"))
            if not isinstance(args,str):args=json.dumps(args,ensure_ascii=False,sort_keys=True,separators=(",",":"))
            calls.append({"id":str(call.get("id") or f'{raw.get("id") or index}:{offset}'),"name":canonical(call.get("name") or fn.get("name")),"arguments":args})
        recipient=raw.get("recipient"); ctype=content.get("content_type") if isinstance(content,dict) else None
        if not calls and _role(raw)=="assistant" and ctype=="code" and isinstance(recipient,str) and recipient and recipient!="all":
            calls=[{"id":str(raw.get("id") or f"message:{index}"),"name":canonical(recipient),"arguments":_text(content)}]
        if calls:
            by_index[index]=calls; mid=str(raw.get("id") or "")
            if mid:by_message[mid]=list(calls)
    out=[]; unmatched=[]; consumed=set()
    def consume(cid):
        cid=str(cid or "")
        for pos in range(len(unmatched)-1,-1,-1):
            if unmatched[pos]["id"]==cid:consumed.add(cid);unmatched.pop(pos);return cid
        return cid or None
    for index,raw in enumerate(messages):
        if not isinstance(raw,dict):continue
        author=raw.get("author") if isinstance(raw.get("author"),dict) else {}; metadata=raw.get("metadata") if isinstance(raw.get("metadata"),dict) else {}; content=raw.get("content"); role=_role(raw); calls=by_index.get(index,[])
        unmatched.extend({"id":c["id"],"name":c["name"],"index":index} for c in calls)
        name=canonical(author.get("name") or raw.get("name")); cid=raw.get("tool_call_id") or metadata.get("tool_call_id")
        if role=="tool":
            if cid:cid=consume(cid)
            else:
                parent=metadata.get("parent_id")
                if parent is not None:
                    candidates=by_message.get(str(parent),[])
                    candidate=next((c for c in candidates if c["id"] not in consumed and (not name or c["name"]==name)),None) or next((c for c in candidates if c["id"] not in consumed),None)
                    if candidate:cid=consume(candidate["id"])
                if not cid:
                    for pos in range(len(unmatched)-1,-1,-1):
                        c=unmatched[pos]
                        if c["index"]<index and (not name or c["name"]==name):cid=c["id"];consumed.add(cid);unmatched.pop(pos);break
        out.append({"role":role,"content":_text(content),"name":name or None,"tool_call_id":str(cid) if cid not in (None,"") else None,"tool_calls":calls,"content_type":str(content.get("content_type","")) if isinstance(content,dict) else None,"metadata_json":json.dumps(metadata,ensure_ascii=False,sort_keys=True,separators=(",",":"))})
    return out

def tools_from_provenance(apps:list[dict]):
    out=[]
    for app in apps or []:
        app_id=str(app.get("app_id",""))
        for tool in (app.get("tool_manifest") or {}).get("tools",[]):
            canonical=str(tool.get("name",""));out.append({"app_id":app_id,"name":_stable_tool_name(app_id,canonical),"description":str(tool.get("description","")),"input_schema":json.dumps(tool.get("inputSchema") or {},ensure_ascii=False,sort_keys=True,separators=(",",":")),"output_schema":json.dumps(tool.get("outputSchema") or {},ensure_ascii=False,sort_keys=True,separators=(",",":"))})
    return out
