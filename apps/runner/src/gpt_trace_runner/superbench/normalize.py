from __future__ import annotations
import json
from typing import Any

# Only operator/infrastructure credentials are redacted. Benchmark-owned passwords,
# JWTs, CSRF tokens, API keys and flags are training data and must survive.
INFRA_SECRET_KEYS = {
    "authorization", "cookie", "set-cookie", "app_control_token",
    "cloakbrowser_license_key", "openai_session_token", "chatgpt_session_token",
    "operator_token", "operator_password",
}

def sanitize(value: Any):
    count = 0
    def walk(v: Any, key: str = ""):
        nonlocal count
        if key.lower() in INFRA_SECRET_KEYS and v not in (None, ""):
            count += 1; return "[REDACTED]"
        if isinstance(v, dict): return {str(k): walk(x, str(k)) for k, x in v.items()}
        if isinstance(v, list): return [walk(x) for x in v]
        return v
    return walk(value), count

def _role(raw: dict) -> str:
    author = raw.get("author")
    role = author.get("role") if isinstance(author, dict) else raw.get("role")
    role = str(role or "assistant")
    return role if role in {"user", "assistant", "tool", "system"} else "assistant"

def _text(value: Any) -> str:
    if value is None: return ""
    if isinstance(value, str): return value
    if isinstance(value, list):
        chunks = [_text(x) for x in value]
        return "\n".join(x for x in chunks if x)
    if isinstance(value, dict):
        if isinstance(value.get("text"), str): return value["text"]
        if "parts" in value: return _text(value.get("parts"))
        if isinstance(value.get("content"), str): return value["content"]
        return ""
    return str(value)

def normalize_messages(messages: list[dict]):
    out = []
    for raw in messages:
        author = raw.get("author") if isinstance(raw.get("author"), dict) else {}
        content = raw.get("content")
        text = _text(content)
        calls = []
        raw_calls = raw.get("tool_calls") or (raw.get("metadata") or {}).get("tool_calls") or []
        for call in raw_calls:
            if not isinstance(call, dict): continue
            fn = call.get("function") if isinstance(call.get("function"), dict) else {}
            args = call.get("arguments", fn.get("arguments"))
            if not isinstance(args, str): args = json.dumps(args, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            calls.append({"id": str(call.get("id", "")), "name": str(call.get("name") or fn.get("name", "")), "arguments": args})
        metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
        out.append({
            "role": _role(raw), "content": text,
            "name": str(author.get("name") or raw.get("name") or "") or None,
            "tool_call_id": raw.get("tool_call_id") or metadata.get("tool_call_id"),
            "tool_calls": calls,
            "content_type": str(content.get("content_type", "")) if isinstance(content, dict) else None,
            "metadata_json": json.dumps(metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        })
    return out

def tools_from_provenance(apps: list[dict]):
    out = []
    for app in apps or []:
        for tool in (app.get("tool_manifest") or {}).get("tools", []):
            out.append({
                "app_id": str(app.get("app_id", "")), "name": str(tool.get("name", "")),
                "description": str(tool.get("description", "")),
                "input_schema": json.dumps(tool.get("inputSchema") or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                "output_schema": json.dumps(tool.get("outputSchema") or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            })
    return out
