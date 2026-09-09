from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any

APP_ID = "browser"
VERSION = "1.0.0"

TOOLS: tuple[dict[str, Any], ...] = (
    {
        "name": "search",
        "description": "Search the public web through the isolated task browser and return ordered result links.",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "query": {"type": "string", "minLength": 1},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 20, "default": 10},
            },
            "required": ["query"],
        },
    },
    {
        "name": "navigate",
        "description": "Navigate the active browser tab to an HTTP or HTTPS URL allowed by the network policy.",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "url": {"type": "string", "minLength": 1},
                "wait_until": {"type": "string", "enum": ["domcontentloaded", "load"], "default": "domcontentloaded"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "read_page",
        "description": "Read visible text and interactive element references from the active browser tab.",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "max_chars": {"type": "integer", "minimum": 1, "maximum": 200000, "default": 50000},
                "include_elements": {"type": "boolean", "default": True},
                "max_elements": {"type": "integer", "minimum": 1, "maximum": 500, "default": 200},
            },
        },
    },
    {
        "name": "click",
        "description": "Click an element reference returned by read_page in the active tab.",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "properties": {"ref": {"type": "string", "pattern": "^e[1-9][0-9]*$"}},
            "required": ["ref"],
        },
    },
    {
        "name": "type",
        "description": "Enter text into an editable element reference and optionally submit with Enter.",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "ref": {"type": "string", "pattern": "^e[1-9][0-9]*$"},
                "text": {"type": "string"},
                "clear": {"type": "boolean", "default": True},
                "submit": {"type": "boolean", "default": False},
            },
            "required": ["ref", "text"],
        },
    },
    {
        "name": "press",
        "description": "Press one allowed navigation or editing key in the active tab or on a referenced element.",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "key": {"type": "string", "enum": ["Enter", "Escape", "Tab", "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "PageUp", "PageDown", "Home", "End", "Backspace", "Delete"]},
                "ref": {"type": ["string", "null"], "pattern": "^e[1-9][0-9]*$", "default": None},
            },
            "required": ["key"],
        },
    },
    {
        "name": "wait",
        "description": "Wait for a bounded duration or until exact visible text appears in the active tab.",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "seconds": {"type": "number", "minimum": 0, "maximum": 30, "default": 1},
                "text": {"type": ["string", "null"], "default": None},
            },
        },
    },
    {
        "name": "screenshot",
        "description": "Capture a PNG screenshot of the active tab and return bounded base64 content.",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "properties": {"full_page": {"type": "boolean", "default": False}},
        },
    },
    {
        "name": "download",
        "description": "Click a referenced download control and return a bounded downloaded file as base64 with integrity metadata.",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "ref": {"type": "string", "pattern": "^e[1-9][0-9]*$"},
                "max_bytes": {"type": "integer", "minimum": 1, "maximum": 10485760, "default": 5242880},
            },
            "required": ["ref"],
        },
    },
    {
        "name": "tabs",
        "description": "List, create, select, or close tabs in the isolated task browser.",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "action": {"type": "string", "enum": ["list", "new", "select", "close"], "default": "list"},
                "index": {"type": ["integer", "null"], "minimum": 0, "default": None},
                "url": {"type": ["string", "null"], "default": None},
            },
        },
    },
)


def manifest() -> dict[str, Any]:
    return {"app_id": APP_ID, "version": VERSION, "tools": deepcopy(list(TOOLS))}


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def manifest_sha256() -> str:
    return hashlib.sha256(canonical_bytes(manifest())).hexdigest()
