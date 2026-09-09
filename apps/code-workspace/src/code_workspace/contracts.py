from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any

APP_ID = "code-workspace"
VERSION = "1.0.0"

TOOLS: tuple[dict[str, Any], ...] = (
    {
        "name": "exec_command",
        "description": "Execute one shell command in the active task workspace and return bounded stdout, stderr, exit status, and timeout state.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "command": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Shell command to execute with /bin/bash.",
                },
                "cwd": {
                    "type": "string",
                    "default": ".",
                    "description": "Working directory relative to the task workspace.",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1800,
                    "default": 120,
                    "description": "Wall-clock timeout in seconds.",
                },
            },
            "required": ["command"],
        },
    },
    {
        "name": "read_file",
        "description": "Read a UTF-8 text file inside the active task workspace without following paths outside it.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "path": {"type": "string", "minLength": 1, "description": "File path relative to the task workspace."},
                "start_line": {"type": "integer", "minimum": 1, "default": 1},
                "end_line": {"type": ["integer", "null"], "minimum": 1, "default": None},
                "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1048576, "default": 262144},
            },
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Create or replace one UTF-8 text file inside the active task workspace.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "path": {"type": "string", "minLength": 1, "description": "File path relative to the task workspace."},
                "content": {"type": "string", "description": "Complete UTF-8 file content."},
                "overwrite": {"type": "boolean", "default": True},
                "create_parents": {"type": "boolean", "default": True},
                "expected_sha256": {
                    "type": ["string", "null"],
                    "pattern": "^[0-9a-f]{64}$",
                    "default": None,
                    "description": "When set, the existing file must have this SHA-256 before replacement.",
                },
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "apply_patch",
        "description": "Apply ordered, exact text replacements to one workspace file after verifying its SHA-256.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "path": {"type": "string", "minLength": 1},
                "expected_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "replacements": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "old": {"type": "string", "minLength": 1},
                            "new": {"type": "string"},
                            "expected_count": {"type": "integer", "minimum": 1, "default": 1},
                        },
                        "required": ["old", "new"],
                    },
                },
            },
            "required": ["path", "expected_sha256", "replacements"],
        },
    },
    {
        "name": "list_directory",
        "description": "List workspace entries in deterministic path order without following symlinks.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "path": {"type": "string", "default": "."},
                "recursive": {"type": "boolean", "default": False},
                "max_entries": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 1000},
            },
        },
    },
    {
        "name": "search_files",
        "description": "Search UTF-8 workspace files for a literal string and return deterministic structured matches.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "query": {"type": "string", "minLength": 1},
                "path": {"type": "string", "default": "."},
                "file_glob": {"type": "string", "default": "**/*"},
                "case_sensitive": {"type": "boolean", "default": False},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
            },
            "required": ["query"],
        },
    },
)


def manifest() -> dict[str, Any]:
    return {"app_id": APP_ID, "version": VERSION, "tools": deepcopy(list(TOOLS))}


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def manifest_sha256() -> str:
    return hashlib.sha256(canonical_bytes(manifest())).hexdigest()
