from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class AppProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    app_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    ui_name: str = Field(min_length=1, max_length=255)
    kind: Literal["local_mcp", "external_connector"]
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
    tool_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool_manifest: dict[str, Any]

    @model_validator(mode="after")
    def _manifest_identity_and_hash(self) -> "AppProvenance":
        if set(self.tool_manifest) != {"app_id", "version", "tools"}:
            raise ValueError("tool_manifest must contain exactly app_id, version, and tools")
        if self.tool_manifest.get("app_id") != self.app_id or self.tool_manifest.get("version") != self.version:
            raise ValueError("tool_manifest identity differs from App provenance")
        tools = self.tool_manifest.get("tools")
        if not isinstance(tools, list):
            raise ValueError("tool_manifest.tools must be a list")
        names: set[str] = set()
        for tool in tools:
            if not isinstance(tool, dict) or set(tool) != {"name", "description", "inputSchema"}:
                raise ValueError("canonical tools require name, description, and inputSchema")
            name = tool.get("name")
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name):
                raise ValueError("canonical tool name is invalid")
            if name in names:
                raise ValueError("tool_manifest contains a duplicate canonical tool")
            names.add(name)
            if not isinstance(tool.get("description"), str) or not tool["description"].strip():
                raise ValueError("canonical tool description is missing")
            schema = tool.get("inputSchema")
            if not isinstance(schema, dict) or schema.get("type") != "object":
                raise ValueError("canonical tool inputSchema must be an object schema")
        encoded = json.dumps(
            self.tool_manifest,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if hashlib.sha256(encoded).hexdigest() != self.tool_manifest_sha256:
            raise ValueError("tool_manifest SHA-256 differs from App provenance")
        return self


class StartRunRequest(BaseModel):
    task_id: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._:-]+$")
    runner_id: str = Field(min_length=1, max_length=255)
    expected_attempt: int = Field(ge=1)
    task_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    app_provenance: list[AppProvenance]

    @field_validator("task_id")
    @classmethod
    def _not_reserved_path_segment(cls, value: str) -> str:
        if value in {".", ".."}:
            raise ValueError("reserved task_id")
        return value

    @model_validator(mode="after")
    def _unique_apps(self) -> "StartRunRequest":
        identifiers = [item.app_id for item in self.app_provenance]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("app_provenance contains duplicate logical App IDs")
        return self


class MutationBase(BaseModel):
    attempt: int = Field(ge=1)
    runner_id: str = Field(min_length=1, max_length=255)


class ConversationRequest(MutationBase):
    conversation_id: str = Field(min_length=1, max_length=255)


class CompleteRunRequest(MutationBase):
    conversation_id: str = Field(min_length=1, max_length=255)
    messages: list[dict[str, Any]] = Field(min_length=2)
    runtime_metadata: dict[str, Any] = Field(default_factory=dict)


class FailRunRequest(MutationBase):
    error_type: str = Field(min_length=1, max_length=255)
    error_message: str = Field(max_length=8000)


class RunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    task_id: str
    status: str
    runner_id: str | None = None
    attempt: int
    task_fingerprint: str | None = None
    conversation_id: str | None = None
    runtime_metadata: dict[str, Any] | None = None
    app_provenance: list[dict[str, Any]] | None = None
    error_type: str | None = None
    error_message: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class StatsResponse(BaseModel):
    pending: int = 0
    running: int = 0
    completed: int = 0
    failed: int = 0
    total: int = 0
