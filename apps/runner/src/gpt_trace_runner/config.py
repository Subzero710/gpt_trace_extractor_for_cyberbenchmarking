from __future__ import annotations

import socket
import uuid
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    storage_base_url: str = "http://storage:8080"
    browser_cdp_url: str = "http://browser:9222?fingerprint=710"
    browser_novnc_url: str = (
        "http://localhost:7900/vnc.html?autoconnect=1&resize=scale"
    )

    tasks_root: Path = Path("/data/tasks")

    chatgpt_base_url: str = "https://chatgpt.com"
    chatgpt_conversation_turns: int = Field(default=100, ge=1, le=1000)
    chatgpt_turn_timeout_seconds: float = Field(default=1800.0, gt=0)
    chatgpt_stream_start_timeout_seconds: float = Field(default=60.0, gt=0)
    chatgpt_tool_select_timeout_seconds: float = Field(default=15.0, gt=0)
    chatgpt_upload_timeout_seconds: float = Field(default=60.0, gt=0)

    runner_id: str = ""
    runner_inter_task_delay_seconds: float = Field(default=3.0, ge=0)
    runner_recover_existing: bool = True

    def effective_runner_id(self) -> str:
        return self.runner_id.strip() or (
            f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}"
        )
