from __future__ import annotations

import socket
import uuid
from pathlib import Path
from urllib.parse import urlencode

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    storage_base_url: str = "http://storage:8080"

    # BROWSER_CDP_URL remains an escape hatch for custom deployments. Normal
    # installs use base_url + one installation-specific, persistent seed.
    browser_cdp_url: str = ""
    browser_cdp_base_url: str = "http://browser:9222"
    browser_fingerprint_seed: int | None = None
    browser_novnc_url: str = (
        "http://localhost:7900/vnc.html?autoconnect=1&resize=scale"
    )

    tasks_root: Path = Path("/data/tasks")

    chatgpt_base_url: str = "https://chatgpt.com"
    chatgpt_conversation_turns: int = Field(default=100, ge=1, le=1000)
    chatgpt_turn_timeout_seconds: float = Field(default=1800.0, gt=0)
    chatgpt_stream_start_timeout_seconds: float = Field(default=180.0, gt=0)
    chatgpt_tool_select_timeout_seconds: float = Field(default=20.0, gt=0)
    chatgpt_upload_timeout_seconds: float = Field(default=60.0, gt=0)
    chatgpt_site_ready_timeout_seconds: float = Field(default=15.0, gt=0)
    chatgpt_challenge_timeout_seconds: float = Field(default=180.0, gt=0)
    chatgpt_natural_snapshot_wait_seconds: float = Field(default=2.0, ge=0)

    runner_id: str = ""
    runner_recover_existing: bool = True

    def _seed(self) -> int:
        if self.browser_fingerprint_seed is None:
            raise ValueError(
                "BROWSER_FINGERPRINT_SEED is required. Generate it once per "
                "installation and keep it stable in .env."
            )
        if self.browser_fingerprint_seed <= 0:
            raise ValueError("BROWSER_FINGERPRINT_SEED must be a positive integer")
        return self.browser_fingerprint_seed

    def effective_browser_cdp_url(self) -> str:
        explicit = self.browser_cdp_url.strip()
        if explicit:
            return explicit
        base = self.browser_cdp_base_url.rstrip("/")
        return f"{base}?{urlencode({'fingerprint': self._seed()})}"

    def browser_version_url(self) -> str:
        base = self.browser_cdp_base_url.rstrip("/")
        return f"{base}/json/version?{urlencode({'fingerprint': self._seed()})}"

    def effective_runner_id(self) -> str:
        return self.runner_id.strip() or (
            f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}"
        )
