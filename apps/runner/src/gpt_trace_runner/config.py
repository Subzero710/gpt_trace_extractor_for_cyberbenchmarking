from __future__ import annotations

import socket
import tomllib
import uuid
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .exceptions import BrowserIdentityError


RUNNER_CONFIG_PATH = Path("/data/config/runner.toml")


def _versioned_config() -> dict[str, Any]:
    if not RUNNER_CONFIG_PATH.exists():
        return {}
    try:
        payload = tomllib.loads(RUNNER_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"cannot parse versioned runner config: {RUNNER_CONFIG_PATH}") from exc
    if set(payload) != {"runner", "workstation"} or not isinstance(payload["runner"], dict) or not isinstance(payload["workstation"], dict):
        raise RuntimeError("runner.toml must contain [runner] and [workstation] tables")
    allowed = {"provider", "broker_socket", "gateway_container", "boot_timeout_seconds", "guest_agent_timeout_seconds", "memory_mb", "vcpus", "overlay_quota_gb", "screenshot_max_bytes", "max_terminals", "max_output_bytes", "max_transfer_bytes", "max_seed_bytes", "egress_allow_cidrs"}
    if set(payload["workstation"]) != allowed:
        raise RuntimeError("workstation configuration has missing or unknown fields")
    return {**payload["runner"], **{"workstation_" + k: v for k, v in payload["workstation"].items()}}


class Settings(BaseSettings):
    # Process environment is still available for true secrets. Versioned config
    # is passed as init data and therefore wins over accidental environment
    # overrides for non-secret settings. No dotenv file is read in-container.
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    storage_base_url: str = "http://storage:8080"
    browser_cdp_url: str = ""
    browser_cdp_base_url: str = "http://teacher-browser:9222"
    browser_profile_identity_path: Path = Path("/browser-profile/.gpt-trace-identity")
    browser_novnc_url: str = "http://localhost:7900/vnc.html?autoconnect=1&resize=scale"
    browser_humanize: bool = True
    browser_humanize_preset: Literal["default", "careful"] = "default"
    browser_clipboard_url: str = "http://teacher-browser:8765/clipboard"

    runner_state_root: Path = Path("/data/state")
    app_registry_path: Path = Path("/data/apps/registry/apps.json")
    app_control_token_file: Path = Path("/run/secrets/app_control_token")
    workstation_broker_token_file: Path = Path("/run/secrets/workstation_broker_admin_token")

    workstation_provider: Literal["libvirt"] = "libvirt"
    workstation_broker_socket: Path = Path("/run/workstation-broker/broker.sock")
    workstation_gateway_container: str = "gpt-trace-workstation-gateway"
    workstation_boot_timeout_seconds: int = Field(default=120, ge=30, le=600)
    workstation_guest_agent_timeout_seconds: int = Field(default=60, ge=10, le=300)
    workstation_memory_mb: int = Field(default=8192, ge=1024, le=65536)
    workstation_vcpus: int = Field(default=4, ge=1, le=32)
    workstation_overlay_quota_gb: int = Field(default=16, ge=4, le=128)
    workstation_screenshot_max_bytes: int = Field(default=8388608, ge=1024, le=16777216)
    workstation_max_terminals: int = Field(default=8, ge=1, le=64)
    workstation_max_output_bytes: int = Field(default=1048576, ge=1024, le=8388608)
    workstation_max_transfer_bytes: int = Field(default=67108864, ge=1024, le=268435456)
    workstation_max_seed_bytes: int = Field(default=671088640, ge=1024, le=671088640)
    workstation_egress_allow_cidrs: list[str] = Field(default_factory=list)


    chatgpt_base_url: str = "https://chatgpt.com"
    chatgpt_conversation_turns: int = Field(default=100, ge=1, le=1000)
    chatgpt_turn_timeout_seconds: float = Field(default=1800.0, gt=0)
    chatgpt_stream_start_timeout_seconds: float = Field(default=180.0, gt=0)
    chatgpt_tool_select_timeout_seconds: float = Field(default=20.0, gt=0)
    chatgpt_upload_timeout_seconds: float = Field(default=60.0, gt=0)
    chatgpt_site_ready_timeout_seconds: float = Field(default=15.0, gt=0)
    chatgpt_challenge_timeout_seconds: float = Field(default=180.0, gt=0)
    chatgpt_natural_snapshot_wait_seconds: float = Field(default=0.0, ge=0)
    chatgpt_expected_model_slug: str = "gpt-5-6-thinking"

    runner_id: str = ""
    runner_recover_existing: bool = True

    def __init__(self, **values: Any) -> None:
        merged = _versioned_config()
        merged.update(values)
        super().__init__(**merged)

    @field_validator("chatgpt_expected_model_slug")
    @classmethod
    def _valid_expected_model(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("chatgpt_expected_model_slug must not be empty")
        return value

    def _identity_pairs(self) -> list[tuple[str, str]]:
        path = self.browser_profile_identity_path
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError as exc:
            raise BrowserIdentityError(
                f"teacher browser identity is missing at {path}; run `make up` first"
            ) from exc

        values: dict[str, str] = {}
        for raw in lines:
            if not raw.strip():
                continue
            if "=" not in raw:
                raise BrowserIdentityError("teacher browser identity contains a malformed line")
            key, value = raw.split("=", 1)
            if key in values:
                raise BrowserIdentityError(f"duplicate browser identity key: {key}")
            values[key] = value

        allowed = {"fingerprint", "timezone", "locale", "geoip"}
        unknown = set(values) - allowed
        if unknown:
            raise BrowserIdentityError(
                f"teacher browser identity has unknown keys: {sorted(unknown)}"
            )

        seed = values.get("fingerprint", "")
        if not seed.isdigit() or int(seed) <= 0:
            raise BrowserIdentityError("teacher browser fingerprint must be a positive integer")

        timezone = values.get("timezone", "").strip()
        locale = values.get("locale", "").strip()
        geoip = values.get("geoip", "false").strip().casefold()
        if geoip not in {"true", "false"}:
            raise BrowserIdentityError("teacher browser geoip must be true or false")
        if timezone and (
            len(timezone) > 128
            or any(
                ch not in
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+/-"
                for ch in timezone
            )
        ):
            raise BrowserIdentityError("teacher browser timezone is invalid")
        if locale and (
            len(locale) > 64
            or any(
                ch not in
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-"
                for ch in locale
            )
        ):
            raise BrowserIdentityError("teacher browser locale is invalid")

        pairs = [("fingerprint", seed)]
        if timezone:
            pairs.append(("timezone", timezone))
        if locale:
            pairs.append(("locale", locale))
        if geoip == "true":
            pairs.append(("geoip", "true"))
        return pairs

    def _validate_explicit_cdp(self, explicit: str) -> str:
        parsed = urlparse(explicit)
        if parsed.path not in {"", "/"}:
            raise BrowserIdentityError("browser_cdp_url must point to the cloakserve root")
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        keys = [key for key, _ in pairs]
        if len(keys) != len(set(keys)):
            raise BrowserIdentityError("browser_cdp_url contains duplicate query parameters")
        expected = self._identity_pairs()
        if sorted(pairs) != sorted(expected):
            raise BrowserIdentityError(
                "browser_cdp_url identity parameters must exactly match "
                f"{dict(expected)!r}; got {dict(pairs)!r}"
            )
        return explicit

    def effective_browser_cdp_url(self) -> str:
        explicit = self.browser_cdp_url.strip()
        if explicit:
            return self._validate_explicit_cdp(explicit)
        base_parsed = urlparse(self.browser_cdp_base_url)
        if base_parsed.query or base_parsed.fragment:
            raise BrowserIdentityError("browser_cdp_base_url must not contain query/fragment")
        return f"{self.browser_cdp_base_url.rstrip('/')}?{urlencode(self._identity_pairs())}"

    def browser_version_url(self) -> str:
        parsed = urlparse(self.effective_browser_cdp_url())
        path = parsed.path.rstrip("/") + "/json/version"
        return urlunparse(parsed._replace(path=path))

    def validate_clipboard_url(self) -> str:
        parsed = urlparse(self.browser_clipboard_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "teacher-browser"
            or parsed.path != "/clipboard"
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise BrowserIdentityError(
                "browser_clipboard_url must be the internal http://teacher-browser:<port>/clipboard helper"
            )
        return self.browser_clipboard_url

    def effective_runner_id(self) -> str:
        label = self.runner_id.strip() or socket.gethostname()
        return f"{label[:230]}-{uuid.uuid4().hex[:16]}"

    @property
    def runner_lock_path(self) -> Path:
        return self.runner_state_root / "runner.lock"

    @property
    def journal_path(self) -> Path:
        return self.runner_state_root / "submission.json"

    @property
    def superbench_active_run_path(self) -> Path:
        return self.runner_state_root / "superbench" / "active-run.json"
