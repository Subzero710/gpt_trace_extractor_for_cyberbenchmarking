from __future__ import annotations

import socket
import uuid
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .exceptions import BrowserIdentityError


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    storage_base_url: str = "http://storage:8080"
    browser_cdp_url: str = ""
    browser_cdp_base_url: str = "http://browser:9222"
    browser_fingerprint_seed: int | None = None
    browser_novnc_url: str = "http://localhost:7900/vnc.html?autoconnect=1&resize=scale"
    browser_humanize: bool = True
    browser_humanize_preset: Literal["default", "careful"] = "default"
    browser_clipboard_url: str = "http://browser:8765/clipboard"
    browser_timezone: str = ""
    browser_locale: str = ""
    browser_geoip: bool = False

    tasks_root: Path = Path("/data/tasks")
    runner_state_root: Path = Path("/data/state")
    app_registry_path: Path = Path("/data/apps/registry/apps.json")
    app_control_token_file: Path = Path("/run/secrets/app_control_token")

    docker_socket_path: Path = Path("/var/run/docker.sock")
    app_code_workspace_image: str = "gpt-trace-code-workspace:latest"
    app_browser_image: str = "gpt-trace-browser:latest"
    workspace_gateway_container: str = "gpt-trace-workspace-gateway"
    browser_gateway_container: str = "gpt-trace-browser-gateway"

    cloakbrowser_license_key: str = ""
    app_browser_fingerprint_seed: int | None = None
    app_browser_search_url_template: str = "https://duckduckgo.com/?q={query}"
    app_browser_allowed_private_hosts: str = ""
    app_browser_humanize: bool = True
    app_browser_humanize_preset: Literal["default", "careful"] = "default"
    app_browser_timezone: str = ""
    app_browser_locale: str = ""
    app_browser_geoip: bool = False

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

    @field_validator("browser_timezone", "app_browser_timezone")
    @classmethod
    def _valid_timezone(cls, value: str) -> str:
        value = value.strip()
        if value and (len(value) > 128 or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+/-" for ch in value)):
            raise ValueError("BROWSER_TIMEZONE contains unsupported characters")
        return value

    @field_validator("browser_locale", "app_browser_locale")
    @classmethod
    def _valid_locale(cls, value: str) -> str:
        value = value.strip()
        if value and (len(value) > 64 or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-" for ch in value)):
            raise ValueError("BROWSER_LOCALE must be a simple BCP-47 locale")
        return value

    @field_validator("chatgpt_expected_model_slug")
    @classmethod
    def _valid_expected_model(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("CHATGPT_EXPECTED_MODEL_SLUG must not be empty")
        return value

    def _seed(self) -> int:
        if self.browser_fingerprint_seed is None:
            raise BrowserIdentityError("BROWSER_FINGERPRINT_SEED is required; run `make init` once")
        if self.browser_fingerprint_seed <= 0:
            raise BrowserIdentityError("BROWSER_FINGERPRINT_SEED must be positive")
        return self.browser_fingerprint_seed

    def _identity_pairs(self) -> list[tuple[str, str]]:
        pairs = [("fingerprint", str(self._seed()))]
        if self.browser_timezone.strip():
            pairs.append(("timezone", self.browser_timezone.strip()))
        if self.browser_locale.strip():
            pairs.append(("locale", self.browser_locale.strip()))
        if self.browser_geoip:
            pairs.append(("geoip", "true"))
        return pairs

    def _validate_explicit_cdp(self, explicit: str) -> str:
        parsed = urlparse(explicit)
        if parsed.path not in {"", "/"}:
            raise BrowserIdentityError("BROWSER_CDP_URL must point to the cloakserve root")
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        keys = [key for key, _ in pairs]
        if len(keys) != len(set(keys)):
            raise BrowserIdentityError("BROWSER_CDP_URL contains duplicate query parameters")
        expected = self._identity_pairs()
        if sorted(pairs) != sorted(expected):
            raise BrowserIdentityError(
                "BROWSER_CDP_URL identity parameters must exactly match "
                f"{dict(expected)!r}; got {dict(pairs)!r}"
            )
        return explicit

    def effective_browser_cdp_url(self) -> str:
        explicit = self.browser_cdp_url.strip()
        if explicit:
            return self._validate_explicit_cdp(explicit)
        base_parsed = urlparse(self.browser_cdp_base_url)
        if base_parsed.query or base_parsed.fragment:
            raise BrowserIdentityError("BROWSER_CDP_BASE_URL must not contain query/fragment")
        return f"{self.browser_cdp_base_url.rstrip('/')}?{urlencode(self._identity_pairs())}"

    def browser_version_url(self) -> str:
        parsed = urlparse(self.effective_browser_cdp_url())
        path = parsed.path.rstrip("/") + "/json/version"
        return urlunparse(parsed._replace(path=path))

    def validate_clipboard_url(self) -> str:
        parsed = urlparse(self.browser_clipboard_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "browser"
            or parsed.path != "/clipboard"
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise BrowserIdentityError("BROWSER_CLIPBOARD_URL must be the internal http://browser:<port>/clipboard helper")
        return self.browser_clipboard_url

    def dynamic_browser_environment(self) -> dict[str, str]:
        seed = self.app_browser_fingerprint_seed
        if seed is None or seed <= 0:
            raise BrowserIdentityError("APP_BROWSER_FINGERPRINT_SEED must be a positive integer; run `make init`")
        if "{query}" not in self.app_browser_search_url_template:
            raise BrowserIdentityError("APP_BROWSER_SEARCH_URL_TEMPLATE must contain {query}")
        return {
            "CLOAKBROWSER_LICENSE_KEY": self.cloakbrowser_license_key,
            "APP_BROWSER_FINGERPRINT_SEED": str(seed),
            "APP_BROWSER_SEARCH_URL_TEMPLATE": self.app_browser_search_url_template,
            "APP_BROWSER_ALLOWED_PRIVATE_HOSTS": self.app_browser_allowed_private_hosts,
            "APP_BROWSER_HUMANIZE": "true" if self.app_browser_humanize else "false",
            "APP_BROWSER_HUMANIZE_PRESET": self.app_browser_humanize_preset,
            "APP_BROWSER_TIMEZONE": self.app_browser_timezone.strip(),
            "APP_BROWSER_LOCALE": self.app_browser_locale.strip(),
            "APP_BROWSER_GEOIP": "true" if self.app_browser_geoip else "false",
        }

    def effective_runner_id(self) -> str:
        label = self.runner_id.strip() or socket.gethostname()
        return f"{label[:230]}-{uuid.uuid4().hex[:16]}"

    @property
    def runner_lock_path(self) -> Path:
        return self.runner_state_root / "runner.lock"

    @property
    def journal_path(self) -> Path:
        return self.runner_state_root / "submission.json"
