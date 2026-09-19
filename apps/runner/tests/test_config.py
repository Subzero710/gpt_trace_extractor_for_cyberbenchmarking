from pathlib import Path

import pytest

from gpt_trace_runner.config import Settings
from gpt_trace_runner.exceptions import BrowserIdentityError


def marker(tmp_path: Path, *, seed: int = 123456, timezone: str = "", locale: str = "", geoip: bool = False) -> Path:
    path = tmp_path / ".gpt-trace-identity"
    path.write_text(
        f"fingerprint={seed}\n"
        f"timezone={timezone}\n"
        f"locale={locale}\n"
        f"geoip={'true' if geoip else 'false'}\n",
        encoding="utf-8",
    )
    return path


def test_effective_browser_url_uses_persistent_profile_identity(tmp_path: Path) -> None:
    identity = marker(tmp_path)
    settings = Settings(
        browser_cdp_url="",
        browser_cdp_base_url="http://browser:9222",
        browser_profile_identity_path=identity,
    )
    assert settings.effective_browser_cdp_url() == "http://browser:9222?fingerprint=123456"
    assert settings.browser_version_url() == "http://browser:9222/json/version?fingerprint=123456"


def test_explicit_cdp_url_requires_same_identity(tmp_path: Path) -> None:
    identity = marker(tmp_path)
    settings = Settings(
        browser_cdp_url="http://custom:9333?fingerprint=123456",
        browser_profile_identity_path=identity,
    )
    assert settings.effective_browser_cdp_url() == "http://custom:9333?fingerprint=123456"


def test_explicit_cdp_url_rejects_seed_mismatch(tmp_path: Path) -> None:
    identity = marker(tmp_path)
    settings = Settings(
        browser_cdp_url="http://custom:9333?fingerprint=42",
        browser_profile_identity_path=identity,
    )
    with pytest.raises(BrowserIdentityError):
        settings.effective_browser_cdp_url()


def test_optional_native_identity_params_are_read_from_profile(tmp_path: Path) -> None:
    identity = marker(
        tmp_path,
        seed=7,
        timezone="Europe/Zurich",
        locale="fr-CH",
        geoip=True,
    )
    settings = Settings(browser_profile_identity_path=identity)
    url = settings.effective_browser_cdp_url()
    assert "fingerprint=7" in url
    assert "timezone=Europe%2FZurich" in url
    assert "locale=fr-CH" in url
    assert "geoip=true" in url


def test_missing_profile_identity_is_rejected(tmp_path: Path) -> None:
    settings = Settings(browser_profile_identity_path=tmp_path / "missing")
    with pytest.raises(BrowserIdentityError):
        settings.effective_browser_cdp_url()


def test_external_clipboard_host_is_rejected() -> None:
    settings = Settings(browser_clipboard_url="https://example.com/clipboard")
    with pytest.raises(BrowserIdentityError):
        settings.validate_clipboard_url()


def test_runner_id_is_unique_even_with_fixed_label() -> None:
    settings = Settings(runner_id="worker")
    first = settings.effective_runner_id()
    second = settings.effective_runner_id()
    assert first.startswith("worker-")
    assert second.startswith("worker-")
    assert first != second


def test_dynamic_browser_environment_has_no_global_seed() -> None:
    settings = Settings()
    env = settings.dynamic_browser_environment()
    assert "APP_BROWSER_FINGERPRINT_SEED" not in env


def test_invalid_app_browser_timezone_and_empty_model_are_rejected() -> None:
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        Settings(app_browser_timezone="Europe/Zurich\nInjected")
    with pytest.raises(ValidationError):
        Settings(chatgpt_expected_model_slug="   ")
