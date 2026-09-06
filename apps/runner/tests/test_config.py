import pytest

from gpt_trace_runner.config import Settings
from gpt_trace_runner.exceptions import BrowserIdentityError


def test_effective_browser_url_uses_persistent_seed() -> None:
    settings = Settings(browser_cdp_url="", browser_cdp_base_url="http://browser:9222", browser_fingerprint_seed=123456)
    assert settings.effective_browser_cdp_url() == "http://browser:9222?fingerprint=123456"
    assert settings.browser_version_url() == "http://browser:9222/json/version?fingerprint=123456"


def test_explicit_cdp_url_requires_same_identity() -> None:
    settings = Settings(browser_cdp_url="http://custom:9333?fingerprint=123456", browser_fingerprint_seed=123456)
    assert settings.effective_browser_cdp_url() == "http://custom:9333?fingerprint=123456"


def test_explicit_cdp_url_rejects_seed_mismatch() -> None:
    settings = Settings(browser_cdp_url="http://custom:9333?fingerprint=42", browser_fingerprint_seed=123456)
    with pytest.raises(BrowserIdentityError):
        settings.effective_browser_cdp_url()


def test_explicit_cdp_url_rejects_duplicate_identity_param() -> None:
    settings = Settings(browser_cdp_url="http://custom:9333?fingerprint=123456&fingerprint=123456", browser_fingerprint_seed=123456)
    with pytest.raises(BrowserIdentityError):
        settings.effective_browser_cdp_url()


def test_optional_native_identity_params_are_consistent() -> None:
    settings = Settings(
        browser_fingerprint_seed=7,
        browser_timezone="Europe/Zurich",
        browser_locale="fr-CH",
        browser_geoip=True,
    )
    url = settings.effective_browser_cdp_url()
    assert "fingerprint=7" in url
    assert "timezone=Europe%2FZurich" in url
    assert "locale=fr-CH" in url
    assert "geoip=true" in url


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


def test_clipboard_path_must_be_exact_internal_helper() -> None:
    with pytest.raises(BrowserIdentityError):
        Settings(browser_clipboard_url="http://browser:8765/other").validate_clipboard_url()


def test_invalid_timezone_and_empty_model_are_rejected() -> None:
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        Settings(browser_timezone="Europe/Zurich\nInjected")
    with pytest.raises(ValidationError):
        Settings(chatgpt_expected_model_slug="   ")
