from gpt_trace_runner.config import Settings


def test_effective_browser_url_uses_persistent_seed() -> None:
    settings = Settings(
        browser_cdp_url="",
        browser_cdp_base_url="http://browser:9222",
        browser_fingerprint_seed=123456,
    )
    assert settings.effective_browser_cdp_url() == (
        "http://browser:9222?fingerprint=123456"
    )
    assert settings.browser_version_url() == (
        "http://browser:9222/json/version?fingerprint=123456"
    )


def test_explicit_cdp_url_remains_supported() -> None:
    settings = Settings(
        browser_cdp_url="http://custom:9333?fingerprint=42",
        browser_fingerprint_seed=123456,
    )
    assert settings.effective_browser_cdp_url() == (
        "http://custom:9333?fingerprint=42"
    )
