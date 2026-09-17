import socket

import pytest

from browser_mcp.core import BrowserAppError, BrowserPolicy


@pytest.mark.asyncio
@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "http://127.0.0.1:8000/control/state",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.1/",
])
async def test_internal_and_non_http_targets_are_blocked(url: str) -> None:
    with pytest.raises(BrowserAppError):
        await BrowserPolicy().validate_url(url)


@pytest.mark.asyncio
async def test_dns_answers_are_checked(monkeypatch) -> None:
    def private(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.2", 80))]

    monkeypatch.setattr(socket, "getaddrinfo", private)
    with pytest.raises(BrowserAppError, match="private"):
        await BrowserPolicy().validate_url("https://example.test/")


@pytest.mark.asyncio
async def test_explicit_private_host_allowlist_is_exact() -> None:
    policy = BrowserPolicy({"127.0.0.1"})
    assert await policy.validate_url("http://127.0.0.1:8080/") == "http://127.0.0.1:8080/"
    with pytest.raises(BrowserAppError):
        await policy.validate_url("http://localhost:8080/")
