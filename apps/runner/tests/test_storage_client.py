import httpx
import pytest

from gpt_trace_runner.exceptions import StorageConflict, StorageError
from gpt_trace_runner.storage_client import StorageClient


@pytest.mark.asyncio
async def test_storage_conflict_is_batch_error() -> None:
    async def handler(request):
        return httpx.Response(409, text="stale", request=request)
    client = StorageClient("http://storage")
    await client._client.aclose()
    client._client = httpx.AsyncClient(base_url="http://storage", transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(StorageConflict):
            await client.start("t", "r", 1, "a" * 64)
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_safe_mutation_retries_one_lost_transport_response() -> None:
    calls = 0
    async def handler(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx.ReadTimeout("lost", request=request)
        return httpx.Response(
            200,
            json={"task_id": "t", "status": "running", "attempt": 1, "runner_id": "r"},
            request=request,
        )
    client = StorageClient("http://storage")
    await client._client.aclose()
    client._client = httpx.AsyncClient(base_url="http://storage", transport=httpx.MockTransport(handler))
    try:
        result = await client.start("t", "r", 1, "a" * 64)
        assert result.attempt == 1
        assert calls == 2
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_get_transport_failure_is_storage_error() -> None:
    async def handler(request):
        raise httpx.ConnectError("down", request=request)
    client = StorageClient("http://storage")
    await client._client.aclose()
    client._client = httpx.AsyncClient(base_url="http://storage", transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(StorageError):
            await client.get("t")
    finally:
        await client.close()
