import base64
import os
from pathlib import Path

import pytest

from browser_mcp.interaction import InteractionService


class FakeDownload:
    def __init__(self, path: Path, name: str = "download.bin"):
        self._path = path
        self.suggested_filename = name

    async def path(self):
        return str(self._path)


class DownloadEvent:
    def __init__(self, item):
        self.item = item

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    @property
    def value(self):
        async def done():
            return self.item
        return done()


class FakeLocator:
    def __init__(self, page):
        self.page = page
        self.first = self

    async def click(self):
        return None

    async def set_input_files(self, value):
        self.page.input_value = value


class FakePage:
    def __init__(self, item):
        self.item = item
        self.input_value = None

    def expect_download(self):
        return DownloadEvent(self.item)

    def locator(self, _selector):
        return FakeLocator(self)


class FakeRuntime:
    def __init__(self, page):
        self.page = page

    def error(self, message):
        return RuntimeError(message)

    async def info(self):
        return {"page_id":"p","context_id":"c","url":"https://example.test","title":"t"}


class FakeRelay:
    enabled = True

    def __init__(self):
        self.acked = []

    async def publish_fd(self, fd, *, size, sha256, name, media_type, target):
        os.lseek(fd, 0, os.SEEK_SET)
        assert len(os.read(fd, size + 1)) == size
        assert target == "code-workspace"
        return {"file_id":"f_"+"a"*64,"name":name,"size":size,"sha256":sha256,"media_type":media_type}

    async def fetch_to_fd(self, file_id, fd):
        data = b"relay-upload"
        os.write(fd, data)
        return {"file_id":file_id,"name":"upload.bin","size":len(data),"sha256":"x"*64,"media_type":"application/octet-stream"}

    async def ack(self, file_id):
        self.acked.append(file_id)


def _service(tmp_path, monkeypatch, data=b"download-bytes"):
    for name in ("FILE_RELAY_URL","FILE_RELAY_TOKEN","FILE_RELAY_APP_ID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("APP_BROWSER_STATE_ROOT", str(tmp_path / "state"))
    path = tmp_path / "download.bin"
    path.write_bytes(data)
    page = FakePage(FakeDownload(path))
    return InteractionService(FakeRuntime(page)), page, data


@pytest.mark.asyncio
async def test_download_is_direct_without_relay(tmp_path, monkeypatch):
    service, _page, data = _service(tmp_path, monkeypatch)
    out = await service.download({"selector":"#download","max_bytes":1024,"media_type":"application/octet-stream"})
    assert base64.b64decode(out["content_base64"]) == data
    assert "file_id" not in out


@pytest.mark.asyncio
async def test_download_uses_relay_when_available(tmp_path, monkeypatch):
    service, _page, _data = _service(tmp_path, monkeypatch)
    service.relay = FakeRelay()
    out = await service.download({"selector":"#download","max_bytes":1024,"media_type":"application/octet-stream"})
    assert out["file_id"] == "f_" + "a" * 64
    assert "content_base64" not in out


@pytest.mark.asyncio
async def test_direct_upload_without_relay(tmp_path, monkeypatch):
    service, page, _data = _service(tmp_path, monkeypatch)
    out = await service.upload({"selector":"#file","filename":"x.bin","content_base64":base64.b64encode(b"x").decode(),"mime_type":None})
    assert page.input_value["name"] == "x.bin"
    assert page.input_value["buffer"] == b"x"
    assert out["filename"] == "x.bin"


@pytest.mark.asyncio
async def test_direct_upload_is_rejected_when_relay_is_available(tmp_path, monkeypatch):
    service, page, _data = _service(tmp_path, monkeypatch)
    service.relay = FakeRelay()
    with pytest.raises(RuntimeError, match="direct upload is unavailable when file relay is configured"):
        await service.upload({
            "selector":"#file",
            "filename":"x.bin",
            "content_base64":base64.b64encode(b"x").decode(),
            "mime_type":None,
        })
    assert page.input_value is None


@pytest.mark.asyncio
async def test_relay_upload_by_file_id(tmp_path, monkeypatch):
    service, page, _data = _service(tmp_path, monkeypatch)
    relay = FakeRelay()
    service.relay = relay
    file_id = "f_" + "b" * 64
    out = await service.upload({"selector":"#file","file_id":file_id,"filename":None,"content_base64":None,"mime_type":None})
    assert Path(page.input_value).read_bytes() == b"relay-upload"
    assert relay.acked == [file_id]
    assert out["filename"] == "upload.bin"
