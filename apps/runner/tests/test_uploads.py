from pathlib import Path

import pytest

from gpt_trace_runner.uploads import build_file_payloads


def test_build_file_payloads_reads_bytes_and_detects_mime(tmp_path: Path) -> None:
    artifact = tmp_path / "sample.json"
    artifact.write_bytes(b'{"ok":true}')

    payloads = build_file_payloads((artifact,))

    assert payloads == [
        {
            "name": "sample.json",
            "mimeType": "application/json",
            "buffer": b'{"ok":true}',
        }
    ]


def test_build_file_payloads_uses_binary_fallback(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.unknown_extension_for_test"
    artifact.write_bytes(b"payload")

    payload = build_file_payloads((artifact,))[0]

    assert payload["name"] == artifact.name
    assert payload["mimeType"] == "application/octet-stream"
    assert payload["buffer"] == b"payload"


def test_build_file_payloads_rejects_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "missing.zip"

    with pytest.raises(FileNotFoundError):
        build_file_payloads((missing,))
