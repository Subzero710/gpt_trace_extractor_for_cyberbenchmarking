from __future__ import annotations

import json

from sqlalchemy.dialects import postgresql

from gpt_trace_storage.db import _json_dumps
from gpt_trace_storage.models import Run


def test_trace_payload_columns_use_json_while_internal_provenance_stays_jsonb() -> None:
    table = Run.__table__.c
    for name in (
        "messages",
        "runtime_metadata",
        "dataset_metadata",
        "evaluation",
    ):
        assert type(table[name].type) is postgresql.JSON
    assert type(table.app_provenance.type) is postgresql.JSONB


def test_production_json_serializer_preserves_nul_as_json_escape() -> None:
    original = {
        "title": "Microsoft Word - coversheet2.docx\x00suffix",
        "nested": {"value": "\x00"},
    }
    encoded = _json_dumps(original)
    assert "\x00" not in encoded
    assert "\\u0000" in encoded
    assert json.loads(encoded) == original


def test_production_json_serializer_does_not_replace_nul() -> None:
    encoded = _json_dumps({"x": "a\x00b"})
    assert "\ufffd" not in encoded
    assert json.loads(encoded)["x"] == "a\x00b"
