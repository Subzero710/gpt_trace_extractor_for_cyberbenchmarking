#!/usr/bin/env python3
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

URL = os.environ.get("GPT_TRACE_EXPORT_URL", "http://127.0.0.1:8080/v1/export.jsonl")
OUTPUT = Path(os.environ.get("GPT_TRACE_EXPORT_OUTPUT", "exports/runs.jsonl"))


def fail(message: str) -> None:
    print(f"export failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    runs = 0
    messages = 0
    try:
        response = urllib.request.urlopen(URL, timeout=30)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        fail(f"storage unavailable at {URL}: {exc}")

    tmp_path = OUTPUT.with_name(OUTPUT.name + ".tmp")
    try:
        with response, tmp_path.open("w", encoding="utf-8") as out:
            for line_no, raw in enumerate(response, 1):
                if not raw.strip():
                    continue
                try:
                    text = raw.decode("utf-8")
                    run = json.loads(text)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    fail(f"invalid storage JSONL at line {line_no}: {exc}")
                if not isinstance(run, dict):
                    fail(f"storage row {line_no} is not an object")
                entries = run.get("messages")
                if not isinstance(entries, list):
                    fail(f"storage row {line_no} has non-list messages")
                out.write(text.rstrip("\r\n"))
                out.write("\n")
                runs += 1
                messages += len(entries)
        tmp_path.replace(OUTPUT)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise

    print(f"exported {runs} run(s) / {messages} message(s) to {OUTPUT}")


if __name__ == "__main__":
    main()
