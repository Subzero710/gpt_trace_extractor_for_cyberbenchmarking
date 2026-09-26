"""Trusted display capture and QMP input, independent of the guest agent/X11."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import tempfile
from pathlib import Path

from PIL import Image

KEYS = {"Enter": "ret", "Escape": "esc", "Tab": "tab", "Backspace": "backspace",
        "Delete": "delete", "ArrowUp": "up", "ArrowDown": "down", "ArrowLeft": "left",
        "ArrowRight": "right", "Home": "home", "End": "end", "PageUp": "pgup",
        "PageDown": "pgdn", "Control": "ctrl", "Alt": "alt", "Shift": "shift",
        "Super": "meta_l", "Space": "spc"}
PUNCT = dict(zip(" -=[]\\;',./`", ["spc", "minus", "equal", "bracket_left",
             "bracket_right", "backslash", "semicolon", "apostrophe", "comma", "dot",
             "slash", "grave_accent"]))
SHIFTED = dict(zip('~!@#$%^&*()_+{}|:"<>?',
                   ['grave_accent', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
                    'minus', 'equal', 'bracket_left', 'bracket_right', 'backslash',
                    'semicolon', 'apostrophe', 'comma', 'dot', 'slash']))


def capture(run, domain: str, directory: Path, max_bytes: int) -> dict:
    with tempfile.NamedTemporaryFile(dir=directory, suffix=".ppm", delete=False) as handle:
        shot = Path(handle.name)
    try:
        run("virsh", "-c", "qemu:///system", "screenshot", domain, "--file", str(shot))
        with Image.open(shot) as source:
            source.load()
            if source.width > 3840 or source.height > 2160:
                raise ValueError("screen exceeds configured dimensions")
            output = io.BytesIO()
            source.convert("RGB").save(output, format="PNG")
            raw = output.getvalue()
            if len(raw) > max_bytes:
                raise ValueError("screenshot exceeds configured bytes")
            return {"width": source.width, "height": source.height, "mime_type": "image/png",
                    "content_base64": base64.b64encode(raw).decode(),
                    "sha256": hashlib.sha256(raw).hexdigest()}
    finally:
        shot.unlink(missing_ok=True)


def qmp(run, domain: str, events: list[dict]) -> None:
    command = json.dumps({"execute": "input-send-event", "arguments": {"events": events}})
    response = json.loads(run("virsh", "-c", "qemu:///system", "qemu-monitor-command", domain, command))
    if "error" in response or "return" not in response:
        raise RuntimeError(f"QMP input failed: {str(response)[:300]}")


def key(code: str, down: bool) -> dict:
    return {"type": "key", "data": {"down": down, "key": {"type": "qcode", "data": code}}}


def character(value: str) -> list[dict]:
    if value.isascii() and value.isalpha():
        code, shifted = value.lower(), value.isupper()
    elif value.isascii() and value.isdigit():
        code, shifted = value, False
    elif value in PUNCT:
        code, shifted = PUNCT[value], False
    elif value in SHIFTED:
        code, shifted = SHIFTED[value], True
    elif value == "\n":
        code, shifted = "ret", False
    elif value == "\t":
        code, shifted = "tab", False
    elif ord(value) >= 128:
        # Standard GTK/X11 Unicode entry through the emulated keyboard.
        # The guest agent and X11 control APIs are not involved.
        sequence = [key("ctrl", True), key("shift", True), key("u", True), key("u", False),
                    key("shift", False), key("ctrl", False)]
        for digit in f"{ord(value):x}":
            sequence.extend(character(digit))
        sequence.extend([key("ret", True), key("ret", False)])
        return sequence
    else:
        raise ValueError("unsupported control character in QMP text")
    return ([key("shift", True)] if shifted else []) + [key(code, True), key(code, False)] + ([key("shift", False)] if shifted else [])


def input_events(run, domain: str, args: dict, width: int, height: int) -> dict:
    events = args.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= 100:
        raise ValueError("input requires 1 to 100 events")
    for item in events:
        if not isinstance(item, dict):
            raise ValueError("invalid input event")
        kind = item.get("type")
        if kind == "mouse_move":
            x, y = item.get("x"), item.get("y")
            if type(x) is not int or type(y) is not int or not 0 <= x < width or not 0 <= y < height:
                raise ValueError("mouse coordinates outside captured screen")
            qmp(run, domain, [{"type": "abs", "data": {"axis": axis, "value": round(pos * 32767 / max(1, size - 1))}}
                              for axis, pos, size in (("x", x, width), ("y", y, height))])
        elif kind in {"mouse_down", "mouse_up", "click"}:
            button = item.get("button") or "left"
            if button not in {"left", "middle", "right"}:
                raise ValueError("invalid mouse button")
            states = [True, False] if kind == "click" else [kind == "mouse_down"]
            for down in states:
                qmp(run, domain, [{"type": "btn", "data": {"down": down, "button": button}}])
        elif kind == "scroll":
            steps = item.get("steps") if item.get("steps") is not None else 1
            if type(steps) is not int or not -20 <= steps <= 20:
                raise ValueError("invalid scroll")
            button = "wheel-up" if steps < 0 else "wheel-down"
            for _ in range(abs(steps)):
                qmp(run, domain, [{"type": "btn", "data": {"down": state, "button": button}} for state in (True, False)])
        elif kind == "text":
            value = item.get("text")
            if not isinstance(value, str) or len(value.encode()) > 8192:
                raise ValueError("invalid input text")
            for char in value:
                qmp(run, domain, character(char))
        elif kind in {"key", "key_down", "key_up"}:
            value = item.get("key")
            parts = value.split("+") if isinstance(value, str) else []
            aliases = {label.casefold(): code for label, code in KEYS.items()}
            codes = [aliases.get(part.casefold(), part.lower()) for part in parts]
            if not parts or any(not (len(code) == 1 and code.isascii() and code.isalnum())
                                and code not in KEYS.values() for code in codes):
                raise ValueError("unsupported QMP key")
            if kind == "key":
                qmp(run, domain, [key(code, True) for code in codes] + [key(code, False) for code in reversed(codes)])
            else:
                qmp(run, domain, [key(code, kind == "key_down") for code in codes])
        else:
            raise ValueError("unknown input event")
    return {"ok": True, "events_processed": len(events)}
