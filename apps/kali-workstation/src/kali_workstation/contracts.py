from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

APP_ID = "kali-workstation"
VERSION = "3.0.0"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Empty(Strict): pass
class Command(Strict):
    command: str = Field(min_length=1, max_length=131072)
    cwd: str = Field(default="/home/kali/workspace", max_length=4096)
    timeout_seconds: int = Field(default=120, ge=1, le=1800)
    stdin: str = Field(default="", max_length=4194304)
    environment: dict[str, str] = Field(default_factory=dict, max_length=128)


class NewTerminal(Strict):
    cwd: str = "/home/kali/workspace"
    environment: dict[str, str] = Field(default_factory=dict)
    rows: int = Field(default=24, ge=10, le=200)
    cols: int = Field(default=80, ge=20, le=400)


class TerminalId(Strict): terminal_id: str = Field(pattern=r"^[0-9a-f]{32}$")
class TerminalSend(TerminalId): input: str = Field(max_length=65536)
class TerminalRead(TerminalId):
    max_bytes: int = Field(default=65536, ge=1, le=1048576)
    wait_seconds: float = Field(default=0, ge=0, le=30)
class TerminalResize(TerminalId):
    rows: int = Field(ge=10, le=200)
    cols: int = Field(ge=20, le=400)


class Event(Strict):
    type: Literal["mouse_move", "mouse_down", "mouse_up", "click", "scroll", "text", "key", "key_down", "key_up"]
    x: int | None = Field(default=None, ge=0, le=3840)
    y: int | None = Field(default=None, ge=0, le=2160)
    button: Literal["left", "middle", "right"] | None = None
    steps: int | None = Field(default=None, ge=-20, le=20)
    text: str | None = Field(default=None, max_length=8192)
    key: str | None = Field(default=None, max_length=64)
class Input(Strict): events: list[Event] = Field(min_length=1, max_length=100)


class Import(Strict):
    path: str = Field(min_length=1, max_length=4096)
    artifact_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    overwrite: bool = False
class Export(Strict): path: str = Field(min_length=1, max_length=4096)


class Page(Strict): page_id: str | None = None
class SwitchPage(Strict): page_id: str = Field(pattern=r"^page-[0-9a-f]{16}$")
class URL(Page): url: str = Field(min_length=1, max_length=8192)
class NewPage(Strict): url: str | None = None
class Selector(Page): selector: str = Field(min_length=1, max_length=4096)
class Fill(Selector): text: str = Field(max_length=262144)
class Press(Selector): key: str = Field(min_length=1, max_length=128)
class Drag(Page): source_selector: str; target_selector: str
class Select(Selector): values: list[str] = Field(min_length=1, max_length=100)
class Attr(Selector): name: str
class Inspect(Page): selector: str = "html"
class Html(Page): selector: str | None = None
class Eval(Page): expression: str = Field(min_length=1, max_length=262144); argument: Any = None
class Cookies(Page): urls: list[str] = Field(default_factory=list, max_length=100)
class Cookie(Page): cookie: dict[str, Any]
class Logs(Page): limit: int = Field(default=200, ge=1, le=500)
class Request(Strict): request_id: str = Field(pattern=r"^req-[0-9a-f]{16}$")
class Response(Request): max_bytes: int = Field(default=8388608, ge=1, le=8388608)
class Upload(Selector): path: str = Field(min_length=1, max_length=4096)


class Result(Strict):
    # Every implementation result is validated against the specialized model below.
    pass
class OK(Result): ok: bool
class Closed(Result): closed: bool; active_page_id: str | None
class PageOut(Result): page_id: str; url: str; title: str
class PagesOut(Result): pages: list[PageOut]; active_page_id: str | None
class CommandOut(Result):
    exit_code: int; timed_out: bool; stdout: str; stderr: str
    stdout_truncated: bool; stderr_truncated: bool
class Created(Result): terminal_id: str; pid: int
class Sent(Result): accepted_bytes: int
class Read(Result): output: str; output_base64: str; dropped_bytes: int; exit_code: int | None; running: bool
class Resized(Result): ok: bool
class ClosedTerminal(Result): closed: bool
class Image(Result): width: int; height: int; mime_type: Literal["image/png"]; content_base64: str; sha256: str
class InputOut(Result): ok: bool; events_processed: int
class FileOut(Result): path: str; size: int; sha256: str
class ExportOut(FileOut): artifact_id: str
class QueryOut(Result): count: int; matches: list[dict[str, Any]]
class InspectOut(Result): nodes: list[dict[str, Any]]
class HtmlOut(Result): html: str; truncated: bool
class AttrOut(Result): value: str | None
class EvalOut(Result): result: Any
class CookiesOut(Result): cookies: list[dict[str, Any]]
class LogsOut(Result): entries: list[dict[str, Any]]
class RequestOut(Result): request: dict[str, Any]
class BodyOut(Result): size: int; sha256: str; truncated: bool; content_base64: str


# Tool name -> category, argument contract, result contract, precise description.
SPECS = {
    "exec_command": ("shell", Command, CommandOut, "Execute a Bash command in the Kali guest with optional stdin, cwd, environment and bounded output."),
    "create_terminal": ("shell", NewTerminal, Created, "Create an interactive Bash session attached to a Unix PTY in the Kali guest."),
    "send_terminal_input": ("shell", TerminalSend, Sent, "Write text or control characters to a persistent PTY."),
    "read_terminal_output": ("shell", TerminalRead, Read, "Read bounded output from a persistent PTY."),
    "close_terminal": ("shell", TerminalId, ClosedTerminal, "Terminate and reap a persistent PTY session."),
    "resize_terminal": ("shell", TerminalResize, Resized, "Set PTY rows and columns and signal the foreground terminal process."),
    "observe_screen": ("computer", Empty, Image, "Capture the Kali desktop PNG, resolution and SHA-256."),
    "computer_input": ("computer", Input, InputOut, "Apply bounded generic mouse and keyboard events to the Kali desktop."),
    "import_file": ("transfer", Import, FileOut, "Import an artifact from the attempt's controller-side store into a guest path."),
    "export_file": ("transfer", Export, ExportOut, "Export a bounded guest file to the controller-side store and return its artifact ID."),
    "navigate": ("browser", URL, PageOut, "Navigate a browser page to an HTTP(S) URL."),
    "new_page": ("browser", NewPage, PageOut, "Open a new browser tab, optionally at a URL."),
    "list_pages": ("browser", Empty, PagesOut, "List browser tabs and the active tab."),
    "close_page": ("browser", Page, Closed, "Close the selected browser tab."),
    "switch_page": ("browser", SwitchPage, PageOut, "Activate a browser tab."),
    "go_back": ("browser", Page, PageOut, "Navigate backward in a browser tab."),
    "go_forward": ("browser", Page, PageOut, "Navigate forward in a browser tab."),
    "reload": ("browser", Page, PageOut, "Reload a browser tab."),
    "click": ("browser", Selector, PageOut, "Click a DOM element selected by CSS."),
    "type_text": ("browser", Fill, PageOut, "Fill a DOM form element with text."),
    "press": ("browser", Press, PageOut, "Press a key on a DOM element."),
    "hover": ("browser", Selector, PageOut, "Hover over a DOM element."),
    "drag": ("browser", Drag, PageOut, "Drag one DOM element onto another."),
    "select_option": ("browser", Select, PageOut, "Select option values in a DOM select element."),
    "query_selector": ("browser", Selector, QueryOut, "Query matching DOM elements and bounded text."),
    "inspect_dom": ("browser", Inspect, InspectOut, "Inspect bounded DOM nodes for a CSS selector."),
    "get_html": ("browser", Html, HtmlOut, "Return bounded page or element HTML."),
    "get_attribute": ("browser", Attr, AttrOut, "Read an attribute of a DOM element."),
    "evaluate_javascript": ("browser", Eval, EvalOut, "Evaluate JavaScript in the selected browser page."),
    "get_cookies": ("browser", Cookies, CookiesOut, "Read browser cookies."),
    "set_cookie": ("browser", Cookie, CookiesOut, "Set a browser cookie."),
    "clear_cookies": ("browser", Empty, CookiesOut, "Clear browser cookies."),
    "get_console_logs": ("browser", Logs, LogsOut, "Read bounded browser console events."),
    "get_network_logs": ("browser", Logs, LogsOut, "Read bounded browser request and response events."),
    "get_request_details": ("browser", Request, RequestOut, "Read headers and method for a captured browser request."),
    "get_response_body": ("browser", Response, BodyOut, "Read a bounded captured browser response body."),
    "upload_file": ("browser", Upload, PageOut, "Select an existing Kali file for a browser file input."),
    "download_file": ("browser", Selector, FileOut, "Download a clicked browser link into the Kali Downloads directory."),
}


def manifest() -> dict:
    return {"schema_version": 2, "app_id": APP_ID, "version": VERSION,
            "tools": [{"name": name, "category": category, "description": description,
                       "inputSchema": input_model.model_json_schema(),
                       "outputSchema": output_model.model_json_schema()}
                      for name, (category, input_model, output_model, description) in SPECS.items()]}


def canonical_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
