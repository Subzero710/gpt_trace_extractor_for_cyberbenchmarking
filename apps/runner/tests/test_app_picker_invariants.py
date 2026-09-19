from pathlib import Path


def _source(name: str) -> str:
    return (
        Path(__file__).parents[1]
        / "src"
        / "gpt_trace_runner"
        / name
    ).read_text(encoding="utf-8")


def test_app_selection_uses_keyboard_enter_not_popup_dom() -> None:
    source = _source("tools.py")
    assert 'await page.keyboard.type("@")' in source
    assert "await page.keyboard.type(tool.name)" in source
    assert 'await page.keyboard.press("Enter")' in source
    assert "_find_mention_result" not in source
    assert "_POPUP_ROOTS" not in source
    assert "_MENTION_ITEMS" not in source
    assert "delay=20" not in source


def test_app_selection_waits_for_current_composer_transition() -> None:
    source = _source("tools.py")
    select = source.split("async def _select_app_via_mention", 1)[1].split(
        "async def _composer_has_keyboard_focus", 1
    )[0]

    assert 'await page.keyboard.press("Enter")' in select
    assert "await _wait_app_accepted(" in select
    assert select.index('await page.keyboard.press("Enter")') < select.index(
        "await _wait_app_accepted("
    )
    assert "page.wait_for_function(" in source
    assert "_COMPOSER_ACCEPTED_JS" in source
    assert "page.expect_response(" not in source
    assert "client_prepare_source" not in source
    assert "asyncio.sleep" not in source


def test_auth_cleanup_reacquires_composer_and_uses_backspace_only() -> None:
    source = _source("tools.py")
    cleanup = source.split("async def _clear_auth_editor", 1)[1].split(
        "async def assert_apps_available", 1
    )[0]

    assert cleanup.count("editor = await get_editor()") >= 2
    assert 'await page.keyboard.press("Backspace")' in cleanup
    assert 'press("Control+A")' not in cleanup
    assert 'press("Control+End")' not in cleanup
    assert "interaction.click" not in cleanup
    assert "_composer_has_keyboard_focus(editor)" in cleanup


def test_each_app_resolves_current_composer() -> None:
    source = _source("tools.py")
    select = source.split("async def _select_app_via_mention", 1)[1].split(
        "async def _composer_has_keyboard_focus", 1
    )[0]
    preflight = source.split("async def assert_apps_available", 1)[1].split(
        "async def select_apps", 1
    )[0]
    runtime = source.split("async def select_apps", 1)[1]

    assert "editor = await get_editor()" in select
    assert "get_editor=get_editor" in preflight
    assert "await _clear_auth_editor(page, get_editor=get_editor)" in preflight
    assert "get_editor=get_editor" in runtime

    chatgpt = _source("chatgpt.py")
    verify = chatgpt.split("async def verify_apps_available", 1)[1].split(
        "async def _compose", 1
    )[0]
    compose = chatgpt.split("async def _compose", 1)[1].split(
        "async def prepare_task", 1
    )[0]
    assert "get_editor=self._site.wait_ready" in verify
    assert "get_editor=self._site.wait_ready" in compose


def test_chatgpt_compose_selects_apps_before_appending_exact_benchmark_prompt() -> None:
    source = _source("chatgpt.py")
    compose = source.split("async def _compose", 1)[1].split(
        "async def prepare_task", 1
    )[0]

    assert "await select_apps(" in compose
    assert "self._interaction.type_text(" in compose
    assert "            task.prompt," in compose
    assert "clear_existing=False" in compose
    assert compose.index("select_apps") < compose.index("type_text")
    assert "_prompt_for_chatgpt" not in source


def test_chatgpt_uses_one_prompt_identity_for_transport_and_validation() -> None:
    source = _source("chatgpt.py")
    submit = source.split("async def submit_task", 1)[1].split(
        "def _validate_required_tools", 1
    )[0]
    validated = source.split("def _validated_messages", 1)[1].split(
        "async def wait_for_completion", 1
    )[0]

    assert "submitted_prompt_matches(prepared.task.prompt)" in submit
    assert "validate_task_conversation(messages, task.prompt)" in validated
    assert "_prompt_for_chatgpt" not in source
    prepared = source.split("class PreparedTurn", 1)[1].split(
        "@dataclass(slots=True)\nclass SubmittedTurn", 1
    )[0]

    assert "submitted_prompt" not in prepared


def test_new_chat_wait_for_function_uses_keyword_arg() -> None:
    source = _source("chatgpt.py")
    new_chat = source.split("async def _new_chat_if_needed", 1)[1].split(
        "async def _visible_exact_text", 1
    )[0]
    assert "arg=old_id" in new_chat
    assert "\n                old_id,\n" not in new_chat

def test_wait_for_function_payload_is_keyword_only() -> None:
    source = _source("tools.py")
    wait = source.split("async def _wait_app_accepted", 1)[1].split(
        "def check_playwright_ui_contracts", 1
    )[0]

    assert "arg=[raw_mention, tool.name]" in wait
    assert (
        "_COMPOSER_ACCEPTED_JS,\n"
        "            [raw_mention, tool.name],"
    ) not in wait


def test_doctor_checks_playwright_ui_contracts() -> None:
    tools = _source("tools.py")
    assert "def check_playwright_ui_contracts() -> None:" in tools
    assert 'node.func.attr == "wait_for_function"' in tools
    assert '"arg" not in keyword_names' in tools

    cli = _source("cli.py")
    doctor = cli.split("def doctor(", 1)[1].split("@app.command()", 1)[0]
    assert "check_playwright_ui_contracts()" in doctor

def test_app_selection_focuses_composer_without_pointer_click() -> None:
    source = _source("tools.py")
    select = source.split("async def _select_app_via_mention", 1)[1].split(
        "async def _composer_has_keyboard_focus", 1
    )[0]

    assert "await interaction.focus(editor)" in select
    assert "interaction.click(editor)" not in select
    assert 'await editor.press("Control+End")' in select

