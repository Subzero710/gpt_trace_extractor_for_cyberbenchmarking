from pathlib import Path


def _source(name: str) -> str:
    return (
        Path(__file__).parents[1]
        / "src"
        / "gpt_trace_runner"
        / name
    ).read_text(encoding="utf-8")


def test_app_selection_types_one_validated_query_and_waits_before_enter() -> None:
    source = _source("tools.py")
    select = source.split("async def _select_app_via_mention", 1)[1].split(
        "async def _composer_has_keyboard_focus", 1
    )[0]

    assert "interaction.type_text(" in select
    assert "raw_mention," in select
    assert "clear_existing=False" in select
    assert "await _wait_app_candidate_ready(" in select
    assert 'await page.keyboard.press("Enter")' in select
    assert select.index("_wait_app_candidate_ready(") < select.index(
        'page.keyboard.press("Enter")'
    )
    assert 'page.keyboard.type("@")' not in select
    assert "page.keyboard.type(tool.name)" not in select
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
    assert "_APP_PICKER_READY_JS" in source
    assert "aria-activedescendant" in source
    assert "Enter was not pressed" in source
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


def test_chatgpt_binds_input_receipt_to_transport_by_message_identity() -> None:
    source = _source("chatgpt.py")
    submit = source.split("async def submit_task", 1)[1].split(
        "def _validate_required_tools", 1
    )[0]
    validated = source.split("def _validated_messages", 1)[1].split(
        "async def wait_for_completion", 1
    )[0]

    assert "submitted_user_message_id()" in submit
    assert "on_user_message_id(user_message_id)" in submit
    assert "submitted_prompt_matches" not in source
    assert "validate_conversation_identity(messages, user_message_id)" in validated
    assert "validate_task_conversation" not in source
    assert "_prompt_for_chatgpt" not in source

    submitted = source.split("class SubmittedTurn", 1)[1].split(
        "class ChatGPTClient", 1
    )[0]
    assert "user_message_id: str" in submitted


def test_new_chat_never_pointer_clicks_or_uses_new_chat_control() -> None:
    source = _source("chatgpt.py")
    new_chat = source.split("async def _new_chat_if_needed", 1)[1].split(
        "async def _visible_exact_text", 1
    )[0]

    assert "await self.goto_home()" in new_chat
    assert "self._interaction.click" not in new_chat
    assert "NEW_CHAT_SELECTORS" not in source
    assert "create-new-chat-button" not in source

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
    assert "interaction.type_text(" in select
    assert "clear_existing=False" in select

def test_runtime_app_selection_retries_once_only_pre_submission() -> None:
    source = _source("tools.py")
    runtime = source.split("async def select_apps", 1)[1]

    assert "for attempt in range(2):" in runtime
    assert "except AppUnavailable:" in runtime
    assert "if attempt:" in runtime
    assert 'await page.keyboard.press("Escape")' in runtime
    assert "await _clear_auth_editor(page, get_editor=get_editor)" in runtime


def test_app_picker_guard_detects_accidental_enter_submission() -> None:
    source = _source("tools.py")
    select = source.split("async def _select_app_via_mention", 1)[1].split(
        "async def _composer_has_keyboard_focus", 1
    )[0]

    assert "before_enter_url = page.url" in select
    assert 'page.url != before_enter_url and "/c/" in page.url' in select
    assert "App selection Enter unexpectedly submitted a conversation" in select

