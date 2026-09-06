from pathlib import Path

SRC = Path(__file__).parents[1] / "src" / "gpt_trace_runner"


def test_chatgpt_does_not_set_hidden_file_input_directly() -> None:
    text = (SRC / "chatgpt.py").read_text()
    assert "set_input_files" not in text
    assert "expect_file_chooser" in text
    assert ".set_files(payloads)" in text


def test_prompt_and_tools_have_no_machine_cadence_helpers() -> None:
    joined = "".join((SRC / name).read_text() for name in ("chatgpt.py", "tools.py", "interaction.py"))
    assert "keyboard.insert_text" not in joined
    assert "press_sequentially" not in joined
    assert "delay=20" not in joined
    assert "navigator.clipboard" not in joined
    assert "grant_permissions" not in joined


def test_normal_task_path_uses_new_chat_ui_not_home_reload() -> None:
    text = (SRC / "chatgpt.py").read_text()
    prepare = text.split("async def prepare_task", 1)[1].split("async def _click_send", 1)[0]
    assert "goto_home()" not in prepare
    assert "_new_chat_if_needed()" in prepare


def test_app_selection_happens_after_prompt_paste() -> None:
    text = (SRC / "chatgpt.py").read_text()
    compose = text.split("async def _compose", 1)[1].split("async def prepare_task", 1)[0]
    assert compose.index("paste_text") < compose.index("select_apps")
