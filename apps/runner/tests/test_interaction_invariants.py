from pathlib import Path


SRC = Path(__file__).parents[1] / "src" / "gpt_trace_runner"


def test_chatgpt_does_not_set_hidden_file_input_directly() -> None:
    text = (SRC / "chatgpt.py").read_text()
    assert "set_input_files" not in text
    assert "expect_file_chooser" in text
    assert ".set_files(payloads)" in text


def test_prompt_and_tools_have_no_machine_cadence_helpers() -> None:
    chatgpt = (SRC / "chatgpt.py").read_text()
    tools = (SRC / "tools.py").read_text()
    interaction = (SRC / "interaction.py").read_text()
    joined = chatgpt + tools + interaction
    assert "keyboard.insert_text" not in joined
    assert "press_sequentially" not in joined
    assert "delay=20" not in joined


def test_normal_task_path_does_not_reload_chatgpt_home() -> None:
    text = (SRC / "chatgpt.py").read_text()
    start = text.split("async def start_task", 1)[1].split(
        "def _validate_required_tools", 1
    )[0]
    assert "goto_home()" not in start
    assert "_new_chat_if_needed()" in start
