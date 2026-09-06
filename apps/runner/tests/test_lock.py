from pathlib import Path

import pytest

from gpt_trace_runner.exceptions import ConcurrentRunnerError
from gpt_trace_runner.lock import RunnerLock


def test_runner_lock_is_exclusive(tmp_path: Path) -> None:
    path = tmp_path / "runner.lock"
    first = RunnerLock(path)
    second = RunnerLock(path)
    first.acquire()
    try:
        with pytest.raises(ConcurrentRunnerError):
            second.acquire()
    finally:
        first.release()
    second.acquire()
    second.release()
