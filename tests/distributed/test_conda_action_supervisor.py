"""Real-process and protocol regressions for the offline Conda action supervisor."""
from __future__ import annotations

import json
import os
from pathlib import Path
import runpy
import sys
import types

import pytest

import superbench_pool as pool


@pytest.fixture
def conda_child(tmp_path, monkeypatch):
    child = tmp_path / 'instrumented-conda.py'
    child.write_text('''\
import json
import os
from pathlib import Path
import sys
import time

scenario = json.loads(os.environ['CONDA_TEST_PAYLOAD'])
fd = int(os.environ.pop('GPT_TRACE_CONDA_EVENT_FD'))
Path(scenario['pid_file']).write_text(str(os.getpid()))
for item in scenario['events']:
    if isinstance(item, str):
        message = item.encode()
    else:
        message = (json.dumps({
            'event': item[0], 'id': item[1], 'label': item[2],
            'at': time.monotonic(),
        }) + '\\n').encode()
    os.write(fd, message)
os.close(fd)
print(scenario['output'], flush=True)
time.sleep(scenario['sleep'])
raise SystemExit(scenario['exit_code'])
''')
    monkeypatch.setattr(pool, '__file__', str(child))
    monkeypatch.setattr(pool, '_conda_progress_interval', lambda: 0.4)
    monkeypatch.setattr(pool, '_operation_timeout', lambda: 2)

    def run(events, *, exit_code=0, sleep=0.1, output='Conda diagnostic output'):
        payload = {
            'events': events, 'exit_code': exit_code, 'sleep': sleep,
            'output': output, 'pid_file': str(tmp_path / 'conda-child.pid'),
        }
        command = [sys.executable, '-m', 'conda', 'create', '--offline',
                   '--file', str(tmp_path / 'manifest')]
        environment = {**os.environ, 'CONDA_TEST_PAYLOAD': json.dumps(payload)}
        return pool._native_run_conda_elementary(command, {'root': tmp_path}, environment)

    return run, tmp_path / 'conda-child.pid'


READY = [('ready', 0, 'instrumented')]
COMPLETE = [('complete', 0, 'finished')]


def test_eof_before_successful_process_exit_is_accepted(conda_child):
    run, _pid = conda_child
    assert b'Conda succeeded' in run(READY + COMPLETE, output='Conda succeeded')


def test_eof_before_failed_exit_exposes_conda_output(conda_child):
    run, _pid = conda_child
    with pytest.raises(RuntimeError, match='instrumented Conda creation failed') as error:
        run(READY, exit_code=17, output='original Conda error')
    assert 'original Conda error' in str(error.value)
    assert '"exit_code": 17' in '\n'.join(error.value.__notes__)


def test_eof_while_child_remains_active_is_bounded_and_killed(conda_child):
    run, pid_file = conda_child
    with pytest.raises(TimeoutError, match='channel closed while the process remained active') as error:
        run(READY + COMPLETE, sleep=4, output='last Conda output')
    assert 'last Conda output' in '\n'.join(error.value.__notes__)
    pid = int(pid_file.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_success_without_completed_protocol_is_rejected(conda_child):
    run, _pid = conda_child
    with pytest.raises(RuntimeError, match='without a complete, balanced action stream'):
        run(READY)


@pytest.mark.parametrize('events,expected', [
    (['incomplete JSON'], 'truncated Conda action event stream'),
    (READY + [('begin', 1, 'active')] + COMPLETE, 'unexpected Conda action transition'),
    (READY + COMPLETE + COMPLETE, 'unexpected Conda action transition'),
    (COMPLETE, 'unexpected Conda action transition'),
])
def test_broken_action_stream_rejected(conda_child, events, expected):
    run, _pid = conda_child
    with pytest.raises(RuntimeError, match=expected):
        run(events)


def test_concrete_begin_end_protocol_remains_accepted(conda_child):
    run, _pid = conda_child
    stream = READY + [('begin', 1, 'file'), ('end', 1, 'file')] + COMPLETE
    assert b'Conda diagnostic output' in run(stream)


@pytest.mark.parametrize('exit_code,completed', [(0, True), (1, False)])
def test_child_emits_completion_only_after_success(monkeypatch, exit_code, completed):
    conda = types.ModuleType('conda')
    conda.__path__ = []
    core = types.ModuleType('conda.core')
    core.__path__ = []
    link = types.ModuleType('conda.core.link')
    cache = types.ModuleType('conda.core.package_cache_data')
    actions = types.ModuleType('conda.core.path_actions')

    class Action:
        def execute(self):
            return None
        def verify(self):
            return None

    class ProgressiveFetchExtract:
        @staticmethod
        def make_actions_for_record(*_args):
            return []

    actions._Action = Action
    cache.ProgressiveFetchExtract = ProgressiveFetchExtract
    cache.do_extract_action = lambda *_args: None
    cache.do_cache_action = lambda *_args: None
    link.run_script = lambda *_args: None
    core.link = link
    core.package_cache_data = cache
    core.path_actions = actions
    conda.core = core
    for module in (conda, core, link, cache, actions):
        monkeypatch.setitem(sys.modules, module.__name__, module)

    def run_module(*_args, **_kwargs):
        raise SystemExit(exit_code)

    monkeypatch.setattr(runpy, 'run_module', run_module)
    monkeypatch.setattr(sys, 'argv', ['script', '--conda-elementary-run', 'create'])
    reader, writer = os.pipe()
    monkeypatch.setenv('GPT_TRACE_CONDA_EVENT_FD', str(writer))
    try:
        with pytest.raises(SystemExit) as error:
            pool._conda_elementary_entry()
        assert error.value.code == exit_code
    finally:
        os.close(writer)
    with os.fdopen(reader, 'rb') as stream:
        events = [json.loads(line)['event'] for line in stream]
    assert events[0] == 'ready'
    assert ('complete' in events) is completed


@pytest.mark.parametrize('exit_code,failed', [(0, False), (None, False), (2, True)])
def test_normal_systemexit_never_logs_false_failure(monkeypatch, capsys, exit_code, failed):
    monkeypatch.setattr(sys, 'argv', ['script', '--conda-elementary-run'])

    def finish():
        raise SystemExit(exit_code)

    monkeypatch.setattr(pool, '_conda_elementary_entry', finish)
    with pytest.raises(SystemExit):
        pool._pool_cli_entry()
    assert ('[pool] FAILED' in capsys.readouterr().err) is failed
