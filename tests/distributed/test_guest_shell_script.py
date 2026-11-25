import errno
import json
import os
import runpy
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym'
runtime = runpy.run_path(str(ADAPTER / 'guest_runtime.py'))
shell = runtime['shell']


def test_pinned_conda_scripts_exceed_exec_argument_limit_but_parse_as_files(tmp_path):
    contract = json.loads((ADAPTER / 'contract.json').read_bytes())
    lock = json.loads((ADAPTER / 'conda-lock.json').read_bytes())
    oversized = []
    for key, record in contract['environments'].items():
        commands = runtime['locked_environment_script'](key, record, lock)
        script = 'set -eo pipefail\n' + '\n'.join(runtime['_template_script'](commands)) + '\n'
        path = tmp_path / (key + '.sh')
        path.write_text(script)
        subprocess.run(['/bin/bash', '-n', str(path)], check=True)
        if len(os.fsencode(script)) >= 32 * os.sysconf('SC_PAGE_SIZE'):
            oversized.append(script)
    assert oversized
    for script in oversized:
        with pytest.raises(OSError) as error:
            subprocess.run(['/bin/bash', '-n', '-c', script], check=True)
        assert error.value.errno == errno.E2BIG


@pytest.mark.parametrize('trace', [False, True])
def test_large_recipe_preserves_shell_state_and_cleans_script(tmp_path, monkeypatch, trace):
    serial = tmp_path / 'serial'
    monkeypatch.setenv('GPTTRACE_TEMPLATE_TRACE', '1' if trace else '0')
    real_trace = runtime['_template_script']
    monkeypatch.setitem(shell.__globals__, '_template_script', lambda commands: (
        line.replace('>/dev/ttyS0', '>>' + str(serial)) for line in real_trace(commands)))
    (tmp_path / 'subdir').mkdir()
    limit = 32 * os.sysconf('SC_PAGE_SIZE')
    commands = ['value=preserved', 'cd subdir', ': ' + 'x' * limit,
                'printf "%s\\n" "$value" "$PWD" "$1"', 'printf "%s\\n" "$0" > ../script-path']
    log = tmp_path / 'recipe.log'
    shell(commands, cwd=tmp_path, log=log)
    assert log.read_text().splitlines() == ['preserved', str(tmp_path / 'subdir'), '']
    assert not Path((tmp_path / 'script-path').read_text().strip()).exists()
    if trace:
        assert serial.read_text().splitlines() == [
            f'GPTTRACE_TEMPLATE {state} recipe-{index}'
            for index in range(len(commands)) for state in ('begin', 'end')]


def test_failed_recipe_keeps_log_and_pipefail(tmp_path, monkeypatch):
    monkeypatch.delenv('GPTTRACE_TEMPLATE_TRACE', raising=False)
    log = tmp_path / 'error.log'
    with pytest.raises(RuntimeError, match='failure detail'):
        shell(['printf "%s\\n" "$0" > script-path', 'echo failure detail', 'false | true',
               'touch must-not-run'], cwd=tmp_path, log=log)
    assert not (tmp_path / 'must-not-run').exists()
    assert not Path((tmp_path / 'script-path').read_text().strip()).exists()
    assert 'failure detail' in log.read_text()


def test_offline_recipe_stays_inside_network_namespace(tmp_path, monkeypatch):
    monkeypatch.delenv('GPTTRACE_TEMPLATE_TRACE', raising=False)
    seen = []
    def inspect(argv, **kwargs):
        assert argv[:3] == ['unshare', '--net', '/bin/bash']
        assert len(argv) == 4
        assert Path(argv[3]).read_text() == 'ip link set lo up\nset -eo pipefail\ntrue\n'
        seen.append(Path(argv[3]))
        return subprocess.CompletedProcess(argv, 0)
    monkeypatch.setattr(subprocess, 'run', inspect)
    shell(['true'], cwd=tmp_path, offline=True)
    assert len(seen) == 1 and not seen[0].exists()
