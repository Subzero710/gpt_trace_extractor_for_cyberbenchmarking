from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from typing import Any, Sequence
from urllib.parse import urlparse

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from rich.console import Console

from .app_lifecycle import AppLifecycle
from .exceptions import AppInfrastructureError
from .models import BenchmarkTask, BenchmarkTool, task_fingerprint


def _validate_endpoint(tool: BenchmarkTool) -> str:
    value = tool.mcp_endpoint or ""
    parsed = urlparse(value)
    if (parsed.scheme, parsed.hostname, parsed.port, parsed.path.rstrip('/')) != ('http', 'workstation-gateway', 8000, '/mcp'):
        raise AppInfrastructureError('invalid kali-workstation MCP endpoint')
    return value


async def _call(session: ClientSession, name: str, args: dict) -> dict:
    result = await session.call_tool(name, args)
    if result.isError or len(result.content) != 1:
        raise AppInfrastructureError(f'MCP {name} failed: {result.content}')
    output = json.loads(result.content[0].text)
    if not isinstance(output, dict):
        raise AppInfrastructureError(f'MCP {name} result was not an object')
    return output


async def _smoke(session: ClientSession, tool: BenchmarkTool, index: int, prior: str | None) -> str:
    actual = {t.name: t for t in (await session.list_tools()).tools}
    expected = {t['name']: t for t in tool.tool_manifest['tools']}
    if set(actual) != set(expected):
        raise AppInfrastructureError('MCP tools differ from the recorded manifest')
    for name, row in expected.items():
        if actual[name].description != row['description'] or actual[name].inputSchema != row['inputSchema']:
            raise AppInfrastructureError(f'MCP contract differs for {name}')

    marker = f'doctor-{index}-{hashlib.sha256(tool.manifest_sha256.encode()).hexdigest()[:12]}'
    command = await _call(session, 'exec_command', {'command': 'cat > marker.txt; sha256sum marker.txt',
        'stdin': marker, 'cwd': '/home/kali/workspace'})
    if command['exit_code'] != 0 or hashlib.sha256(marker.encode()).hexdigest() not in command['stdout']:
        raise AppInfrastructureError('guest exec stdin/sha256 failed')
    if prior is not None:
        stale = await _call(session, 'exec_command', {'command': 'test ! -e previous-attempt-marker'})
        if stale['exit_code'] != 0: raise AppInfrastructureError('fresh overlay retained previous attempt')
    await _call(session, 'exec_command', {'command': 'cp marker.txt previous-attempt-marker'})

    terminal = await _call(session, 'create_terminal', {})
    terminal_id = terminal['terminal_id']
    try:
        await _call(session, 'send_terminal_input', {'terminal_id': terminal_id, 'input': 'test -t 0 && echo PTY_IS_TTY\n'})
        output = await _call(session, 'read_terminal_output', {'terminal_id': terminal_id, 'wait_seconds': 1.0})
        if not any(line.rstrip('\r') == 'PTY_IS_TTY' for line in output['output'].split('\n')):
            raise AppInfrastructureError('terminal is not a working Unix PTY')
        await _call(session, 'resize_terminal', {'terminal_id': terminal_id, 'rows': 30, 'cols': 100})
    finally:
        await _call(session, 'close_terminal', {'terminal_id': terminal_id})

    network = await _call(session, 'exec_command', {'command':
        'getent ahostsv4 example.com >/dev/null && curl --fail --silent --show-error --max-time 15 -I https://example.com >/dev/null',
        'timeout_seconds': 30})
    if network['exit_code'] != 0:
        raise AppInfrastructureError(f'guest DNS/HTTPS egress failed: {network["stderr"][:300]}')
    isolation = await _call(session, 'exec_command', {'command':
        'test ! -e /var/run/docker.sock && test ! -e /var/run/libvirt/libvirt-sock && '
        'test ! -e /run/workstation-broker/broker.sock && '
        '(! timeout 3 bash -c "</dev/tcp/172.17.0.1/2375" 2>/dev/null)',
        'timeout_seconds': 10})
    if isolation['exit_code'] != 0:
        raise AppInfrastructureError('guest sees a host control socket or private Docker endpoint')

    before_screen = await _call(session, 'observe_screen', {})
    await _call(session, 'evaluate_javascript', {'expression': '''() => {
        document.body.style.background = 'rgb(255, 0, 0)';
        document.body.innerHTML = '<a download="doctor.txt" href="data:text/plain,doctor-test">save</a><input id="file" type="file"><p id="name"></p>';
        document.querySelector('#file').onchange=e=>document.querySelector('#name').textContent=e.target.files[0].name;
        return true;
    }'''})
    downloaded = await _call(session, 'download_file', {'selector': 'a'})
    shell = await _call(session, 'exec_command', {'command': 'sha256sum /home/kali/Downloads/doctor.txt'})
    if downloaded['sha256'] not in shell['stdout']:
        raise AppInfrastructureError('browser download missing in guest shell')
    await _call(session, 'upload_file', {'selector': '#file', 'path': '/home/kali/workspace/marker.txt'})
    html = await _call(session, 'get_html', {'selector': '#name'})
    if 'marker.txt' not in html['html']:
        raise AppInfrastructureError('browser cannot upload guest shell file')
    await _call(session, 'evaluate_javascript', {'expression':
        "() => { const input = document.createElement('input'); input.id = 'computer-probe'; document.body.appendChild(input); return true; }"})
    await _call(session, 'click', {'selector': '#computer-probe'})
    await _call(session, 'computer_input', {'events': [{'type': 'text', 'text': 'FROM_COMPUTER'}]})
    value = await _call(session, 'evaluate_javascript', {'expression': "() => document.querySelector('#computer-probe').value"})
    if value['result'] != 'FROM_COMPUTER':
        raise AppInfrastructureError('QMP computer input did not affect the structured browser page')
    image = await _call(session, 'observe_screen', {})
    raw = base64.b64decode(image['content_base64'], validate=True)
    if not raw.startswith(b'\x89PNG\r\n\x1a\n') or image['sha256'] != hashlib.sha256(raw).hexdigest():
        raise AppInfrastructureError('desktop screenshot integrity failed')
    if image['sha256'] == before_screen['sha256']:
        raise AppInfrastructureError('browser action did not change the libvirt display')
    return marker


async def preflight_tasks(lifecycle: AppLifecycle, tasks: Sequence[BenchmarkTask], *, console: Console,
                          require_chatgpt_block: bool = False) -> None:
    if not tasks: raise AppInfrastructureError('empty preflight selection')
    prior = None
    for index, task in enumerate(tasks, 1):
        probe = replace(task, task_id=f'doctor-{index}-{task_fingerprint(task)[:16]}')
        fingerprint = task_fingerprint(probe)
        environments = lifecycle.environment_ids(probe, attempt=1, fingerprint=fingerprint)
        prepared = False
        try:
            await lifecycle.health(probe)
            await lifecycle.prepare(probe, environments, fingerprint, attempt=1)
            prepared = True
            for tool in probe.tools:
                if tool.kind != 'local_mcp': continue
                async with streamable_http_client(_validate_endpoint(tool)) as (read, write, _):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        prior = await _smoke(session, tool, index, prior)
            console.print(f'[green]preflight {task.task_id}: ok[/]')
        finally:
            await lifecycle.reset(probe, environments, fingerprint, attempt=1)
            await lifecycle.assert_clean(probe, environments, fingerprint, attempt=1)
