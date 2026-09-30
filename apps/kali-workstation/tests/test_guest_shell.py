from __future__ import annotations
import asyncio
import os
import pytest
from kali_workstation.guest.shell import Terminals, exec_command

@pytest.mark.asyncio
async def test_exec_stdin_cwd_environment_timeout_and_bounded_output(tmp_path):
    result=await exec_command({'command':'pwd; cat; printf "%s" "$BENCH"', 'cwd':str(tmp_path),
                               'stdin':'hello','environment':{'BENCH':'world'},'timeout_seconds':10})
    assert result['exit_code']==0 and str(tmp_path) in result['stdout']
    assert 'helloworld' in result['stdout']
    bounded=await exec_command({'command':'yes x | head -c 1200000','cwd':str(tmp_path)})
    assert bounded['stdout_truncated'] is True and len(bounded['stdout'])<=1048576
    timeout=await exec_command({'command':'sleep 10','cwd':str(tmp_path),'timeout_seconds':1})
    assert timeout['timed_out'] is True

@pytest.mark.asyncio
async def test_real_unix_pty_resize_and_ctrl_c(tmp_path):
    terminals=Terminals(limit=1)
    created=terminals.create({'cwd':str(tmp_path),'rows':24,'cols':80})
    identifier=created['terminal_id']
    terminal=terminals.get({'terminal_id':identifier})
    assert terminal.process.poll() is None
    try:
        await terminals.send({'terminal_id':identifier,'input':'test -t 0 && echo IS_TTY; stty size\n'})
        output=await terminals.read({'terminal_id':identifier,'wait_seconds':.3})
        assert 'IS_TTY' in output['output'] and '24 80' in output['output']
        terminals.resize({'terminal_id':identifier,'rows':35,'cols':110})
        await terminals.send({'terminal_id':identifier,'input':'stty size\n'})
        output=await terminals.read({'terminal_id':identifier,'wait_seconds':.3})
        assert '35 110' in output['output']
        await terminals.send({'terminal_id':identifier,'input':'sleep 30\n'})
        await asyncio.sleep(.2)
        await terminals.send({'terminal_id':identifier,'input':'\x03'})
        await asyncio.sleep(.2)
        assert terminals.get({'terminal_id':identifier}).process.poll() is None
    finally:
        terminals.close({'terminal_id':identifier})
    assert terminal.process.poll() is not None
