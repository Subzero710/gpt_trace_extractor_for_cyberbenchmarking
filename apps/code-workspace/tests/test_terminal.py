import os,pytest
from code_workspace.filesystem import WorkspaceSandbox
from code_workspace.shell import ShellService
@pytest.mark.asyncio
async def test_terminal(tmp_path):
 s=ShellService(WorkspaceSandbox(tmp_path,os.getuid(),os.getgid(),lambda:None),os.getuid(),os.getgid());t=await s.create({});await s.send({'terminal_id':t['terminal_id'],'input':'export X=ok; echo $X'});o=await s.read({'terminal_id':t['terminal_id'],'wait_seconds':.1});assert 'ok' in o['stdout'];await s.close({'terminal_id':t['terminal_id']})
