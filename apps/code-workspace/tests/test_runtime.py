import os,pytest
from code_workspace.filesystem import WorkspaceSandbox
from code_workspace.shell import ShellService
from code_workspace.runtime import RuntimeService
@pytest.mark.asyncio
async def test_runtime(tmp_path):
 b=WorkspaceSandbox(tmp_path,os.getuid(),os.getgid(),lambda:None);r=RuntimeService(b,ShellService(b,os.getuid(),os.getgid()));assert (await r.venv({'path':'.venv'}))['exit_code']==0
