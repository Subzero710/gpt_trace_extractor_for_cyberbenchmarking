import os,pytest
from code_workspace.filesystem import WorkspaceSandbox
from code_workspace.shell import ShellService
from code_workspace.git import GitService
@pytest.mark.asyncio
async def test_git(tmp_path):
 b=WorkspaceSandbox(tmp_path,os.getuid(),os.getgid(),lambda:None);s=ShellService(b,os.getuid(),os.getgid());g=GitService(b,s);assert (await s.run(['git','init','repo'],tmp_path))['exit_code']==0;assert (await g.status({'cwd':'repo'}))['exit_code']==0
