import os,pytest
from code_workspace.filesystem import WorkspaceSandbox
from code_workspace.network import NetworkService
@pytest.mark.asyncio
async def test_dns(tmp_path):
 n=NetworkService(WorkspaceSandbox(tmp_path,os.getuid(),os.getgid(),lambda:None));assert (await n.dns({'hostname':'localhost','family':'ipv4'}))['addresses']
