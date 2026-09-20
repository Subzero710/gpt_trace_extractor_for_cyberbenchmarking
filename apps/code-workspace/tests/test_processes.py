import os
from code_workspace.processes import ProcessService
def test_processes_lists_self():assert any(x['pid']==os.getpid() for x in ProcessService(os.getuid(),lambda:None).list({})['processes'])
