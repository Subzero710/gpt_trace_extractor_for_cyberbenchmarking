import os,pytest
from pathlib import Path
from code_workspace.filesystem import WorkspaceSandbox,FilesystemError
def test_filesystem_v2(tmp_path):
 s=WorkspaceSandbox(tmp_path,os.getuid(),os.getgid(),lambda:None);s.mkdir({'path':'a'});s.atomic_write(s.path('a/x'),b'x');assert s.stat({'path':'a/x'})['size']==1
 with pytest.raises(FilesystemError):s.stat({'path':'../../etc/passwd'})
