import os,stat
from pathlib import Path
import pytest
from code_workspace.filesystem import WorkspaceSandbox,FilesystemError

def test_workspace_path_rejects_traversal_and_symlink(tmp_path):
 root=tmp_path/"w";root.mkdir();outside=tmp_path/"secret";outside.write_text("x");(root/"link").symlink_to(outside)
 s=WorkspaceSandbox(root,os.getuid(),os.getgid(),lambda:None)
 with pytest.raises(FilesystemError):s.path("../secret")
 with pytest.raises(FilesystemError):s.path("link",True)

def test_fifo_is_not_regular(tmp_path):
 p=tmp_path/"fifo";os.mkfifo(p);st=os.lstat(p);assert not stat.S_ISREG(st.st_mode)
