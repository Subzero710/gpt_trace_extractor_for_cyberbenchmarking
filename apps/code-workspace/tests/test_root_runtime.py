from code_workspace.core import WorkspaceManagerV2


def test_root_manager_configuration(tmp_path):
    manager = WorkspaceManagerV2(
        tmp_path / "workspace",
        tmp_path / "state",
        sandbox_uid=0,
        sandbox_gid=0,
        templates_root=__import__("pathlib").Path(__file__).resolve().parents[1] / "templates",
    )
    assert manager.sandbox_uid == 0
    assert manager.sandbox_gid == 0
    assert manager.shell_v2.uid == 0
    assert manager.shell_v2.gid == 0
    assert manager.shell_v2.env["HOME"] == "/root"
