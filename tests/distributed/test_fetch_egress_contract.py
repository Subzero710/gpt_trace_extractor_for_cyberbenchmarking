"""Test the preparation-network configuration without probing host networking."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "apps/workstation-broker/src/workstation_broker/fetch_egress.py"


def _module():
    spec = importlib.util.spec_from_file_location("fetch_egress_contract", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_composed_network_identity_is_shared_by_worker_and_builder():
    module = _module()
    network = module.source_network()
    assert module.source_builder() == network
    command = module.fetch_worker_command(SimpleNamespace(pw_uid=2345, pw_gid=2346),
                                          "/usr/bin/python3", ["/path with spaces/worker.py"])
    assert command[:4] == ["ip", "netns", "exec", network]
    assert "--reuid=2345" in command
    assert "--regid=2346" in command
    assert "--clear-groups" in command
    assert "--umask=0077" in command
    assert "--no-new-privs" in command
    assert command[-4:] == ["/usr/bin/python3", "-I", "-B", "/path with spaces/worker.py"]


def test_network_identity_is_declared_in_compose_not_environment(monkeypatch):
    module = _module()
    network = module.source_network()
    for key in ("GPT_TRACE_FETCH_DOCKER_NETWORK", "GPT_TRACE_FETCH_NETNS",
                "GPT_TRACE_FETCH_BUILDER", "DIST_FETCH_DOCKER_NETWORK",
                "DIST_FETCH_NETNS", "DIST_FETCH_BUILDER"):
        monkeypatch.setenv(key, "should-not-be-used")
    assert module.source_network() == network
    assert module.source_builder() == network


def test_no_runtime_route_or_vpn_discovery():
    content = SOURCE.read_text()
    for forbidden in ("mullvad", "nft", "route get", "ipify", "resolvectl",
                      "network inspect", "docker network create", "subprocess.run"):
        assert forbidden not in content.lower()


def test_deployment_name_comes_from_compose_file(monkeypatch, tmp_path):
    module = _module()
    config = tmp_path / "compose.yaml"
    config.write_text('{"networks":{"fetch_egress":{"name":"different-provisioned-name"}}}')
    monkeypatch.setattr(module, "MANIFEST", config)
    assert module.source_network() == "different-provisioned-name"
    assert module.source_builder() == "different-provisioned-name"
    command = module.fetch_worker_command(SimpleNamespace(pw_uid=2001, pw_gid=2002),
                                          "/usr/bin/python3", ["worker.py"])
    assert command[:4] == ["ip", "netns", "exec", "different-provisioned-name"]
