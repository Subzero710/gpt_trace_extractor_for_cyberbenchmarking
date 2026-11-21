"""Use the preparation network identity declared by the Compose specification.

The same identity is provisioned outside this repository as a Linux network
namespace and a remote Buildx builder. No runtime route or VPN introspection.
"""
from __future__ import annotations

import json
from pathlib import Path


MANIFEST = Path(__file__).resolve().parents[4] / "compose.fetch-egress.yaml"


def source_network():
    document = json.loads(MANIFEST.read_text(encoding="utf-8"))
    return document["networks"]["fetch_egress"]["name"]


def source_builder():
    return source_network()


def fetch_worker_command(account, interpreter, argv):
    return [
        "ip", "netns", "exec", source_network(),
        "setpriv", "--reuid=" + str(account.pw_uid),
        "--regid=" + str(account.pw_gid), "--clear-groups",
        "--umask=0077", "--no-new-privs", "--inh-caps=-all",
        "--ambient-caps=-all", "--bounding-set=-all",
        str(interpreter), "-I", "-B", *map(str, argv),
    ]
