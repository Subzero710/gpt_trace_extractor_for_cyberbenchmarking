from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
from pathlib import Path

from .wire import certificate_sha, private_address, safe_file, token


def command(*arguments):
    subprocess.run(["openssl", *arguments], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def issue(root, name, san, usage):
    key, request, certificate = (root / (name + extension) for extension in (".key", ".csr", ".crt"))
    command("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(key))
    key.chmod(0o600)
    command("req", "-new", "-key", str(key), "-out", str(request), "-subj", "/CN=" + name)
    extension = root / (name + ".ext")
    extension.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                         "extendedKeyUsage=" + usage + "\nsubjectAltName=" + san + "\n")
    command("x509", "-req", "-in", str(request), "-CA", str(root / "ca.crt"), "-CAkey", str(root / "ca.key"),
            "-set_serial", "0x" + secrets.token_hex(16), "-days", "365", "-sha256", "-extfile", str(extension),
            "-out", str(certificate))
    certificate.chmod(0o644)
    command("verify", "-CAfile", str(root / "ca.crt"), "-purpose", "sslserver" if usage == "serverAuth" else "sslclient",
            str(certificate))


def provision(output, *, server_name, execution_address, control_address, control_id="control", execution_id="execution",
              port=9443, tokens_from=None):
    output = Path(output).absolute()
    for parent in (output, *output.parents):
        if parent.is_symlink():
            raise ValueError("symlink in PKI output path")
    if output.exists() or not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", server_name):
        raise ValueError("PKI output must be new and server DNS name must be explicit")
    for name in (control_id, execution_id):
        if not re.fullmatch(r"[a-zA-Z0-9-]{1,63}", name):
            raise ValueError("invalid host identity")
    execution_address, control_address = private_address(execution_address), private_address(control_address)
    if execution_address == control_address or control_id == execution_id or not 1024 <= port <= 65535:
        raise ValueError("hosts must have distinct identities and private addresses")
    output.mkdir(mode=0o700, parents=True)
    authority = output / "authority"
    authority.mkdir(mode=0o700)
    command("req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "3650", "-sha256",
            "-keyout", str(authority / "ca.key"), "-out", str(authority / "ca.crt"),
            "-subj", "/CN=Cyber-Dataset-Private-Broker-CA",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    (authority / "ca.key").chmod(0o600)
    issue(authority, "server", "DNS:" + server_name, "serverAuth")
    for role in ("admin", "controller"):
        issue(authority, role, "URI:urn:gpt-trace:" + control_id + ":" + role, "clientAuth")
        name = "workstation_broker_" + role + "_token"
        value = token(Path(tokens_from) / name) if tokens_from else secrets.token_urlsafe(48)
        (authority / name).write_text(value + "\n")
        (authority / name).chmod(0o600)
    if token(authority / "workstation_broker_admin_token") == token(authority / "workstation_broker_controller_token"):
        raise ValueError("admin and controller tokens must be distinct")
    metadata = {"schema": 1, "server_name": server_name, "execution_address": execution_address,
                "control_address": control_address, "control_id": control_id, "execution_id": execution_id,
                "port": port, "server_sha256": certificate_sha(authority / "server.crt")}
    result = {}
    for role in ("execution", "control"):
        directory = output / role
        directory.mkdir(mode=0o700)
        names = ["ca.crt", "server.crt", "admin.crt", "controller.crt",
                 "workstation_broker_admin_token", "workstation_broker_controller_token"]
        names += ["server.key"] if role == "execution" else ["admin.key", "controller.key"]
        for name in names:
            shutil.copyfile(authority / name, directory / name)
            (directory / name).chmod(0o600 if name.endswith(".key") or name.endswith("_token") else 0o644)
        manifest = {**metadata, "role": role, "files": {name: digest(directory / name) for name in names}}
        (directory / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
        bundle_sha = digest(directory / "manifest.json")
        # The installer transfers the expected digest with the credential bundle.
        # It is not entered in .env or generated from the manifest at runtime.
        (directory / "manifest.sha256").write_text(bundle_sha + "\n")
        (directory / "manifest.sha256").chmod(0o600)
        (directory / "distributed.env").write_text(
            f"DIST_ROLE={role}\n"
            f"DIST_CONTROL_ADDRESS={control_address}\n"
            f"DIST_EXECUTION_ADDRESS={execution_address}\n"
            f"DIST_SERVER_NAME={server_name}\n")
        (directory / "distributed.env").chmod(0o600)
        result[role] = {"manifest_sha256": bundle_sha, "directory": str(directory)}
    result["server_certificate_sha256"] = metadata["server_sha256"]
    return result


def verify_bundle(directory, expected, role, cfg):
    directory = Path(directory)
    if directory.is_symlink() or directory.stat().st_mode & 0o077:
        raise ValueError("credential bundle directory must be private mode 0700")
    if expected is None:
        # The expected digest was generated by provisioning, never configured
        # by the operator. Missing/changed pin fails closed. The initial transfer
        # must still be authenticated; a colocated checksum is not a trust root.
        expected = safe_file(directory / "manifest.sha256", secret=True).decode("ascii").strip()
    raw = safe_file(directory / "manifest.json")
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("bundle manifest fingerprint mismatch; verify transfer out of band")
    manifest = json.loads(raw)
    names = {"ca.crt", "server.crt", "admin.crt", "controller.crt", "workstation_broker_admin_token", "workstation_broker_controller_token"}
    names |= {"server.key"} if role == "execution" else {"admin.key", "controller.key"}
    if manifest.get("schema") != 1 or manifest.get("role") != role or set(manifest.get("files", {})) != names:
        raise ValueError("wrong bundle role/schema/files")
    for key, value in cfg.items():
        if manifest.get(key) != value:
            raise ValueError("bundle host/address/identity mismatch: " + key)
    for name, expected_sha in manifest["files"].items():
        raw = safe_file(directory / name, secret=name.endswith(".key") or name.endswith("_token"), mounted=name.endswith("_token"))
        if hashlib.sha256(raw).hexdigest() != expected_sha:
            raise ValueError("bundle member hash mismatch: " + name)
    if certificate_sha(directory / "server.crt") != manifest.get("server_sha256"):
        raise ValueError("server certificate pin mismatch")
    for name, usage in (("server", "sslserver"), ("admin", "sslclient"), ("controller", "sslclient")):
        command("verify", "-CAfile", str(directory / "ca.crt"), "-purpose", usage, str(directory / (name + ".crt")))
        command("x509", "-checkend", "0", "-noout", "-in", str(directory / (name + ".crt")))
    if token(directory / "workstation_broker_admin_token") == token(directory / "workstation_broker_controller_token"):
        raise ValueError("broker token scopes are not distinct")
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Offline, dedicated broker CA and separate host credential bundles")
    parser.add_argument("--output", required=True)
    parser.add_argument("--server-name", required=True)
    parser.add_argument("--execution-address", required=True)
    parser.add_argument("--control-address", required=True)
    parser.add_argument("--control-id", default="control")
    parser.add_argument("--execution-id", default="execution")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--tokens-from")
    args = parser.parse_args()
    print(json.dumps(provision(args.output, server_name=args.server_name, execution_address=args.execution_address,
        control_address=args.control_address, control_id=args.control_id, execution_id=args.execution_id,
        port=args.port, tokens_from=args.tokens_from), indent=2))


if __name__ == "__main__":
    main()
