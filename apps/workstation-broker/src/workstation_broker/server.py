from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import ipaddress
import pwd
import re
import secrets
import shutil
import socket
import struct
import subprocess
import tempfile
import uuid
import xml.etree.ElementTree as ET
import tomllib
from dataclasses import dataclass
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from .computer import capture, input_events

PORT = 17171
MAX_BODY = 32 * 1024 * 1024
SAFE_ID = re.compile(r"^[a-zA-Z0-9._:-]{1,255}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PROJECT = "gpt-trace-extractor"
META_NS = "urn:gpt-trace:workstation:3"
BLOCKED_EGRESS = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
                  "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
                  "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4")


def run(*args: str, input: bytes | None = None, ok: tuple[int, ...] = (0,)) -> bytes:
    result = subprocess.run(args, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if result.returncode not in ok:
        raise RuntimeError(f"{args[0]} {args[1] if len(args)>1 else ''} failed: {result.stderr[:500]!r}")
    return result.stdout


def identity(payload: dict) -> dict:
    result = {key: payload.get(key) for key in ("task_id", "attempt", "environment_id", "fingerprint")}
    if not all(isinstance(result[k], str) and SAFE_ID.fullmatch(result[k]) for k in ("task_id", "environment_id")):
        raise ValueError("invalid task or environment identity")
    if type(result["attempt"]) is not int or not 1 <= result["attempt"] <= 1000000:
        raise ValueError("invalid attempt")
    if not isinstance(result["fingerprint"], str) or not SHA256.fullmatch(result["fingerprint"]):
        raise ValueError("invalid fingerprint")
    return result


def suffix(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:20]


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def domain_xml(name: str, network: str, overlay: Path, config_iso: Path, cid: int,
               memory_mb: int, vcpus: int, ident: dict, digest: str) -> bytes:
    domain = ET.Element("domain", type="kvm")
    ET.SubElement(domain, "name").text = name
    ET.SubElement(domain, "memory", unit="MiB").text = str(memory_mb)
    ET.SubElement(domain, "vcpu").text = str(vcpus)
    ET.SubElement(domain, "os").append(ET.Element("type", arch="x86_64", machine="q35"))
    domain.find("os/type").text = "hvm"
    ET.SubElement(domain, "features").append(ET.Element("acpi"))
    ET.SubElement(domain, "cpu", mode="host-passthrough")
    ET.SubElement(domain, "clock", offset="utc")
    ET.SubElement(domain, "on_poweroff").text = "destroy"
    ET.SubElement(domain, "on_reboot").text = "restart"
    ET.SubElement(domain, "on_crash").text = "destroy"
    metadata = ET.SubElement(domain, "metadata")
    node = ET.SubElement(metadata, f"{{{META_NS}}}attempt")
    node.text = json.dumps({**ident, "project": PROJECT, "base_sha256": digest,
                            "overlay": str(overlay), "network": network, "cid": cid}, sort_keys=True)
    devices = ET.SubElement(domain, "devices")
    disk = ET.SubElement(devices, "disk", type="file", device="disk")
    ET.SubElement(disk, "driver", name="qemu", type="qcow2")
    ET.SubElement(disk, "source", file=str(overlay))
    ET.SubElement(disk, "target", dev="vda", bus="virtio")
    cd = ET.SubElement(devices, "disk", type="file", device="cdrom")
    ET.SubElement(cd, "driver", name="qemu", type="raw")
    ET.SubElement(cd, "source", file=str(config_iso))
    ET.SubElement(cd, "target", dev="sda", bus="sata")
    ET.SubElement(cd, "readonly")
    nic = ET.SubElement(devices, "interface", type="network")
    ET.SubElement(nic, "source", network=network)
    ET.SubElement(nic, "model", type="virtio")
    ET.SubElement(devices, "controller", type="usb", model="qemu-xhci")
    ET.SubElement(devices, "input", type="tablet", bus="usb")
    ET.SubElement(devices, "video").append(ET.Element("model", type="virtio", heads="1", primary="yes"))
    ET.SubElement(devices, "graphics", type="spice", autoport="yes", listen="127.0.0.1")
    vsock = ET.SubElement(devices, "vsock", model="virtio")
    ET.SubElement(vsock, "cid", auto="no", address=str(cid))
    return ET.tostring(domain, encoding="utf-8")


@dataclass
class Broker:
    root: Path
    base: Path
    admin_token: str
    controller_token: str
    memory_mb: int = 8192
    vcpus: int = 4
    boot_timeout_seconds: int = 120
    guest_agent_timeout_seconds: int = 60
    overlay_quota_gb: int = 16
    screenshot_max_bytes: int = 8388608
    max_terminals: int = 8
    max_output_bytes: int = 1048576
    max_transfer_bytes: int = 67108864
    max_seed_bytes: int = 268435456
    egress_allow_cidrs: tuple[str, ...] = ()

    def __post_init__(self):
        if not self.base.is_file() or self.base.is_symlink():
            raise RuntimeError(f"missing immutable Kali base image: {self.base}")
        if not 1024 <= self.memory_mb <= 65536 or not 1 <= self.vcpus <= 32:
            raise RuntimeError("invalid VM resource limits")
        if not 1 <= self.boot_timeout_seconds <= 600 or not 1 <= self.guest_agent_timeout_seconds <= 180:
            raise RuntimeError("invalid guest time limits")
        if not 4 <= self.overlay_quota_gb <= 128 or not 1024 <= self.screenshot_max_bytes <= 16 * 1024 * 1024:
            raise RuntimeError("invalid disk/screen limits")
        if not 1 <= self.max_terminals <= 64 or not 1024 <= self.max_output_bytes <= 8388608 or not 1024 <= self.max_seed_bytes <= 671088640 or not 1024 <= self.max_transfer_bytes <= 268435456:
            raise RuntimeError("invalid workstation I/O limits")
        for cidr in self.egress_allow_cidrs:
            if str(ipaddress.ip_network(cidr, strict=True)) != cidr or ':' in cidr:
                raise ValueError("egress exceptions must be canonical IPv4 CIDRs")
        self.qemu_uid = next((pwd.getpwnam(name).pw_uid for name in ("libvirt-qemu", "qemu")
                              if name in {entry.pw_name for entry in pwd.getpwall()}), None)
        if self.qemu_uid is None:
            raise RuntimeError("libvirt QEMU service user is missing")
        self.base_digest = file_sha256(self.base)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o711)

    def _mount(self, directory: Path) -> None:
        reservation = directory / "reservation.img"
        with reservation.open("xb") as output:
            os.fchmod(output.fileno(), 0o600)
        run("fallocate", "-l", f"{self.overlay_quota_gb}G", str(reservation))
        if reservation.stat().st_blocks * 512 < self.overlay_quota_gb * 1024 ** 3:
            raise RuntimeError("filesystem did not reserve the complete overlay quota")
        run("mkfs.ext4", "-F", "-q", str(reservation))
        mountpoint = directory / "disk"
        mountpoint.mkdir(mode=0o711)
        run("mount", "-o", "loop,nosuid,nodev", str(reservation), str(mountpoint))
        os.chmod(mountpoint, 0o711)

    @staticmethod
    def _unmount(directory: Path) -> None:
        mountpoint = directory / "disk"
        if mountpoint.is_mount():
            run("umount", str(mountpoint))

    def _firewall(self, ident: dict, bridge: str, gateway_ip: str) -> None:
        table = "gt_" + suffix(ident)
        exception_rules = "\n".join(f'add rule inet {table} forward iifname "{bridge}" ip daddr {cidr} accept'
                                    for cidr in self.egress_allow_cidrs)
        # DNS is accepted only to dnsmasq on this attempt's bridge. DHCP discover
        # is necessarily broadcast before the guest owns an address, while renewals
        # may be unicast to the bridge gateway. No other host-local service is exposed.
        script = f'''add table inet {table}
add chain inet {table} forward {{ type filter hook forward priority -50; policy accept; }}
add chain inet {table} input {{ type filter hook input priority -50; policy accept; }}
add rule inet {table} forward iifname "{bridge}" meta nfproto ipv6 drop
{exception_rules}
add rule inet {table} forward iifname "{bridge}" ip daddr {{ {', '.join(BLOCKED_EGRESS)} }} drop
add rule inet {table} input iifname "{bridge}" ip daddr {gateway_ip} udp dport 53 accept
add rule inet {table} input iifname "{bridge}" ip daddr {gateway_ip} tcp dport 53 accept
add rule inet {table} input iifname "{bridge}" ip daddr {{ {gateway_ip}, 255.255.255.255 }} udp dport 67 accept
add rule inet {table} input iifname "{bridge}" drop
'''
        run("nft", "-f", "-", input=script.encode())

    @staticmethod
    def _remove_firewall_key(key: str) -> None:
        if not re.fullmatch(r"[0-9a-f]{20}", key):
            raise ValueError("invalid workstation resource key")
        table = "gt_" + key
        if subprocess.run(("nft", "list", "table", "inet", table), capture_output=True).returncode == 0:
            run("nft", "delete", "table", "inet", table)

    @classmethod
    def _remove_firewall(cls, ident: dict) -> None:
        cls._remove_firewall_key(suffix(ident))

    def _paths(self, ident: dict) -> tuple[str, str, Path]:
        key = suffix(ident)
        return f"gpt-trace-ws-{key}", f"gpt-trace-net-{key}", self.root / key

    def _read(self, ident: dict, *, require_firewall: bool = True) -> dict:
        name, network, directory = self._paths(ident)
        state = directory / "state.json"
        if not state.is_file() or state.is_symlink():
            raise ValueError("attempt state missing")
        data = json.loads(state.read_text())
        if data.get("identity") != ident or data.get("name") != name or data.get("network") != network:
            raise ValueError("attempt identity mismatch")
        xml = ET.fromstring(run("virsh", "-c", "qemu:///system", "dumpxml", name))
        node = xml.find(f"./metadata/{{{META_NS}}}attempt")
        if node is None or json.loads(node.text or "null") != data["metadata"]:
            raise ValueError("libvirt domain identity mismatch")
        if data["metadata"]["base_sha256"] != self.base_digest:
            raise ValueError("base image identity changed")
        disk = xml.find("./devices/disk[@device='disk']/source")
        if disk is None or disk.get("file") != str(directory / "disk/overlay.qcow2"):
            raise ValueError("domain overlay mismatch")
        if not (directory / "disk").is_mount() or not (directory / "disk/overlay.qcow2").is_file():
            raise ValueError("overlay missing")
        disk_info = json.loads(run("qemu-img", "info", "--output=json", str(directory / "disk/overlay.qcow2")))
        if disk_info.get("format") != "qcow2" or Path(disk_info.get("backing-filename", "")).resolve() != self.base.resolve():
            raise ValueError("overlay backing image mismatch")
        if not run("virsh", "-c", "qemu:///system", "net-list", "--all", "--name").decode().splitlines().__contains__(network):
            raise ValueError("attempt network missing")
        if require_firewall and subprocess.run(("nft", "list", "table", "inet", "gt_" + suffix(ident)),
                                               capture_output=True).returncode != 0:
            raise ValueError("attempt egress firewall missing")
        return data

    async def create(self, ident: dict) -> dict:
        name, network, directory = self._paths(ident)
        if directory.exists() or name in run("virsh", "-c", "qemu:///system", "list", "--all", "--name").decode().splitlines():
            raise ValueError("attempt already exists; discover or destroy it explicitly")
        directory.mkdir(mode=0o711)
        secret = secrets.token_hex(32)
        cid = 4096 + int(suffix(ident), 16) % 2147480000
        digest = self.base_digest
        overlay, iso = directory / "disk/overlay.qcow2", directory / "disk/identity.iso"
        meta = {**ident, "project": PROJECT, "base_sha256": digest,
                "overlay": str(overlay), "network": network, "cid": cid}
        state = {"identity": ident, "name": name, "network": network, "metadata": meta,
                 "secret": secret, "backend": "vsock", "base": str(self.base)}
        try:
            self._mount(directory)
            run("qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(self.base), str(overlay))
            os.chown(overlay, self.qemu_uid, -1)
            os.chmod(overlay, 0o600)
            key = int(suffix(ident), 16)
            subnet = f"10.{200 + key % 24}.{(key >> 8) % 256}"
            proposed = ipaddress.ip_network(subnet + ".0/24")
            for route in json.loads(run("ip", "-j", "route", "show", "table", "all")):
                destination = route.get("dst", "default")
                if destination == "default":
                    continue
                try:
                    existing = ipaddress.ip_network(destination, strict=False)
                except ValueError:
                    continue
                if proposed.overlaps(existing):
                    raise ValueError(f"workstation network conflicts with host route {existing}")
            bridge = "gt" + suffix(ident)[:10]
            net = (f"<network><name>{network}</name><forward mode='nat'/>"
                   f"<bridge name='{bridge}' stp='off' delay='0'/>"
                   f"<ip address='{subnet}.1' netmask='255.255.255.0'>"
                   f"<dhcp><range start='{subnet}.10' end='{subnet}.200'/></dhcp></ip></network>").encode()
            network_definition = directory / "network.xml"
            network_definition.write_bytes(net)
            run("virsh", "-c", "qemu:///system", "net-define", str(network_definition))
            run("virsh", "-c", "qemu:///system", "net-start", network)
            self._firewall(ident, bridge, f"{subnet}.1")
            (directory / "identity.json").write_text(json.dumps({**ident, "secret": secret,
                "limits": {"max_terminals": self.max_terminals, "max_output_bytes": self.max_output_bytes,
                           "max_transfer_bytes": self.max_transfer_bytes, "max_seed_bytes": self.max_seed_bytes}}))
            os.chmod(directory / "identity.json", 0o600)
            run("xorriso", "-as", "mkisofs", "-quiet", "-o", str(iso), "-V", "GPTTRACE", str(directory / "identity.json"))
            os.chown(iso, self.qemu_uid, -1)
            os.chmod(iso, 0o600)
            domain_definition = directory / "domain.xml"
            domain_definition.write_bytes(domain_xml(name, network, overlay, iso, cid, self.memory_mb, self.vcpus, ident, digest))
            run("virsh", "-c", "qemu:///system", "define", str(domain_definition))
            (directory / "state.json").write_text(json.dumps(state, sort_keys=True))
            os.chmod(directory / "state.json", 0o600)
            run("virsh", "-c", "qemu:///system", "start", name)
            for _ in range(self.boot_timeout_seconds):
                try:
                    reply = await self.rpc(ident, "health", {})
                    if reply.get("identity") == ident:
                        return await self.inspect_verified(ident)
                except (OSError, TimeoutError, ValueError):
                    pass
                await asyncio.sleep(1)
            raise TimeoutError("guest agent did not become ready")
        except BaseException:
            self.destroy(ident, strict=False)
            raise

    def inspect(self, ident: dict) -> dict:
        data = self._read(ident)
        state = run("virsh", "-c", "qemu:///system", "domstate", data["name"]).decode().strip()
        if state != "running":
            raise ValueError(f"attempt domain is {state}")
        return {"identity": ident, "domain": data["name"], "network": data["network"],
                "base_sha256": data["metadata"]["base_sha256"], "overlay": data["metadata"]["overlay"],
                "cid": data["metadata"]["cid"], "provider": "libvirt"}

    async def inspect_verified(self, ident: dict) -> dict:
        result = self.inspect(ident)
        health = await self.rpc(ident, "health", {})
        if health.get("identity") != ident or health.get("guest_agent_version") != "3.0.0":
            raise ValueError("guest agent identity/version mismatch")
        return {**result, "guest_agent_version": health["guest_agent_version"]}

    def destroy(self, ident: dict, *, strict: bool = True) -> None:
        name, network, directory = self._paths(ident)
        if directory.exists() and strict:
            self._read(ident, require_firewall=False)
        elif strict and name in run("virsh", "-c", "qemu:///system", "list", "--all", "--name").decode().splitlines():
            raise ValueError("unowned domain exists; refusing blind deletion")
        if not directory.exists() and strict:
            return
        domains = run("virsh", "-c", "qemu:///system", "list", "--all", "--name").decode().splitlines()
        if name in domains:
            state = run("virsh", "-c", "qemu:///system", "domstate", name).decode().strip()
            if state == "running":
                run("virsh", "-c", "qemu:///system", "destroy", name)
            run("virsh", "-c", "qemu:///system", "undefine", name)
        networks = run("virsh", "-c", "qemu:///system", "net-list", "--all", "--name").decode().splitlines()
        if network in networks:
            active = run("virsh", "-c", "qemu:///system", "net-list", "--name").decode().splitlines()
            if network in active:
                run("virsh", "-c", "qemu:///system", "net-destroy", network)
            run("virsh", "-c", "qemu:///system", "net-undefine", network)
        self._remove_firewall(ident)
        self._unmount(directory)
        shutil.rmtree(directory, ignore_errors=False)
        self.assert_absent(ident)

    def assert_absent(self, ident: dict) -> None:
        name, network, directory = self._paths(ident)
        key = suffix(ident)
        firewall_present = subprocess.run(("nft", "list", "table", "inet", "gt_" + key),
                                          capture_output=True).returncode == 0
        if (directory.exists() or (directory / "disk").is_mount() or firewall_present
                or name in run("virsh", "-c", "qemu:///system", "list", "--all", "--name").decode().splitlines()
                or network in run("virsh", "-c", "qemu:///system", "net-list", "--all", "--name").decode().splitlines()):
            raise ValueError("attempt resources remain")

    def _destroy_orphan_key(self, key: str, directory: Path | None = None) -> None:
        if not re.fullmatch(r"[0-9a-f]{20}", key):
            raise ValueError("invalid orphan workstation resource key")
        name = f"gpt-trace-ws-{key}"
        network = f"gpt-trace-net-{key}"
        domains = run("virsh", "-c", "qemu:///system", "list", "--all", "--name").decode().splitlines()
        if name in domains:
            state = run("virsh", "-c", "qemu:///system", "domstate", name).decode().strip()
            if state == "running":
                run("virsh", "-c", "qemu:///system", "destroy", name)
            run("virsh", "-c", "qemu:///system", "undefine", name)
        networks = run("virsh", "-c", "qemu:///system", "net-list", "--all", "--name").decode().splitlines()
        if network in networks:
            active = run("virsh", "-c", "qemu:///system", "net-list", "--name").decode().splitlines()
            if network in active:
                run("virsh", "-c", "qemu:///system", "net-destroy", network)
            run("virsh", "-c", "qemu:///system", "net-undefine", network)
        self._remove_firewall_key(key)
        if directory is not None and directory.exists():
            if directory.is_symlink() or not directory.is_dir():
                raise ValueError(f"unsafe attempt state entry: {directory}")
            self._unmount(directory)
            shutil.rmtree(directory, ignore_errors=False)

    def destroy_all(self) -> dict:
        removed = []
        orphaned = []
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        for directory in sorted(self.root.iterdir()):
            if directory.is_symlink() or not directory.is_dir() or not re.fullmatch(r"[0-9a-f]{20}", directory.name):
                raise ValueError(f"unexpected workstation state entry: {directory.name}")
            state = directory / "state.json"
            if state.is_file() and not state.is_symlink():
                data = json.loads(state.read_text())
                ident = identity(data["identity"])
                if suffix(ident) != directory.name:
                    raise ValueError("attempt state directory/identity mismatch")
                self.destroy(ident)
                self.assert_absent(ident)
                removed.append(ident)
            else:
                # A host crash can happen after the quota filesystem or libvirt
                # resources exist but before state.json is durable. The directory
                # name is the project-owned deterministic key, so recover it without
                # requiring partially-written identity metadata.
                self._destroy_orphan_key(directory.name, directory)
                orphaned.append(directory.name)

        # Also reap project-prefixed libvirt/nft resources whose state directory was
        # lost entirely. The prefixes are reserved exclusively by this broker.
        domains = [name for name in run("virsh", "-c", "qemu:///system", "list", "--all", "--name").decode().splitlines()
                   if re.fullmatch(r"gpt-trace-ws-[0-9a-f]{20}", name)]
        networks = [name for name in run("virsh", "-c", "qemu:///system", "net-list", "--all", "--name").decode().splitlines()
                    if re.fullmatch(r"gpt-trace-net-[0-9a-f]{20}", name)]
        keys = {name.removeprefix("gpt-trace-ws-") for name in domains}
        keys.update(name.removeprefix("gpt-trace-net-") for name in networks)
        nft_tables = run("nft", "list", "tables").decode(errors="replace").splitlines()
        for line in nft_tables:
            match = re.fullmatch(r"table inet gt_([0-9a-f]{20})", line.strip())
            if match:
                keys.add(match.group(1))
        for key in sorted(keys):
            self._destroy_orphan_key(key)
            orphaned.append(key)

        remaining = [name for name in run("virsh", "-c", "qemu:///system", "list", "--all", "--name").decode().splitlines()
                     if name.startswith("gpt-trace-ws-")]
        remaining += [name for name in run("virsh", "-c", "qemu:///system", "net-list", "--all", "--name").decode().splitlines()
                      if name.startswith("gpt-trace-net-")]
        remaining_tables = [line.strip() for line in run("nft", "list", "tables").decode(errors="replace").splitlines()
                            if re.fullmatch(r"table inet gt_[0-9a-f]{20}", line.strip())]
        if remaining or remaining_tables:
            raise ValueError(f"project resources remain: {remaining + remaining_tables}")
        return {"removed": removed, "orphaned": sorted(set(orphaned))}

    async def rpc(self, ident: dict, method: str, args: dict) -> dict:
        data = self._read(ident)
        if not isinstance(method, str) or not re.fullmatch(r"[a-z_]{1,40}", method):
            raise ValueError("invalid guest RPC method")
        body = json.dumps({"identity": ident, "secret": data["secret"], "method": method, "args": args}).encode()
        if len(body) > MAX_BODY:
            raise ValueError("guest RPC too large")
        def exchange() -> dict:
            with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.guest_agent_timeout_seconds)
                connection.connect((data["metadata"]["cid"], PORT))
                connection.settimeout(1850)
                connection.sendall(struct.pack("!I", len(body)) + body)
                size = struct.unpack("!I", recv_exact(connection, 4))[0]
                if size > MAX_BODY:
                    raise ValueError("guest response too large")
                response = json.loads(recv_exact(connection, size))
                if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
                    raise ValueError("invalid guest response")
                if not response["ok"]:
                    raise ValueError(str(response.get("error", "guest RPC failed"))[:1000])
                return response["result"]
        return await asyncio.to_thread(exchange)

    def screen(self, ident: dict) -> dict:
        data = self._read(ident)
        return capture(run, data["name"], self._paths(ident)[2] / "disk", self.screenshot_max_bytes)

    def input(self, ident: dict, args: dict) -> dict:
        data = self._read(ident)
        shot = self.screen(ident)
        return input_events(run, data["name"], args, shot["width"], shot["height"])

    def _artifacts(self, ident: dict) -> Path:
        self._read(ident)
        folder = self._paths(ident)[2] / "disk/artifacts"
        folder.mkdir(mode=0o700, exist_ok=True)
        return folder

    def stage_begin(self, ident: dict) -> dict:
        folder = self._artifacts(ident)
        upload_id = uuid.uuid4().hex
        with (folder / (".upload-" + upload_id)).open("xb"):
            pass
        os.chmod(folder / (".upload-" + upload_id), 0o600)
        return {"upload_id": upload_id}

    def stage_abort(self, ident: dict, args: dict) -> dict:
        upload_id = args.get("upload_id", "")
        if not re.fullmatch(r"[0-9a-f]{32}", upload_id):
            raise ValueError("invalid upload identifier")
        (self._artifacts(ident) / (".upload-" + upload_id)).unlink(missing_ok=True)
        return {"aborted": True}

    def stage_chunk(self, ident: dict, args: dict) -> dict:
        upload_id = args.get("upload_id", "")
        if not re.fullmatch(r"[0-9a-f]{32}", upload_id):
            raise ValueError("invalid upload identifier")
        data = base64.b64decode(args["content_base64"], validate=True)
        if len(data) > 1048576:
            raise ValueError("artifact chunk exceeds limit")
        target = self._artifacts(ident) / (".upload-" + upload_id)
        with target.open("r+b") as output:
            output.seek(0, os.SEEK_END)
            if output.tell() + len(data) > self.max_transfer_bytes:
                raise ValueError("artifact exceeds configured limit")
            output.write(data)
        return {"received": target.stat().st_size}

    def stage_end(self, ident: dict, args: dict) -> dict:
        upload_id = args.get("upload_id", "")
        digest = args.get("sha256", "")
        if not re.fullmatch(r"[0-9a-f]{32}", upload_id) or not SHA256.fullmatch(digest):
            raise ValueError("invalid artifact identity")
        folder = self._artifacts(ident)
        source = folder / (".upload-" + upload_id)
        if source.stat().st_size != args.get("size") or file_sha256(source) != digest:
            raise ValueError("staged artifact integrity mismatch")
        target = folder / digest
        if target.exists():
            if file_sha256(target) != digest:
                raise ValueError("existing artifact integrity mismatch")
            source.unlink()
        else:
            os.replace(source, target)
            os.chmod(target, 0o600)
        return {"artifact_id": digest, "size": target.stat().st_size, "sha256": digest}

    async def export_artifact(self, ident: dict, args: dict) -> dict:
        path = args.get("path")
        if not isinstance(path, str) or not path or len(path) > 4096:
            raise ValueError("invalid guest artifact path")
        info = await self.rpc(ident, "artifact_stat", {"path": path})
        size = info["size"]
        if type(size) is not int or not 0 <= size <= self.max_transfer_bytes:
            raise ValueError("export exceeds configured limit")
        folder = self._artifacts(ident)
        with tempfile.NamedTemporaryFile(dir=folder, prefix=".export-", delete=False) as output:
            temp = Path(output.name)
            digest = hashlib.sha256()
            try:
                while output.tell() < size:
                    result = await self.rpc(ident, "artifact_read_chunk", {"path": path, "offset": output.tell()})
                    chunk = base64.b64decode(result["content_base64"], validate=True)
                    if not chunk or len(chunk) > min(1048576, size - output.tell()):
                        raise ValueError("guest artifact changed during export")
                    output.write(chunk)
                    digest.update(chunk)
                output.flush()
                os.fsync(output.fileno())
                target = folder / digest.hexdigest()
                if target.exists():
                    if file_sha256(target) != digest.hexdigest():
                        raise ValueError("existing artifact integrity mismatch")
                else:
                    os.replace(temp, target)
                    os.chmod(target, 0o600)
                return {"path": path, "size": size, "sha256": digest.hexdigest(), "artifact_id": digest.hexdigest()}
            finally:
                temp.unlink(missing_ok=True)

    def artifact_chunk(self, ident: dict, args: dict) -> dict:
        artifact_id, offset = args.get("artifact_id", ""), args.get("offset")
        if not isinstance(artifact_id, str) or not SHA256.fullmatch(artifact_id) or type(offset) is not int or offset < 0:
            raise ValueError("invalid artifact reference")
        source = self._artifacts(ident) / artifact_id
        if not source.is_file() or source.is_symlink() or source.stat().st_size > self.max_transfer_bytes:
            raise ValueError("artifact missing or exceeds configured limit")
        with source.open("rb") as stream:
            stream.seek(offset)
            data = stream.read(1048576)
        return {"content_base64": base64.b64encode(data).decode(), "size": source.stat().st_size,
                "sha256": artifact_id}

    async def import_artifact(self, ident: dict, args: dict) -> dict:
        artifact_id, path = args.get("artifact_id", ""), args.get("path")
        if not isinstance(artifact_id, str) or not SHA256.fullmatch(artifact_id) or not isinstance(path, str) or not path:
            raise ValueError("invalid import reference")
        source = self._artifacts(ident) / artifact_id
        if not source.is_file() or source.is_symlink() or source.stat().st_size > self.max_transfer_bytes or file_sha256(source) != artifact_id:
            raise ValueError("artifact missing or integrity mismatch")
        size = source.stat().st_size
        await self.rpc(ident, "artifact_import_begin", {"path": path, "sha256": artifact_id,
                                                           "overwrite": args.get("overwrite", False)})
        try:
            with source.open("rb") as stream:
                while chunk := stream.read(1048576):
                    await self.rpc(ident, "artifact_import_chunk", {"content_base64": base64.b64encode(chunk).decode()})
            return await self.rpc(ident, "artifact_import_end", {"size": size})
        except BaseException:
            await self.rpc(ident, "artifact_import_abort", {})
            raise


def recv_exact(connection: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = connection.recv(length - len(result))
        if not chunk:
            raise OSError("guest transport closed")
        result.extend(chunk)
    return bytes(result)


def create_app(broker: Broker) -> Starlette:
    controller_actions = frozenset({
        "inspect_attempt", "rpc", "capture_screen", "send_input",
        "artifact_stage_begin", "artifact_stage_chunk", "artifact_stage_end",
        "artifact_stage_abort", "artifact_export", "artifact_import", "artifact_read",
    })

    async def health(_: Request):
        return JSONResponse({"status": "ok", "project": PROJECT})

    async def dispatch(request: Request):
        authorization = request.headers.get("authorization", "")
        admin = hmac.compare_digest(authorization, f"Bearer {broker.admin_token}")
        controller = hmac.compare_digest(authorization, f"Bearer {broker.controller_token}")
        if not admin and not controller:
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        action = request.path_params["action"]
        if controller and not admin and action not in controller_actions:
            return JSONResponse({"detail": "broker action forbidden for controller token"}, status_code=403)
        try:
            raw = await request.body()
            if len(raw) > MAX_BODY:
                raise ValueError("broker request too large")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError("broker request must be an object")
            if action == "probe": return JSONResponse({"status": "ok", "project": PROJECT})
            if action == "destroy_all": return JSONResponse(broker.destroy_all())
            ident = identity(payload)
            if action == "create_attempt": result = await broker.create(ident)
            elif action == "inspect_attempt": result = await broker.inspect_verified(ident)
            elif action == "destroy_attempt":
                broker.destroy(ident); result = {"destroyed": True}
            elif action == "assert_absent":
                broker.assert_absent(ident); result = {"absent": True}
            elif action == "rpc":
                result = await broker.rpc(ident, payload.get("method"), payload.get("args", {}))
            elif action == "capture_screen": result = await asyncio.to_thread(broker.screen, ident)
            elif action == "send_input": result = await asyncio.to_thread(broker.input, ident, payload.get("args", {}))
            elif action == "artifact_stage_begin": result = broker.stage_begin(ident)
            elif action == "artifact_stage_chunk": result = broker.stage_chunk(ident, payload.get("args", {}))
            elif action == "artifact_stage_end": result = broker.stage_end(ident, payload.get("args", {}))
            elif action == "artifact_stage_abort": result = broker.stage_abort(ident, payload.get("args", {}))
            elif action == "artifact_export": result = await broker.export_artifact(ident, payload.get("args", {}))
            elif action == "artifact_import": result = await broker.import_artifact(ident, payload.get("args", {}))
            elif action == "artifact_read": result = broker.artifact_chunk(ident, payload.get("args", {}))
            else: return JSONResponse({"detail": "unknown broker operation"}, status_code=404)
            return JSONResponse(result)
        except (ValueError, RuntimeError, OSError, TimeoutError, json.JSONDecodeError) as exc:
            return JSONResponse({"detail": str(exc)[:1000]}, status_code=409)

    return Starlette(routes=[Route("/healthz", health), Route("/v1/{action}", dispatch, methods=["POST"])])


def main():
    import uvicorn
    admin_token = Path(os.environ["WORKSTATION_BROKER_ADMIN_TOKEN_FILE"]).read_text().strip()
    controller_token = Path(os.environ["WORKSTATION_BROKER_CONTROLLER_TOKEN_FILE"]).read_text().strip()
    if len(admin_token) < 32 or len(controller_token) < 32:
        raise RuntimeError("broker tokens are missing or too short")
    if hmac.compare_digest(admin_token, controller_token):
        raise RuntimeError("broker admin and controller tokens must be distinct")
    config = tomllib.loads(Path(os.environ["WORKSTATION_CONFIG"]).read_text())["workstation"]
    broker = Broker(Path(os.environ["WORKSTATION_BROKER_STATE"]), Path(os.environ["WORKSTATION_BASE_IMAGE"]),
                    admin_token, controller_token,
                    memory_mb=config["memory_mb"], vcpus=config["vcpus"],
                    boot_timeout_seconds=config["boot_timeout_seconds"],
                    guest_agent_timeout_seconds=config["guest_agent_timeout_seconds"],
                    overlay_quota_gb=config["overlay_quota_gb"],
                    screenshot_max_bytes=config["screenshot_max_bytes"],
                    max_terminals=config["max_terminals"], max_output_bytes=config["max_output_bytes"],
                    max_transfer_bytes=config["max_transfer_bytes"], max_seed_bytes=config["max_seed_bytes"],
                    egress_allow_cidrs=tuple(config["egress_allow_cidrs"]))
    uds = Path(os.environ["WORKSTATION_BROKER_SOCKET"])
    uds.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if uds.exists():
        uds.unlink()
    uvicorn.run(create_app(broker), uds=str(uds), log_level="info")


if __name__ == "__main__":
    main()
