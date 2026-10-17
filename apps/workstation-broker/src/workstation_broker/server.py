# GPT_TRACE_PERSISTENT_TEMPLATE_RESUME_V1
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import ipaddress
import logging
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
from .templates import TemplateRegistry, backing
from gpt_trace_transport.wire import CONTROLLER_ACTIONS

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
    if payload.get("purpose") is not None:
        retry = payload.get("evaluator_retry")
        if payload["purpose"] != "evaluator" or not isinstance(retry, str) or re.fullmatch(r"[0-9a-f]{32}", retry) is None:
            raise ValueError("invalid isolated evaluator identity")
        result.update(purpose="evaluator", evaluator_retry=retry)
    return result


def suffix(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:20]


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def qemu_image_info(path: Path, *, force_share: bool = False) -> dict:
    args = ["qemu-img", "info"]
    if force_share:
        # qemu owns the overlay with a write lock while an attempt is running.
        # --force-share is qemu-img's read-only inspection mode for that case.
        args.append("--force-share")
    args.extend(["--output=json", str(path)])
    return json.loads(run(*args))


def domain_xml(name: str, network: str | None, overlay: Path, config_iso: Path, cid: int,
               memory_mb: int, vcpus: int, ident: dict, digest: str,
               template: dict | None = None) -> bytes:
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
                            "overlay": str(overlay), "network": network, "cid": cid, **(template or {})}, sort_keys=True)
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
    if network is not None:
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
    template_root: Path | None = None

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
        self.templates = TemplateRegistry(self.template_root or self.base.parent / "templates",
                                          self.base, qemu_image_info)
        # Verify the immutable golden exactly once. TemplateRegistry.expected()
        # validates provenance/package manifests and hashes the base through the
        # registry digest cache, so later backing checks reuse the same digest.
        self.base_digest = self.templates.expected()["golden_sha256"]
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
        # With a tunnel transport, the control host has no stable or configured IP.
        # Disallow private egress exceptions entirely in this deployment: guests
        # must not reach the control LAN even when no physical address is known.
        if os.environ.get("WORKSTATION_BROKER_EXECUTION_ID") and any(
                ipaddress.ip_network(cidr, strict=False).overlaps(private)
                for cidr in self.egress_allow_cidrs
                for private in (ipaddress.ip_network("10.0.0.0/8"),
                                ipaddress.ip_network("172.16.0.0/12"),
                                ipaddress.ip_network("192.168.0.0/16"))):
            raise ValueError("private egress exceptions are forbidden in two-host tunnel mode")
        control_cidrs = json.loads(os.environ.get("WORKSTATION_CONTROL_PLANE_CIDRS", "[]"))
        if not isinstance(control_cidrs, list):
            raise ValueError("invalid control-plane firewall configuration")
        control_rules = []
        for cidr in control_cidrs:
            network = ipaddress.ip_network(cidr, strict=True)
            if network.version != 4 or str(network) != cidr:
                raise ValueError("control-plane deny routes must be canonical IPv4 CIDRs")
            control_rules.append(f'add rule inet {table} forward iifname "{bridge}" ip daddr {cidr} drop')
        control_rules = "\n".join(control_rules)
        # DNS is accepted only to dnsmasq on this attempt's bridge. DHCP discover
        # is necessarily broadcast before the guest owns an address, while renewals
        # may be unicast to the bridge gateway. No other host-local service is exposed.
        script = f'''add table inet {table}
add chain inet {table} forward {{ type filter hook forward priority -50; policy accept; }}
add chain inet {table} input {{ type filter hook input priority -50; policy accept; }}
add rule inet {table} forward iifname "{bridge}" meta nfproto ipv6 drop
{control_rules}
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
        network = None if ident.get("purpose") == "evaluator" else f"gpt-trace-net-{key}"
        return f"gpt-trace-ws-{key}", network, self.root / key

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
        recorded = data["metadata"]
        if recorded.get("template_id") is not None:
            selection = self.templates.verify_record(recorded)
            selected = Path(selection["backing_path"])
            if recorded["base_sha256"] != selection["backing_sha256"] or data["base"] != str(selected):
                raise ValueError("selected backing identity changed")
        else:
            selected = self.base
            if recorded["base_sha256"] != self.base_digest or self.templates.immutable_sha256(selected) != self.base_digest:
                raise ValueError("base image identity changed")
        disk = xml.find("./devices/disk[@device='disk']/source")
        if disk is None or disk.get("file") != str(directory / "disk/overlay.qcow2"):
            raise ValueError("domain overlay mismatch")
        if not (directory / "disk").is_mount() or not (directory / "disk/overlay.qcow2").is_file():
            raise ValueError("overlay missing")
        disk_info = qemu_image_info(directory / "disk/overlay.qcow2", force_share=True)
        if disk_info.get("format") != "qcow2" or backing(disk_info, directory / "disk/overlay.qcow2") != selected.resolve():
            raise ValueError("overlay backing image mismatch")
        if ident.get("purpose") == "evaluator":
            if network is not None or xml.findall("./devices/interface") or xml.findall("./devices/filesystem") or xml.findall("./devices/graphics"):
                raise ValueError("evaluator has a network, shared filesystem or desktop route")
        elif not run("virsh", "-c", "qemu:///system", "net-list", "--all", "--name").decode().splitlines().__contains__(network):
            raise ValueError("attempt network missing")
        if network is not None and require_firewall and subprocess.run(("nft", "list", "table", "inet", "gt_" + suffix(ident)),
                                               capture_output=True).returncode != 0:
            raise ValueError("attempt egress firewall missing")
        return data

    def preflight_templates(self, template_ids) -> dict:
        if not isinstance(template_ids, list) or len(template_ids) > 256:
            raise ValueError("invalid template preflight selection")
        try:
            selected = {value: self.templates.select(value) for value in sorted(set(template_ids))}
            for record in selected.values():
                _, manifest = self.templates.manifest(record)
                for logical, row in manifest["task_artifacts"].items():
                    if row.get("template_id") == record["template_id"]:
                        self.templates.task_scope(record, logical)
        except (OSError, ValueError) as exc:
            raise RuntimeError("SWE-Gym Lite local artifacts are unavailable/incompatible: " + str(exc) +
                "; run make superbench-fetch ADAPTER=swe-gym-lite on the control host") from exc
        return {"templates": selected}

    async def create(self, ident: dict, template_id: str | None = None, logical_task_id=None, *, _selection=None) -> dict:
        name, network, directory = self._paths(ident)
        if template_id is not None and (directory / "state.json").is_file():
            data = self._read(ident)
            if data["metadata"].get("template_id") != template_id or data["metadata"].get("logical_task_id") != logical_task_id:
                raise ValueError("attempt already uses another template")
            return await self.inspect_verified(ident)
        if ident.get("purpose") == "evaluator" and _selection is None:
            raise ValueError("evaluator must be created from its recorded teacher backing")
        selection = _selection if _selection is not None else self.templates.select(template_id) if template_id is not None else {}
        if selection:
            self.templates.task_scope(selection, logical_task_id)
            selection = {**selection, "logical_task_id": logical_task_id}
        selected = Path(selection["backing_path"]) if selection else self.base
        if directory.exists() or name in run("virsh", "-c", "qemu:///system", "list", "--all", "--name").decode().splitlines():
            raise ValueError("attempt already exists; discover or destroy it explicitly")
        digest = selection["backing_sha256"] if selection else self.base_digest
        if not selection and await asyncio.to_thread(self.templates.immutable_sha256, selected) != digest:
            raise ValueError("Kali base image mutated")
        directory.mkdir(mode=0o711)
        os.chmod(directory, 0o711)
        secret = secrets.token_hex(32)
        cid = 4096 + int(suffix(ident), 16) % 2147480000
        overlay, iso = directory / "disk/overlay.qcow2", directory / "disk/identity.iso"
        meta = {**ident, "project": PROJECT, "base_sha256": digest,
                "overlay": str(overlay), "network": network, "cid": cid, **selection}
        state = {"identity": ident, "name": name, "network": network, "metadata": meta,
                 "secret": secret, "backend": "vsock", "base": str(selected)}
        try:
            # Large quota reservation/formatting must not freeze the HTTP event loop.
            await asyncio.to_thread(self._mount, directory)
            await asyncio.to_thread(run, "qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(selected), str(overlay))
            os.chown(overlay, self.qemu_uid, -1)
            os.chmod(overlay, 0o600)
            if network is not None:
                await asyncio.to_thread(self._create_network, ident, network, directory)
            (directory / "identity.json").write_text(json.dumps({**ident, "secret": secret,
                "limits": {"max_terminals": self.max_terminals, "max_output_bytes": self.max_output_bytes,
                           "max_transfer_bytes": self.max_transfer_bytes, "max_seed_bytes": self.max_seed_bytes}}))
            os.chmod(directory / "identity.json", 0o600)
            await asyncio.to_thread(run, "xorriso", "-as", "mkisofs", "-quiet", "-o", str(iso), "-V", "GPTTRACE", str(directory / "identity.json"))
            os.chown(iso, self.qemu_uid, -1)
            os.chmod(iso, 0o600)
            domain_definition = directory / "domain.xml"
            domain_definition.write_bytes(domain_xml(name, network, overlay, iso, cid, self.memory_mb, self.vcpus, ident, digest, selection))
            await asyncio.to_thread(run, "virsh", "-c", "qemu:///system", "define", str(domain_definition))
            self._write_state(directory / "state.json", state)
            await asyncio.to_thread(run, "virsh", "-c", "qemu:///system", "start", name)
            # One real, monotonic deadline; individual VSOCK probes are bounded.
            loop = asyncio.get_running_loop()
            deadline = loop.time() + self.boot_timeout_seconds
            while loop.time() < deadline:
                try:
                    remaining = deadline - loop.time()
                    reply = await asyncio.wait_for(self.rpc(ident, "health", {}), timeout=min(6.0, remaining))
                    if reply.get("identity") == ident:
                        return await self.inspect_verified(ident)
                except (OSError, TimeoutError, ValueError):
                    pass
                await asyncio.sleep(min(1.0, max(0.0, deadline - loop.time())))
            raise TimeoutError("guest agent did not become ready within configured boot timeout")
        except BaseException:
            if template_id is None:
                await asyncio.to_thread(self.destroy, ident, strict=False)
            # Templated/evaluator failures remain until an explicit operator action.
            raise

    @staticmethod
    def _write_state(path, data):
        temporary = path.with_suffix(".tmp")
        with temporary.open("w") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(data, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)

    def _create_network(self, ident, network, directory):
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
        owner = ET.Element("metadata")
        ET.SubElement(owner, f"{{{META_NS}}}attempt").text = json.dumps({"project": PROJECT, "identity": ident}, sort_keys=True)
        net = (f"<network><name>{network}</name>" + ET.tostring(owner, encoding="unicode") + "<forward mode='nat'/>"
               f"<bridge name='{bridge}' stp='off' delay='0'/>"
               f"<ip address='{subnet}.1' netmask='255.255.255.0'>"
               f"<dhcp><range start='{subnet}.10' end='{subnet}.200'/></dhcp></ip></network>").encode()
        network_definition = directory / "network.xml"
        network_definition.write_bytes(net)
        run("virsh", "-c", "qemu:///system", "net-define", str(network_definition))
        run("virsh", "-c", "qemu:///system", "net-start", network)
        self._firewall(ident, bridge, f"{subnet}.1")

    def inspect(self, ident: dict) -> dict:
        data = self._read(ident)
        state = run("virsh", "-c", "qemu:///system", "domstate", data["name"]).decode().strip()
        if state != "running":
            raise ValueError(f"attempt domain is {state}")
        return {"identity": ident, "domain": data["name"], "network": data["network"],
                "base_sha256": data["metadata"]["base_sha256"], "overlay": data["metadata"]["overlay"],
                "cid": data["metadata"]["cid"], "provider": "libvirt",
                **{key: data["metadata"].get(key) for key in
                   ("template_id", "backing_path", "backing_sha256", "template_generation",
                    "template_source_fingerprint", "logical_task_id")}}

    async def inspect_verified(self, ident: dict) -> dict:
        result = await asyncio.to_thread(self.inspect, ident)
        health = await self.rpc(ident, "health", {})
        if health.get("identity") != ident or health.get("guest_agent_version") != "3.0.0":
            raise ValueError("guest agent identity/version mismatch")
        return {**result, "guest_agent_version": health["guest_agent_version"]}

    def _evaluator_index(self, teacher):
        if teacher.get("purpose") is not None:
            raise ValueError("an evaluator cannot own another evaluator")
        path = self._paths(teacher)[2] / "evaluators.json"
        if not path.exists():
            return path, []
        if path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
            raise ValueError("untrusted evaluator recovery index")
        rows = json.loads(path.read_text())
        if not isinstance(rows, list):
            raise ValueError("invalid evaluator recovery index")
        for row in rows:
            ident = identity(row)
            if ident.get("purpose") != "evaluator" or any(ident[key] != teacher[key] for key in teacher):
                raise ValueError("evaluator does not belong to this teacher attempt")
        return path, rows

    async def create_evaluator(self, teacher, *, abandon_stale=False):
        data = await asyncio.to_thread(self._read, teacher)
        selection = await asyncio.to_thread(self.templates.verify_record, data["metadata"])
        path, previous = self._evaluator_index(teacher)
        if previous:
            if not abandon_stale:
                raise ValueError("stale evaluator preserved; explicit candidate-checkpoint resume is required")
            self.abandon_evaluators(teacher)
        evaluator = {**teacher, "purpose": "evaluator", "evaluator_retry": uuid.uuid4().hex}
        # Write before allocating even the quota filesystem: crashes at any
        # creation point remain associated with the exact teacher attempt.
        self._write_state(path, [evaluator])
        return await self.create(evaluator, selection["template_id"], data["metadata"]["logical_task_id"], _selection=selection)

    def evaluator_identity(self, teacher, retry):
        _, rows = self._evaluator_index(teacher)
        matches = [row for row in rows if row["evaluator_retry"] == retry]
        if len(matches) != 1:
            raise ValueError("unknown evaluator retry for this teacher attempt")
        ident = identity(matches[0])
        evaluated = self._read(ident)
        teacher_data = self._read(teacher)
        for field in ("template_id", "template_generation", "backing_path", "backing_sha256", "logical_task_id"):
            if evaluated["metadata"].get(field) != teacher_data["metadata"].get(field):
                raise ValueError("evaluator backing/source differs from recorded teacher generation")
        return ident

    def inspect_evaluators(self, teacher):
        _, rows = self._evaluator_index(teacher)
        result = []
        for ident in rows:
            directory = self._paths(ident)[2]
            state = directory / "state.json"
            record = {"identity": ident, "state_directory": str(directory), "overlay": str(directory / "disk/overlay.qcow2")}
            if state.is_file() and not state.is_symlink():
                data = json.loads(state.read_text())
                record.update({key: data["metadata"].get(key) for key in
                               ("template_id", "template_generation", "backing_sha256", "logical_task_id")})
            result.append(record)
        return {"evaluators": result}

    def destroy_evaluator(self, teacher, retry):
        ident = self.evaluator_identity(teacher, retry)
        self.destroy(ident)
        path, rows = self._evaluator_index(teacher)
        self._write_state(path, [row for row in rows if row != ident])
        return {"destroyed": True}

    def abandon_evaluators(self, teacher):
        path, rows = self._evaluator_index(teacher)
        for ident in rows:
            # Explicit recovery also handles partial construction/stopped guests.
            self.destroy(identity(ident), strict=False)
        if path.parent.exists():
            self._write_state(path, [])
        return {"abandoned": len(rows)}

    async def materialize_template_artifact(self, ident, artifact_id):
        data = self._read(ident)
        row = self.templates.artifact(data["metadata"], artifact_id)
        path = "/var/lib/gpt-trace-template-artifacts/" + artifact_id + "/payload"
        health = await self.rpc(ident, "health", {})
        if health.get("trusted_artifacts_version") != 1:
            raise ValueError("golden guest lacks trusted template streaming; rebuild/install the golden")
        await self.rpc(ident, "template_import_begin", {"path": path, "sha256": row["sha256"],
                                                        "size": row["size"], "overwrite": True})
        digest, size = hashlib.sha256(), 0
        try:
            # The runner never reads these bytes. Every frame is <= 1 MiB.
            fd = os.open(row["host_path"], os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                before = os.fstat(stream.fileno())
                if before.st_size != row["size"] or before.st_uid != 0 or before.st_mode & 0o222:
                    raise ValueError("template artifact changed before streaming")
                while chunk := stream.read(1048576):
                    size += len(chunk)
                    digest.update(chunk)
                    await self.rpc(ident, "template_import_chunk", {"content_base64": base64.b64encode(chunk).decode()})
                after = os.fstat(stream.fileno())
            stat_key = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_mtime_ns, info.st_ctime_ns)
            if size != row["size"] or digest.hexdigest() != row["sha256"] or stat_key(before) != stat_key(after):
                raise ValueError("template artifact changed while streaming")
            proof = await self.rpc(ident, "template_import_end", {"size": size})
            if proof != {"path": path, "sha256": row["sha256"], "size": size}:
                raise ValueError("guest template artifact integrity mismatch")
            return {**proof, "artifact_id": artifact_id, "kind": row["kind"],
                    "logical_task_id": row["logical_task_id"], "source_identity": row["source_identity"]}
        except BaseException:
            await self.rpc(ident, "template_import_abort", {})
            raise

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
            xml = ET.fromstring(run("virsh", "-c", "qemu:///system", "dumpxml", name))
            owner = xml.find(f"./metadata/{{{META_NS}}}attempt")
            recorded = json.loads(owner.text or "null") if owner is not None else None
            if not isinstance(recorded, dict) or recorded.get("project") != PROJECT:
                raise ValueError("refusing destruction of an unowned domain")
            recorded_identity = identity(recorded)
            if "gpt-trace-ws-" + suffix(recorded_identity) != name:
                raise ValueError("domain metadata/name ownership mismatch")
            if recorded_identity != ident:
                raise ValueError("domain attempt identity mismatch before destruction")
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
        if directory.exists():
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
            xml = ET.fromstring(run("virsh", "-c", "qemu:///system", "dumpxml", name))
            owner = xml.find(f"./metadata/{{{META_NS}}}attempt")
            recorded = json.loads(owner.text or "null") if owner is not None else None
            if not isinstance(recorded, dict) or recorded.get("project") != PROJECT:
                raise ValueError("refusing destruction of an unowned domain")
            recorded_identity = identity(recorded)
            if "gpt-trace-ws-" + suffix(recorded_identity) != name:
                raise ValueError("domain metadata/name ownership mismatch")
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
        inventory(self)  # Audit ownership before the first mutation.
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
        if not inventory(self)["absent"]:
            raise ValueError("authenticated cleanup audit still finds project resources")
        return {"removed": removed, "orphaned": sorted(set(orphaned))}

    async def rpc(self, ident: dict, method: str, args: dict) -> dict:
        data = await asyncio.to_thread(self._read, ident)
        if not isinstance(method, str) or not re.fullmatch(r"[a-z_]{1,40}", method):
            raise ValueError("invalid guest RPC method")
        body = json.dumps({"identity": ident, "secret": data["secret"], "method": method, "args": args}).encode()
        if len(body) > MAX_BODY:
            raise ValueError("guest RPC too large")
        def exchange() -> dict:
            with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as connection:
                # Probing health never needs a 30-minute RPC timeout.
                is_probe = method == "health"
                connection.settimeout(min(5.0, self.guest_agent_timeout_seconds) if is_probe else self.guest_agent_timeout_seconds)
                connection.connect((data["metadata"]["cid"], PORT))
                connection.settimeout(5.0 if is_probe else 1850)
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


def inventory(broker) -> dict:
    """Read-only ownership audit. It includes partial allocation and stopped guests."""
    domains, networks, tables, states = [], [], [], []
    known_keys = set()
    for directory in broker.root.iterdir():
        if directory.is_symlink() or not directory.is_dir() or not re.fullmatch(r"[0-9a-f]{20}", directory.name):
            raise ValueError("untrusted broker state entry")
        known_keys.add(directory.name)
        state = directory / "state.json"
        if state.exists():
            if state.is_symlink(): raise ValueError("untrusted broker state file")
            value = json.loads(state.read_text())
            ident = identity(value["identity"])
            if suffix(ident) != directory.name or value.get("metadata", {}).get("project") != PROJECT:
                raise ValueError("broker state ownership mismatch")
            states.append({"key": directory.name, "identity": ident})
        else:
            states.append({"key": directory.name, "partial": True})
    for name in run("virsh", "-c", "qemu:///system", "list", "--all", "--name").decode().splitlines():
        if not name.startswith("gpt-trace-ws-"): continue
        xml = ET.fromstring(run("virsh", "-c", "qemu:///system", "dumpxml", name))
        owner = xml.find(f"./metadata/{{{META_NS}}}attempt")
        value = json.loads(owner.text or "null") if owner is not None else None
        if not isinstance(value, dict) or value.get("project") != PROJECT:
            raise ValueError("project-prefixed domain lacks verified project ownership")
        ident = identity(value)
        key = suffix(ident)
        if name != "gpt-trace-ws-" + key: raise ValueError("domain name/identity mismatch")
        known_keys.add(key)
        domains.append({"name": name, "identity": ident})
    for name in run("virsh", "-c", "qemu:///system", "net-list", "--all", "--name").decode().splitlines():
        if not name.startswith("gpt-trace-net-"): continue
        xml = ET.fromstring(run("virsh", "-c", "qemu:///system", "net-dumpxml", name))
        owner = xml.find(f"./metadata/{{{META_NS}}}attempt")
        key = name.removeprefix("gpt-trace-net-")
        if owner is not None:
            value = json.loads(owner.text or "null")
            if value.get("project") != PROJECT or suffix(identity(value["identity"])) != key:
                raise ValueError("network project ownership mismatch")
            known_keys.add(key)
        elif key not in known_keys:
            raise ValueError("legacy orphan network lacks ownership evidence; preserve it")
        networks.append(name)
    for line in run("nft", "list", "tables").decode().splitlines():
        match = re.fullmatch(r"table inet gt_([0-9a-f]{20})", line.strip())
        if match:
            if match[1] not in known_keys: raise ValueError("orphan firewall lacks ownership evidence; preserve it")
            tables.append(line.strip())
    manager = getattr(broker, "preparations", None)
    preparations = manager.inventory() if manager is not None else []
    return {"project": PROJECT, "preparations": preparations, "domains": domains, "networks": networks, "firewall_tables": tables,
            "states": states, "absent": not (domains or networks or tables or states or preparations)}


def create_app(broker: Broker) -> Starlette:
    controller_actions = CONTROLLER_ACTIONS
    # Serializing native actions makes the shutdown barrier wait for every
    # in-flight transfer/create/input operation before absence can be proved.
    operation_lock = asyncio.Lock()
    """Cloudflare-safe async broker operation admission"""
    # Results remain available to repeated authenticated polls for this broker
    # process lifetime; a restarted process will refuse to infer any VM outcome.
    operations: dict[tuple[str, str], dict] = {}

    async def execute_background(record: dict, operation: str, ident: dict, payload: dict) -> None:
        try:
            async with operation_lock:
                if getattr(broker, "draining", False):
                    raise RuntimeError("broker draining; async creation rejected")
                if operation == "create_attempt":
                    result = await broker.create(ident, payload.get("template_id"), payload.get("logical_task_id"))
                else:
                    result = await broker.create_evaluator(ident, abandon_stale=payload.get("abandon_stale", False))
            record["result"] = result
            record["state"] = "complete"
        except asyncio.CancelledError:
            record["state"] = "unknown"
            raise
        except Exception as exc:
            logging.getLogger(__name__).exception("broker background %s failed", operation)
            record["error"] = f"{type(exc).__name__}: {str(exc)[:600]}"
            record["state"] = "failed"

    async def health(request: Request):
        authorization = request.headers.get("authorization", "")
        if not (hmac.compare_digest(authorization, f"Bearer {broker.admin_token}") or
                hmac.compare_digest(authorization, f"Bearer {broker.controller_token}")):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
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
            # Status is deliberately lock-free. Long VM preparation is serialized
            # by operation_lock, but may outlive Cloudflare's request deadline.
            if action == "poll_async":
                ident = identity(payload)
                operation = payload.get("operation")
                if operation not in {"create_attempt", "create_evaluator"}:
                    raise ValueError("invalid asynchronous operation")
                operation_id = payload.get("operation_id")
                if not isinstance(operation_id, str) or re.fullmatch(r"[0-9a-f]{32}", operation_id) is None:
                    raise ValueError("invalid asynchronous operation ID")
                record = operations.get((operation, operation_id))
                if record is None:
                    return JSONResponse({"state": "unknown", "identity": ident, "operation": operation})
                if record["identity"] != ident:
                    raise ValueError("asynchronous operation identity mismatch")
                response = {"state": record["state"], "identity": ident, "operation": operation}
                if record["state"] == "complete":
                    response["result"] = record["result"]
                if record["state"] == "failed":
                    response["detail"] = record["error"]
                return JSONResponse(response)
            if action == "begin_async":
                if getattr(broker, "draining", False):
                    raise RuntimeError("broker is draining; creation blocked")
                ident = identity(payload)
                operation = payload.get("operation")
                if operation not in {"create_attempt", "create_evaluator"} or payload.get("purpose") is not None:
                    raise ValueError("invalid asynchronous operation or identity")
                operation_id = payload.get("operation_id")
                if not isinstance(operation_id, str) or re.fullmatch(r"[0-9a-f]{32}", operation_id) is None:
                    raise ValueError("invalid asynchronous operation ID")
                allowed = {"operation", "operation_id", "task_id", "attempt", "environment_id", "fingerprint"}
                if operation == "create_attempt":
                    allowed |= {"template_id", "logical_task_id"}
                else:
                    allowed |= {"abandon_stale"}
                    if type(payload.get("abandon_stale", False)) is not bool:
                        raise ValueError("invalid evaluator recovery flag")
                if set(payload) - allowed:
                    raise ValueError("unknown asynchronous creation argument")
                key = (operation, operation_id)
                previous = operations.get(key)
                if previous is not None:
                    if previous["payload"] != payload:
                        raise ValueError("attempt creation parameters changed; preserve existing operation")
                    return JSONResponse({"state": "accepted", "identity": ident, "operation": operation})
                if len(operations) >= 10000:
                    raise RuntimeError("broker operation registry capacity reached; preserve history")
                if any(op == operation and item["identity"] == ident and item["state"] == "pending"
                       for (op, _), item in operations.items()):
                    raise ValueError("creation already in progress for this identity; reconcile before retry")
                # In particular, never retry blindly after a broker restart.
                if operation == "create_attempt" and broker._paths(ident)[2].exists():
                    raise ValueError("attempt resources already exist; reconcile existing VM explicitly")
                record = {"state": "pending", "payload": dict(payload), "identity": ident}
                operations[key] = record
                record["task"] = asyncio.create_task(execute_background(record, operation, ident, payload))
                return JSONResponse({"state": "accepted", "identity": ident, "operation": operation})
            async with operation_lock:
                if action == "begin_shutdown":
                    if payload: raise ValueError("shutdown barrier takes no parameters")
                    marker = getattr(broker, "drain_file", None)
                    if marker is not None:
                        from workstation_broker.admission import mark_draining
                        mark_draining(marker)
                    broker.draining = True
                    manager = getattr(broker, "preparations", None)
                    if manager is not None: await asyncio.to_thread(manager.cancel_all)
                    return JSONResponse({"draining": True, "project": PROJECT})
                if getattr(broker, "draining", False) and action not in {
                        "probe", "inventory", "deployment_probe", "destroy_all", "destroy_attempt",
                        "abandon_attempt", "assert_absent", "shutdown", "shutdown_status", "template_preparation_status",
                        "throw_template_storage"}:
                    raise RuntimeError("broker is draining for global shutdown; attempt mutations are blocked")
                if action == "shutdown":
                    proof = inventory(broker)
                    callback = getattr(broker, "shutdown_callback", None)
                    if not proof["absent"] or not getattr(broker, "draining", False) or callback is None:
                        raise RuntimeError("broker shutdown requires drained, absent project resources")
                    from workstation_broker.shutdown_observer import request_observation
                    acknowledgement = await asyncio.to_thread(request_observation, broker, payload, proof)
                    from starlette.background import BackgroundTask
                    async def stop_server():
                        await asyncio.sleep(0.5)
                        callback()
                    return JSONResponse(acknowledgement, background=BackgroundTask(stop_server))
                if action == "shutdown_status":
                    from workstation_broker.shutdown_observer import pending_status
                    return JSONResponse(pending_status(payload))
                if action in {"template_preparation_probe", "prepare_templates", "template_preparation_status", "throw_template_storage"}:
                    manager = getattr(broker, "preparations", None)
                    if manager is None: raise RuntimeError("native administrative preparation manager is unavailable")
                    if action == "throw_template_storage":
                        if not getattr(broker, "draining", False):
                            raise RuntimeError("persistent template deletion requires an established shutdown barrier")
                        proof = inventory(broker)
                        if proof.get("absent") is not True:
                            raise RuntimeError("temporary execution resources remain; refusing persistent THROW")
                        return JSONResponse(await asyncio.to_thread(manager.throw_persistent_storage, payload))
                    handler = {"template_preparation_probe": manager.probe,
                        "prepare_templates": manager.start, "template_preparation_status": manager.status}[action]
                    return JSONResponse(await asyncio.to_thread(handler, payload))
                if action == "probe": return JSONResponse({"status": "ok", "project": PROJECT})
                if action == "inventory": return JSONResponse(inventory(broker))
                if action == "deployment_probe":
                    configured = tomllib.loads(Path(os.environ["WORKSTATION_CONFIG"]).read_text())["workstation"]
                    return JSONResponse({"status": "ok", "project": PROJECT,
                        "execution_id": os.environ["WORKSTATION_BROKER_EXECUTION_ID"],
                        "workstation_sha256": hashlib.sha256(json.dumps(configured, sort_keys=True, separators=(",", ":")).encode()).hexdigest()})
                if action == "destroy_all": return JSONResponse(broker.destroy_all())
                if action == "preflight_templates":
                    return JSONResponse(broker.preflight_templates(payload.get("template_ids")))
                ident = identity(payload)
                if controller and not admin and (ident.get("purpose") == "evaluator" or
                        (action == "rpc" and str(payload.get("method", "")).startswith("template_import_"))):
                    return JSONResponse({"detail": "trusted runtime operation forbidden for controller token"}, status_code=403)
                if action == "create_attempt":
                    if ident.get("purpose") is not None:
                        raise ValueError("isolated runtimes require create_evaluator")
                    result = await broker.create(ident, payload.get("template_id"), payload.get("logical_task_id"))
                elif action == "create_evaluator":
                    if type(payload.get("abandon_stale", False)) is not bool:
                        raise ValueError("invalid evaluator recovery flag")
                    result = await broker.create_evaluator(ident, abandon_stale=payload.get("abandon_stale", False))
                elif action == "inspect_evaluators": result = broker.inspect_evaluators(ident)
                elif action == "destroy_evaluator": result = broker.destroy_evaluator(ident, payload.get("evaluator_retry"))
                elif action == "abandon_evaluators": result = broker.abandon_evaluators(ident)
                elif action == "materialize_template_artifact":
                    result = await broker.materialize_template_artifact(ident, payload.get("artifact_id"))
                elif action.startswith("evaluator_"):
                    evaluator = broker.evaluator_identity(ident, payload.get("evaluator_retry"))
                    operation = action.removeprefix("evaluator_")
                    args = payload.get("args", {})
                    if operation == "rpc": result = await broker.rpc(evaluator, payload.get("method"), args)
                    elif operation == "materialize_template_artifact": result = await broker.materialize_template_artifact(evaluator, payload.get("artifact_id"))
                    elif operation == "artifact_export": result = await broker.export_artifact(evaluator, args)
                    elif operation == "artifact_read": result = broker.artifact_chunk(evaluator, args)
                    elif operation == "artifact_stage_begin": result = broker.stage_begin(evaluator)
                    elif operation == "artifact_stage_chunk": result = broker.stage_chunk(evaluator, args)
                    elif operation == "artifact_stage_end": result = broker.stage_end(evaluator, args)
                    elif operation == "artifact_stage_abort": result = broker.stage_abort(evaluator, args)
                    elif operation == "artifact_import": result = await broker.import_artifact(evaluator, args)
                    else: raise ValueError("unknown evaluator operation")
                elif action == "reconcile_attempt":
                    try:
                        broker.assert_absent(ident)
                    except ValueError:
                        result = {"state": "present", "identity": ident, "runtime": await broker.inspect_verified(ident)}
                    else:
                        result = {"state": "absent", "identity": ident}
                elif action == "inspect_attempt": result = await broker.inspect_verified(ident)
                elif action == "destroy_attempt":
                    broker.destroy(ident); result = {"destroyed": True}
                elif action == "abandon_attempt":
                    broker.destroy(ident, strict=False); result = {"destroyed": True}
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
    from gpt_trace_transport.wire import token_value
    admin_token = token_value(os.environ["WORKSTATION_BROKER_ADMIN_TOKEN"])
    controller_token = token_value(os.environ["WORKSTATION_BROKER_CONTROLLER_TOKEN"])
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
                    egress_allow_cidrs=tuple(config["egress_allow_cidrs"]),
                    template_root=Path(os.environ["WORKSTATION_TEMPLATE_ROOT"]) if "WORKSTATION_TEMPLATE_ROOT" in os.environ else None)
    from workstation_broker.preparation import PreparationManager
    broker.preparations = PreparationManager(broker.base, broker.templates.root, broker.templates)
    from workstation_broker.admission import read_barrier, deployment
    broker.drain_file = broker.base.parent / "broker-drain.json"
    if broker.drain_file.exists():
        read_barrier(broker.drain_file, deployment())
        broker.draining = True
    uds = Path(os.environ["WORKSTATION_BROKER_SOCKET"])
    uds.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    from workstation_broker.preparation import process_identity
    from gpt_trace_transport.local_templates import atomic_json
    record_path = uds.parent / "broker-process.json"
    if record_path.exists():
        from gpt_trace_transport.local_templates import safe
        from workstation_broker.preparation import same_process
        previous = json.loads(safe(record_path).read_bytes())
        if previous.get("deployment") != deployment() or same_process(previous["broker_identity"]):
            raise RuntimeError("another native broker identity/process owns this runtime; preserve it")
    if uds.is_symlink(): raise RuntimeError("untrusted native broker socket")
    if uds.exists(): uds.unlink()
    stamp = process_identity(os.getpid())
    if stamp is None: raise RuntimeError("execution host native process identity is unavailable")
    atomic_json(record_path, {"schema": 1, "broker_identity": stamp,
        "deployment": {"control_id": os.environ["WORKSTATION_BROKER_CONTROL_ID"],
        "execution_id": os.environ["WORKSTATION_BROKER_EXECUTION_ID"]}}, 0o600)
    from gpt_trace_transport.gateway import start_from_env
    listener = start_from_env(uds)
    try:
        server = uvicorn.Server(uvicorn.Config(create_app(broker), uds=str(uds), log_level="info"))
        broker.shutdown_callback = lambda: setattr(server, "should_exit", True)
        server.run()
    finally:
        if listener is not None:
            listener.shutdown()
            listener.server_close()


if __name__ == "__main__":
    main()
