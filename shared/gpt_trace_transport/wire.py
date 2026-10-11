from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

MAX_BODY = 32 * 1024 * 1024
CONTROLLER_ACTIONS = frozenset({
    "inspect_attempt", "rpc", "capture_screen", "send_input",
    "artifact_stage_begin", "artifact_stage_chunk", "artifact_stage_end",
    "artifact_stage_abort", "artifact_export", "artifact_import", "artifact_read",
})
READ_ACTIONS = frozenset({
    "probe", "inventory", "reconcile_attempt", "inspect_attempt", "assert_absent",
    "inspect_evaluators", "preflight_templates", "artifact_read", "evaluator_artifact_read",
    "template_preparation_probe", "template_preparation_status", "shutdown_status",
})
PRIVATE = tuple(ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


class TransportFailure(RuntimeError):
    """The request has no verified outcome. This never means a VM is absent."""


class RemoteFailure(TransportFailure):
    def __init__(self, action, status, raw):
        self.status = status
        super().__init__(f"broker {action}: HTTP {status}: {raw[:1000].decode(errors='replace')}")


class IdentityFailure(TransportFailure):
    pass


def private_address(value: str) -> str:
    address = ipaddress.ip_address(value)
    if not any(address in network for network in PRIVATE):
        raise ValueError("broker LAN addresses must be explicit RFC1918 IPv4 addresses")
    return str(address)


def safe_file(path: Path, *, secret: bool = False, mounted: bool = False) -> bytes:
    path = Path(path).absolute()
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise IdentityFailure(f"symlink in credential path: {parent}")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()}:
        raise IdentityFailure(f"untrusted credential file: {path}")
    if info.st_mode & 0o022:
        raise IdentityFailure(f"group/world writable credential: {path}")
    if secret and info.st_mode & 0o077:
        # Existing Compose tokens are 0444 behind a 0700 host directory.
        # Only explicit token mounts may use that contract; private keys cannot.
        permitted = mounted and stat.S_IMODE(info.st_mode) == 0o444
        protected = any(p.stat().st_uid in {0, os.geteuid()} and
                        stat.S_IMODE(p.stat().st_mode) == 0o700 for p in path.parents if p != Path("/"))
        if not permitted or not (str(path).startswith("/run/secrets/") or protected):
            raise IdentityFailure(f"secret must be 0600 or protected token mount: {path}")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        current = os.fstat(fd)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino) or current.st_size > 1048576:
            raise IdentityFailure("credential changed during inspection or exceeds size limit")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            return stream.read(1048577)
    finally:
        os.close(fd)


def certificate_sha(path: Path) -> str:
    try:
        der = ssl.PEM_cert_to_DER_cert(safe_file(path).decode("ascii"))
    except (ValueError, UnicodeError) as exc:
        raise IdentityFailure("invalid single PEM certificate") from exc
    return hashlib.sha256(der).hexdigest()


def token(path: Path, *, strict: bool = True) -> str:
    value = (safe_file(path, secret=True, mounted=True) if strict else path.read_bytes()).decode("ascii").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,512}", value):
        raise IdentityFailure("invalid broker token")
    return value


@dataclass(frozen=True)
class Endpoint:
    mode: str
    socket_path: Path
    url: str = ""
    address: str = ""
    ca: Path | None = None
    cert: Path | None = None
    key: Path | None = None
    server_sha256: str = ""
    access_client_id_file: Path | None = None
    access_client_secret_file: Path | None = None
    connect_timeout: float = 10.0
    operation_timeout: float = 1900.0

    @classmethod
    def from_env(cls, socket_path: Path) -> "Endpoint":
        mode = os.environ.get("WORKSTATION_BROKER_TRANSPORT", "unix")
        if mode == "unix":
            if any(os.environ.get(key) for key in (
                "WORKSTATION_BROKER_URL", "WORKSTATION_BROKER_ADDRESS", "WORKSTATION_BROKER_CA_FILE",
                "WORKSTATION_BROKER_CERT_FILE", "WORKSTATION_BROKER_KEY_FILE", "WORKSTATION_BROKER_SERVER_SHA256")):
                raise IdentityFailure("network credentials supplied with unix transport")
            return cls(mode, socket_path)
        if mode == "access":
            required = {name: os.environ[name] for name in (
                "WORKSTATION_BROKER_URL", "WORKSTATION_BROKER_ACCESS_CLIENT_ID_FILE",
                "WORKSTATION_BROKER_ACCESS_CLIENT_SECRET_FILE")}
            return cls(mode, socket_path, required['WORKSTATION_BROKER_URL'],
                access_client_id_file=Path(required['WORKSTATION_BROKER_ACCESS_CLIENT_ID_FILE']),
                access_client_secret_file=Path(required['WORKSTATION_BROKER_ACCESS_CLIENT_SECRET_FILE']))
        if mode != "mtls":
            raise IdentityFailure("WORKSTATION_BROKER_TRANSPORT must be unix, mtls or access")
        required = {key: os.environ[key] for key in (
            "WORKSTATION_BROKER_URL", "WORKSTATION_BROKER_ADDRESS", "WORKSTATION_BROKER_CA_FILE",
            "WORKSTATION_BROKER_CERT_FILE", "WORKSTATION_BROKER_KEY_FILE", "WORKSTATION_BROKER_SERVER_SHA256")}
        return cls(mode, socket_path, required["WORKSTATION_BROKER_URL"],
                   private_address(required["WORKSTATION_BROKER_ADDRESS"]),
                   Path(required["WORKSTATION_BROKER_CA_FILE"]), Path(required["WORKSTATION_BROKER_CERT_FILE"]),
                   Path(required["WORKSTATION_BROKER_KEY_FILE"]), required["WORKSTATION_BROKER_SERVER_SHA256"])

    def access_headers(self) -> dict[str, str]:
        if self.mode != 'access' or self.access_client_id_file is None or self.access_client_secret_file is None:
            raise IdentityFailure('missing Cloudflare Access credentials')
        result = {}
        for header, path in (('CF-Access-Client-Id', self.access_client_id_file),
                             ('CF-Access-Client-Secret', self.access_client_secret_file)):
            value = safe_file(path, secret=True, mounted=True).decode('ascii').strip()
            if not 10 <= len(value) <= 512 or not re.fullmatch(r'[A-Za-z0-9._-]+', value):
                raise IdentityFailure('invalid Cloudflare Access service token field: ' + header)
            result[header] = value
        return result

    def client_context(self) -> ssl.SSLContext:
        parsed = urlsplit(self.url)
        if (self.mode not in {"mtls", "access"} or parsed.scheme != "https" or not parsed.hostname or
            parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"} or
            not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", parsed.hostname) or
            (self.mode == 'mtls' and (not parsed.port or not re.fullmatch(r"[0-9a-f]{64}", self.server_sha256))) or
            (self.mode == 'access' and (parsed.port not in (None, 443) or '.' not in parsed.hostname))):
            raise IdentityFailure("invalid explicit mTLS origin or server fingerprint")
        if self.mode == 'access':
            self.access_headers()
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_alpn_protocols(['http/1.1'])
            return context
        if self.ca is None or self.cert is None or self.key is None:
            raise IdentityFailure("missing mTLS credentials")
        safe_file(self.ca)
        safe_file(self.cert)
        safe_file(self.key, secret=True)
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(self.ca))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.hostname_checks_common_name = False
        context.load_cert_chain(str(self.cert), str(self.key))
        context.set_alpn_protocols(["http/1.1"])
        return context


def bounded_read(response: http.client.HTTPResponse, connection, maximum: int, deadline: float) -> bytes:
    declared = response.getheader("Content-Length")
    if declared is not None and (not declared.isdigit() or int(declared) > maximum):
        raise TransportFailure("invalid or oversized broker response length")
    if response.getheader("Content-Encoding", "identity") != "identity":
        raise TransportFailure("encoded broker responses are forbidden")
    pieces, total = [], 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransportFailure("broker response deadline exceeded; outcome unconfirmed")
        if connection.sock is not None:
            connection.sock.settimeout(remaining)
        piece = response.read1(min(65536, maximum + 1 - total))
        if not piece:
            break
        total += len(piece)
        if total > maximum:
            raise TransportFailure("broker response exceeds frame limit")
        pieces.append(piece)
    if declared is not None and total != int(declared):
        raise TransportFailure("truncated broker response; outcome unconfirmed")
    return b"".join(pieces)


class WireClient:
    def __init__(self, endpoint: Endpoint):
        self.endpoint = endpoint
        self.context = endpoint.client_context() if endpoint.mode in {'mtls', 'access'} else None
        if endpoint.mode not in {"unix", "mtls", "access"}:
            raise IdentityFailure("unknown broker transport")

    def exchange(self, method: str, path: str, body: bytes, authorization: str,
                 *, timeout: float | None = None) -> tuple[int, bytes]:
        if method not in {"GET", "POST"} or not re.fullmatch(r"/(healthz|v1/[a-z_]{1,64})", path):
            raise TransportFailure("invalid broker request route")
        if len(body) > MAX_BODY or "\r" in authorization or "\n" in authorization:
            raise TransportFailure("invalid broker frame")
        endpoint = self.endpoint
        duration = endpoint.operation_timeout if timeout is None else min(timeout, endpoint.operation_timeout)
        if duration <= 0:
            raise TransportFailure("invalid operation timeout")
        connection = http.client.HTTPConnection("broker", timeout=endpoint.connect_timeout)
        sock = None
        deadline = time.monotonic() + duration
        try:
            if endpoint.mode == "unix":
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(endpoint.connect_timeout)
                sock.connect(str(endpoint.socket_path))
            else:
                parsed = urlsplit(endpoint.url)
                sock = socket.create_connection(((parsed.hostname if endpoint.mode == 'access' else endpoint.address),
                                                 (443 if endpoint.mode == 'access' else parsed.port)), endpoint.connect_timeout)
                sock = self.context.wrap_socket(sock, server_hostname=parsed.hostname)
                if endpoint.mode == 'mtls':
                    digest = hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest()
                    if not hmac.compare_digest(digest, endpoint.server_sha256):
                        raise IdentityFailure("broker certificate fingerprint mismatch")
                connection.host = parsed.hostname
                connection.port = 443 if endpoint.mode == 'access' else parsed.port
            connection.sock = sock
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            headers = {"Authorization": authorization, "Content-Type": "application/json",
                "Content-Length": str(len(body)), "Connection": "close", "Accept-Encoding": "identity"}
            if endpoint.mode == 'access':
                headers.update(endpoint.access_headers())
                headers['Host'] = parsed.hostname
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, bounded_read(response, connection, MAX_BODY, deadline)
        except ssl.SSLError as exc:
            raise IdentityFailure("TLS certificate/handshake validation failed") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise TransportFailure("broker connection failed; VM outcome unconfirmed") from exc
        finally:
            connection.close()
            if sock is not None:
                sock.close()

    def check_access_policy(self):
        """Probe anonymous edge access: unauthenticated /healthz must be blocked.

        Never send broker tokens or service credentials in this request.
        This detects a missing/bypassed Access application on the tunnel hostname.
        """
        if self.endpoint.mode != 'access': return
        parsed = urlsplit(self.endpoint.url)
        connection = http.client.HTTPSConnection(parsed.hostname, 443, timeout=10,
            context=ssl.create_default_context(ssl.Purpose.SERVER_AUTH))
        try:
            connection.request('GET', '/healthz', headers={'Accept-Encoding': 'identity'})
            response = connection.getresponse()
            if response.status not in {302, 401, 403}:
                raise IdentityFailure('Cloudflare Access gate not enforced or origin unreachable: anonymous /healthz HTTP ' + str(response.status))
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            raise IdentityFailure('cannot validate Cloudflare Access security policy') from exc
        finally:
            connection.close()

    def request(self, action: str, payload: dict, credential: str, *, timeout: float | None = None) -> dict:
        status, raw = self.exchange("POST", "/v1/" + action,
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(), "Bearer " + credential, timeout=timeout)
        if status != 200:
            raise RemoteFailure(action, status, raw)
        try:
            result = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise TransportFailure("broker returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise TransportFailure("broker returned a non-object")
        return result
