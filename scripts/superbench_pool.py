#!/usr/bin/env python3
"""Host-only SWE-Gym Lite dependency acquisition. No execution of task recipes.

The downloader runs as a dedicated non-root account. The privileged broker owns
publication. Fetch resolves deterministic build/download inputs only; it never
starts a VM, invokes a task script or deletes persisted data. Native package
metadata hooks and their build dependencies run in disposable private prefixes.
"""
from __future__ import annotations
import argparse
import ast
import importlib.util
import concurrent.futures
import contextlib
import functools
import base64
import gzip
import configparser
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import stat
import tempfile
import threading
import subprocess
import sys
import time
import tomllib
import urllib.parse
import urllib.request
import http.client
import ssl
import urllib.error
from collections import defaultdict
from pathlib import Path

def _load_locked_python_minors():
    """Derive supported target minors from the committed Conda lock."""
    lock_path = Path(__file__).resolve().parents[1] / 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/conda-lock.json'
    try:
        payload = json.loads(lock_path.read_bytes())
        rows = payload.get('artifacts', {}).values()
        minors = sorted({'.'.join(str(row['version']).split('.')[:2]) for row in rows
                         if row.get('name') == 'python' and re.fullmatch(r'\d+\.\d+\.\d+', str(row.get('version', '')))})
    except (OSError, ValueError, KeyError, TypeError):
        minors = []
    if not minors:
        raise RuntimeError('the pinned Conda lock does not define target Python identities')
    return tuple(minors)


PYTHONS = _load_locked_python_minors()
REPO = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z')
COMMIT = re.compile(r'[a-f0-9]{40}\Z')
SHA = re.compile(r'[a-f0-9]{64}\Z')
KALI_SIGNING_FPR = '827C8569F2518CC677FECA1AED65462EC8D5E4C5'
MAX_SOURCE = 12 * 1024 * 1024
MAX_VCS_CLOSURE = 256
def _golden_dependency():
    path = Path(__file__).resolve().parents[1] / 'golden-dependency.json'
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('sealed Kali dependency identity is required for target dependency resolution')
    try:
        value = json.loads(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise RuntimeError('sealed Kali dependency identity is invalid') from exc
    target = value.get('target_environment') if isinstance(value, dict) else None
    if (not isinstance(value, dict)
            or set(value) != {'schema', 'target_environment', 'npm_version', 'apt_package_manifest_sha256'}
            or not isinstance(value.get('apt_package_manifest_sha256'), str)
            or SHA.fullmatch(value['apt_package_manifest_sha256']) is None
            or value.get('schema') != 1 or not isinstance(target, dict)):
        raise RuntimeError('sealed Kali dependency identity is invalid')
    return value


def _golden_system_python():
    target = _golden_dependency()['target_environment']
    markers = target.get('markers') if isinstance(target, dict) else None
    value = markers.get('python_full_version') if isinstance(markers, dict) else None
    if not isinstance(value, str) or not re.fullmatch(r'\d+\.\d+\.\d+', value):
        raise RuntimeError('verified Kali dependency identity lacks the full system Python identity')
    return value


def _pinned_npm_version():
    value = _golden_dependency().get('npm_version')
    if not isinstance(value, str) or not re.fullmatch(r'v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?', value):
        raise RuntimeError('verified Kali dependency identity lacks the pinned npm tool identity')
    return value
DOWNLOAD_ATTEMPTS = 5
DOWNLOAD_RETRY_HTTP = frozenset({408, 425, 429, 500, 502, 503, 504})
DOWNLOAD_RETRY_BACKOFF = (1, 2, 4, 8)
# GPT_TRACE_SWEGYM_GLOBAL_ARTIFACT_POOL_V1
PIP_ARTIFACT_MODEL = 'global-content-addressed-pip-v2-target-provenance'


def digest(path):
    path = Path(path)
    before = path.lstat()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError('unsafe or changed SHA-256 input')
        h = hashlib.sha256()
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            for chunk in iter(lambda: stream.read(1048576), b''): h.update(chunk)
        after = os.fstat(fd)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise RuntimeError('file changed during SHA-256 verification')
        return h.hexdigest()
    finally:
        os.close(fd)


# A single progress owner prevents background workers and command logs from
# competing for the same terminal. All counters describe completed, observed
# work; we intentionally do not claim a global time/work percentage.
_POOL_PROGRESS = None


class _PoolProgress:
    """Compact real-work progress for interactive and durable non-TTY logs.

    TTY output is redrawn in place. A broker-owned append-only log receives
    only stage changes, meaningful count milestones and material byte progress.
    No timer generates an unchanged log record.
    """
    def __init__(self, stream=None, *, tty=None, interval=None):
        self.stream = sys.stdout if stream is None else stream
        self.tty = self.stream.isatty() if tty is None else tty
        self.interval = _conda_progress_interval() if interval is None else interval
        self.lock = threading.RLock()
        self.stage = 'Preparation'
        self.completed = None
        self.total = None
        self.unit = ''
        self.details = ''
        self.network_bytes = 0
        self.transfers = {}
        self.pip_bytes = 0
        self.pip_active = 0
        self.pip_file = None
        self.last_time = time.monotonic()
        self.last_bytes = 0
        self.speed = 0.0
        self.last_emit = 0.0
        self.last_stage = None
        self.last_count_bucket = None
        self.last_report_bytes = 0
        self.last_output = ''

    @staticmethod
    def _count_bucket(completed, total):
        if completed is None or total is None or total == 0:
            return None
        # At most ten non-TTY records per known set, irrespective of its size.
        return min(10, completed * 10 // total)

    def _render(self):
        message = '[pool] ' + self.stage
        if self.completed is not None and self.total is not None:
            message += ' %s/%s %s' % (self.completed, self.total, self.unit)
        elif self.completed is not None:
            message += ' %s %s' % (self.completed, self.unit)
        if self.details:
            message += ' | ' + self.details
        observed = self.network_bytes + self.pip_bytes
        if observed or self.transfers or self.pip_active:
            message += ' | %.1f MiB reçus | %.2f MiB/s' % (
                observed / 1048576, self.speed / 1048576)
        if self.pip_active:
            message += ' | %s pip actifs' % self.pip_active
        known = [row for row in self.transfers.values()
                 if row['total'] > 0 and row['current'] <= row['total']]
        if self.pip_file is not None:
            key, current, total = self.pip_file
            if total > 0 and current <= total:
                known.append({'name': 'pip-' + key, 'current': current, 'total': total})
        if known:
            selected = max(known, key=lambda row: (row['total'], row['current']))
            current, total = selected['current'], selected['total']
            filled = min(16, current * 16 // total)
            message += ' | [%s%s] %.1f%% du fichier (%.1f/%.1f MiB)' % (
                '#' * filled, '-' * (16 - filled), 100 * current / total,
                current / 1048576, total / 1048576)
        return message

    def _emit(self, *, force=False, changed_stage=False):
        now = time.monotonic()
        total_bytes = self.network_bytes + self.pip_bytes
        elapsed = now - self.last_time
        if elapsed >= self.interval or force:
            self.speed = max(0, total_bytes - self.last_bytes) / max(elapsed, 1e-6)
            self.last_bytes = total_bytes
            self.last_time = now
        rendered = self._render()
        if self.tty:
            if not force and now - self.last_emit < 0.2:
                return
            self.stream.write('\r\x1b[K' + rendered)
            if force:
                self.stream.write('\n')
            self.stream.flush()
        else:
            bucket = self._count_bucket(self.completed, self.total)
            material_bytes = (total_bytes - self.last_report_bytes >= 64 * 1048576
                              and now - self.last_emit >= self.interval)
            milestone = (bucket is not None and bucket != self.last_count_bucket)
            if not (force or changed_stage or milestone or material_bytes):
                return
            if rendered != self.last_output:
                self.stream.write(rendered + '\n')
                self.stream.flush()
                self.last_output = rendered
            self.last_count_bucket = bucket
            self.last_report_bytes = total_bytes
        self.last_emit = now

    def update(self, stage, completed=None, total=None, unit='', details='', *, force=False):
        if total is not None and (type(total) is not int or total < 0):
            raise ValueError('invalid stage total')
        if completed is not None and (type(completed) is not int or completed < 0):
            raise ValueError('invalid stage progress')
        with self.lock:
            changed = stage != self.stage
            if changed and self.tty and self.last_stage is not None:
                self.stream.write('\n')
            if changed:
                self.last_count_bucket = None
            self.stage = stage
            self.completed, self.total = completed, total
            self.unit, self.details = unit, details
            self._emit(force=force, changed_stage=changed)
            self.last_stage = stage

    def network_start(self, key, label, total):
        with self.lock:
            if key in self.transfers:
                raise RuntimeError('duplicate transfer identity')
            self.transfers[key] = {'name': label, 'current': 0, 'total': total}
            self._emit()

    def network_advance(self, key, amount):
        with self.lock:
            self.transfers[key]['current'] += amount
            self.network_bytes += amount
            self._emit()

    def network_end(self, key):
        with self.lock:
            self.transfers.pop(key)
            self._emit()

    def pip_update(self, snapshot):
        with self.lock:
            self.pip_bytes = snapshot['bytes']
            self.pip_active = snapshot['jobs']
            self.pip_file = snapshot['file']
            self._emit()

    def finish(self):
        with self.lock:
            self._emit(force=True)


def _pool_progress(stage, completed=None, total=None, unit='', details='', *, force=False):
    if _POOL_PROGRESS is not None:
        _POOL_PROGRESS.update(stage, completed, total, unit, details, force=force)


def invoke(argv, *, cwd=None, capture=False, env=None, timeout=3600):
    command = [str(v) for v in argv]
    if _POOL_PROGRESS is None:
        print('[pool]', ' '.join(command), flush=True)
        try:
            result = subprocess.run(command, cwd=cwd, env=env, check=True,
                                    text=True, stdout=subprocess.PIPE if capture else None,
                                    timeout=timeout)
        except subprocess.CalledProcessError as exc:
            if capture and exc.stdout:
                output = exc.stdout[-65536:]
                print('[pool] failed command captured stdout:', file=sys.stderr, flush=True)
                sys.stderr.write(output + ('' if output.endswith('\n') else '\n'))
                sys.stderr.flush()
            raise
        return result.stdout if capture else None

    # A disk-backed command log means git/apt/npm output cannot bury
    # useful progress. On errors only, retain the diagnostic tail.
    with tempfile.TemporaryFile(mode='w+b') as log:
        try:
            result = subprocess.run(command, cwd=cwd, env=env, check=False,
                                    stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            log.seek(max(0, log.tell() - 8192))
            detail = log.read().decode(errors='replace')
            print('[pool] command timeout: ' + ' '.join(command) + '\n' + detail,
                  file=sys.stderr, flush=True)
            if capture:
                log.seek(0)
                raise subprocess.TimeoutExpired(exc.cmd,exc.timeout,output=log.read().decode(errors='replace')) from exc
            raise
        if result.returncode != 0:
            log.seek(max(0, log.tell() - 8192))
            detail = log.read().decode(errors='replace')
            print('[pool] command failed: ' + ' '.join(command) + '\n' + detail,
                  file=sys.stderr, flush=True)
            log.seek(0)
            raise subprocess.CalledProcessError(result.returncode, command,
                                                output=log.read().decode(errors='replace') if capture else None)
        if capture:
            log.seek(0)
            return log.read().decode('utf-8')
    return None


def write_new(path, data):
    """Publish complete durable bytes exclusively; an interrupted write is not a record."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data if isinstance(data, bytes) else data.encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
        _sync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def sri_parts(sri):
    if sri is None:
        return None
    if not isinstance(sri, str):
        raise RuntimeError('invalid package integrity token')
    candidates = []
    for token in sri.split():
        algorithm, sep, encoded = token.partition('-')
        if not sep or algorithm not in ('sha256', 'sha384', 'sha512'):
            raise RuntimeError('unsupported package integrity token')
        try:
            expected = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise RuntimeError('invalid package integrity base64') from exc
        if len(expected) != hashlib.new(algorithm).digest_size:
            raise RuntimeError('invalid package integrity length')
        candidates.append((algorithm, expected))
    if not candidates:
        raise RuntimeError('missing package integrity token')
    strongest = max(hashlib.new(algorithm).digest_size for algorithm, _ in candidates)
    return [part for part in candidates if hashlib.new(part[0]).digest_size == strongest]


def verify_sri(path, sri):
    candidates = sri_parts(sri)
    if candidates is None:
        return
    checks = [(hashlib.new(algorithm), expected) for algorithm, expected in candidates]
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            for h, _ in checks: h.update(block)
    matched = [part for part, (h, expected) in zip(candidates, checks) if h.digest() == expected]
    if not matched:
        raise RuntimeError('integrity mismatch for cached package')
    return tuple(matched)


def _discard_partial_download(path):
    path=Path(path)
    try: info=path.lstat()
    except FileNotFoundError: return
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise RuntimeError('unsafe partial download path: '+str(path))
    path.unlink()


class DownloadIntegrityError(RuntimeError):
    """A completed transfer did not match its pinned integrity identity."""
    pass


class MetadataDecodeError(RuntimeError):
    """A metadata transfer completed with a corrupt/truncated transport encoding."""
    pass


def _retryable_network_error(exc):
    if isinstance(exc, (DownloadIntegrityError, MetadataDecodeError)):
        # A transport can terminate cleanly after delivering truncated/corrupted
        # bytes, so urllib may expose no network exception. Retry from byte zero;
        # the artifact is still accepted only after exact integrity verification.
        return True
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in DOWNLOAD_RETRY_HTTP
    if isinstance(exc, ssl.SSLCertVerificationError):
        return False
    if isinstance(exc, (TimeoutError, ConnectionError, http.client.IncompleteRead,
                        http.client.BadStatusLine, ssl.SSLEOFError)):
        return True
    if isinstance(exc, urllib.error.URLError):
        reason=exc.reason
        if isinstance(reason, ssl.SSLCertVerificationError): return False
        return isinstance(reason, (TimeoutError, ConnectionError, OSError))
    return False


def _network_retry(label, operation, *, cleanup=None):
    for attempt in range(1, DOWNLOAD_ATTEMPTS+1):
        if cleanup is not None: cleanup()
        try:
            with _network_slots():
                return operation()
        except Exception as exc:
            if not _retryable_network_error(exc): raise
            if cleanup is not None: cleanup()
            if attempt >= DOWNLOAD_ATTEMPTS: raise
            delay=DOWNLOAD_RETRY_BACKOFF[attempt-1]
            detail=('HTTP '+str(exc.code)) if isinstance(exc, urllib.error.HTTPError) else type(exc).__name__
            print(f'[pool] network retry {attempt+1}/{DOWNLOAD_ATTEMPTS} in {delay}s after {detail}: {label}',
                  file=sys.stderr, flush=True)
            time.sleep(delay)
    raise AssertionError('unreachable network retry loop')


@functools.lru_cache(maxsize=1)
def _network_slots():
    """One HTTP budget across metadata and artifact worker pools."""
    return threading.BoundedSemaphore(_acquisition_workers())


_HTTPS_CONNECTIONS=threading.local()


def _drop_expected_https_connection(host):
    connections=getattr(_HTTPS_CONNECTIONS,'connections',None)
    if not connections:return
    connection=connections.pop(host,None)
    if connection is not None:
        try:connection.close()
        except OSError:pass


def _read_metadata_response(response, limit):
    """Read identity/gzip metadata with a hard decompressed-size bound."""
    headers=getattr(response,'headers',None)
    def header(name):
        if hasattr(response,'getheader'):
            return response.getheader(name,'') or ''
        return (headers.get(name,'') if headers is not None else '') or ''
    encoding=header('Content-Encoding').strip().lower()
    length=header('Content-Length')
    if length.isdigit() and int(length)>limit:
        raise RuntimeError('HTTPS response exceeds limit')
    if encoding in ('','identity'):
        raw=response.read(limit+1)
        if length.isdigit() and len(raw) != int(length):
            raise MetadataDecodeError('truncated HTTPS metadata response')
    elif encoding=='gzip':
        try:
            with gzip.GzipFile(fileobj=response,mode='rb') as stream:
                raw=stream.read(limit+1)
        except (OSError,EOFError) as exc:
            raise MetadataDecodeError('invalid gzip HTTPS metadata response') from exc
    else:
        raise RuntimeError('unsupported HTTPS metadata content encoding: '+encoding)
    if len(raw)>limit:raise RuntimeError('HTTPS response exceeds limit')
    return raw


def _validate_https_endpoint(url, expected_host=None):
    try:
        parsed=urllib.parse.urlsplit(url)
        port=parsed.port
    except (TypeError,ValueError) as exc:
        raise RuntimeError('invalid HTTPS endpoint') from exc
    if (parsed.scheme!='https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment or port not in (None,443)
            or any(ord(char)<33 or ord(char)==127 for char in url)
            or (expected_host is not None and parsed.hostname!=expected_host)):
        raise RuntimeError('untrusted HTTPS endpoint or redirect')
    return parsed


class _ValidatedHTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self,expected_host=None):
        self.expected_host=expected_host

    def redirect_request(self,req,fp,code,msg,headers,newurl):
        _validate_https_endpoint(newurl,self.expected_host)
        return super().redirect_request(req,fp,code,msg,headers,newurl)


def _open_https(request, *, timeout, expected_host=None):
    _validate_https_endpoint(request.full_url,expected_host)
    return urllib.request.build_opener(_ValidatedHTTPSRedirect(expected_host)).open(request,timeout=timeout)


def _read_expected_https_once(url, *, timeout, limit, user_agent, expected_host, accept=None):
    parsed=_validate_https_endpoint(url,expected_host)
    connections=getattr(_HTTPS_CONNECTIONS,'connections',None)
    if connections is None:
        connections={}
        _HTTPS_CONNECTIONS.connections=connections
    connection=connections.get(expected_host)
    if connection is None:
        connection=http.client.HTTPSConnection(expected_host,timeout=timeout)
        connections[expected_host]=connection
    elif connection.sock is not None:
        connection.sock.settimeout(timeout)
    path=urllib.parse.urlunsplit(('', '', parsed.path or '/', parsed.query, ''))
    try:
        headers={'User-Agent':user_agent,'Accept-Encoding':'gzip'}
        if accept is not None:headers['Accept']=accept
        connection.request('GET',path,headers=headers)
        response=connection.getresponse()
        if 300 <= response.status < 400:
            # Metadata endpoints are expected to be canonical. Preserve the
            # previous redirect validation path if an upstream starts redirecting.
            response.close()
            _drop_expected_https_connection(expected_host)
            headers={'User-Agent':user_agent,'Accept-Encoding':'gzip'}
            if accept is not None:headers['Accept']=accept
            request=urllib.request.Request(url,headers=headers)
            with _open_https(request,timeout=timeout,expected_host=expected_host) as redirected_response:
                redirected=urllib.parse.urlsplit(redirected_response.url)
                if redirected.scheme!='https' or redirected.hostname!=expected_host:
                    raise RuntimeError('untrusted HTTPS redirect host')
                raw=_read_metadata_response(redirected_response,limit)
        elif not 200 <= response.status < 300:
            # Status is sufficient for retry policy; never spend bandwidth/time
            # draining an error body that cannot participate in dependency identity.
            response.close()
            raise urllib.error.HTTPError(url,response.status,response.reason,response.headers,io.BytesIO(b''))
        else:
            raw=_read_metadata_response(response,limit)
    except BaseException:
        _drop_expected_https_connection(expected_host)
        raise
    return raw


def _read_https(url, *, timeout, limit, user_agent, expected_host=None, accept=None):
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise RuntimeError('untrusted HTTPS endpoint: '+str(url))
    label=(parsed.hostname or '')+parsed.path
    def read_once():
        if expected_host is not None:
            return _read_expected_https_once(
                url,timeout=timeout,limit=limit,user_agent=user_agent,expected_host=expected_host,
                accept=accept)
        headers={'User-Agent':user_agent}
        if accept is not None:headers['Accept']=accept
        request=urllib.request.Request(url, headers=headers)
        with _open_https(request, timeout=timeout) as response:
            redirected=urllib.parse.urlsplit(response.url)
            if redirected.scheme != 'https': raise RuntimeError('untrusted HTTPS redirect')
            raw=_read_metadata_response(response,limit)
        if len(raw)>limit: raise RuntimeError('HTTPS response exceeds limit')
        return raw
    return _network_retry(label, read_once)


def fetch(url, path, *, sha=None, sri=None, limit=2**37, integrity_digests=None, on_block=None):
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise RuntimeError('untrusted download endpoint: '+str(url))
    path=Path(path)
    label=(parsed.hostname or '')+parsed.path
    def transfer():
        request=urllib.request.Request(url,headers={'User-Agent':'gpt-trace-dependency-pool/2'})
        with _open_https(request,timeout=180) as response:
            if urllib.parse.urlsplit(response.url).scheme != 'https':
                raise RuntimeError('untrusted download redirect')
            if response.headers.get('Content-Length','').isdigit() and int(response.headers['Content-Length'])>limit:
                raise RuntimeError('download exceeds limit')
            h=hashlib.sha256(); size=0
            other_hashes={algorithm:hashlib.new(algorithm) for algorithm in ('sha384','sha512')} if integrity_digests is not None else {}
            checks=[(hashlib.new(algo),expected) for algo,expected in (sri_parts(sri) or ())]
            view = _POOL_PROGRESS
            transfer_key = object()
            declared = response.headers.get('Content-Length', '')
            if view is not None:
                view.network_start(transfer_key, path.name, int(declared) if declared.isdigit() else 0)
            try:
                with path.open('xb') as stream:
                    for block in iter(lambda:response.read(1048576),b''):
                        size+=len(block)
                        if size>limit: raise RuntimeError('download exceeds limit; partial retained')
                        stream.write(block); h.update(block)
                        if on_block is not None: on_block(len(block))
                        if view is not None: view.network_advance(transfer_key,len(block))
                        for other in other_hashes.values(): other.update(block)
                        for sri_hash,_ in checks: sri_hash.update(block)
                    stream.flush(); os.fsync(stream.fileno())
            finally:
                if view is not None: view.network_end(transfer_key)
        length=response.headers.get('Content-Length','')
        if length.isdigit() and size!=int(length):
            raise MetadataDecodeError('truncated HTTPS artifact response')
        actual=h.hexdigest()
        if sha and actual != sha:
            raise DownloadIntegrityError('download sha256 mismatch: '+str(path))
        if checks and not any(h.digest()==expected for h,expected in checks):
            raise DownloadIntegrityError('download integrity mismatch: '+str(path))
        if integrity_digests is not None:
            integrity_digests.update({algo:h.digest() for algo,h in other_hashes.items()})
        return actual
    return _network_retry(label, transfer, cleanup=lambda:_discard_partial_download(path))


class _StaticGitReadCache:
    """Per-fetch Git tree/blob single-flight cache, bounded by the I/O worker budget.

    Git tree lookups remain scoped to the exact pinned mirror and commit. Blob
    bytes are shared across commits within that mirror only when the Git object
    identity is identical. Failures are propagated, never replaced by a guess.
    """
    def __init__(self, workers):
        from collections import OrderedDict
        if type(workers) is not int or workers < 1:
            raise RuntimeError('invalid static metadata worker capacity')
        self.lock = threading.RLock()
        self.trees = {}
        self.blobs = OrderedDict()
        self.blob_futures = {}
        self.blob_bytes = 0
        self.max_blob_bytes = MAX_SOURCE * workers

    def _tree_oid(self, mirror, commit, path):
        key = (str(mirror), commit, path)
        with self.lock:
            pending = self.trees.get(key)
            owner = pending is None
            if owner:
                pending = concurrent.futures.Future()
                self.trees[key] = pending
        if owner:
            try:
                raw = invoke(['git', '--git-dir', mirror, 'ls-tree', commit, '--', path],
                             capture=True).strip()
                if not raw:
                    oid = None
                else:
                    matched = re.fullmatch(r'100(?:644|755) blob ([0-9a-f]{40})\t.+', raw)
                    if matched is None:
                        raise RuntimeError('dependency source is not a regular Git file: ' + path)
                    oid = matched.group(1)
            except BaseException as exc:
                with self.lock:
                    self.trees.pop(key, None)
                pending.set_exception(exc)
            else:
                pending.set_result(oid)
        return pending.result()

    def _blob(self, mirror, oid):
        key = (str(mirror), oid)
        with self.lock:
            if key in self.blobs:
                self.blobs.move_to_end(key)
                return self.blobs[key]
            pending = self.blob_futures.get(key)
            owner = pending is None
            if owner:
                pending = concurrent.futures.Future()
                self.blob_futures[key] = pending
        if owner:
            try:
                raw = subprocess.check_output(
                    ['git', '--git-dir', str(mirror), 'cat-file', 'blob', oid], timeout=60)
                if len(raw) > MAX_SOURCE:
                    raise RuntimeError('source metadata too large for Git object: ' + oid)
                content = raw.decode('utf-8')
            except BaseException as exc:
                with self.lock:
                    self.blob_futures.pop(key, None)
                pending.set_exception(exc)
            else:
                with self.lock:
                    self.blob_futures.pop(key, None)
                    size = len(raw)
                    if size <= self.max_blob_bytes:
                        while self.blobs and self.blob_bytes + size > self.max_blob_bytes:
                            _removed, old = self.blobs.popitem(last=False)
                            self.blob_bytes -= len(old.encode('utf-8'))
                        self.blobs[key] = content
                        self.blob_bytes += size
                pending.set_result(content)
        return pending.result()

    def read(self, mirror, commit, path, *, required=False):
        path = path.removeprefix('./')
        if not path or path.startswith('/') or '\\' in path or '\x00' in path or '..' in Path(path).parts:
            raise ValueError('unsafe Git dependency file: ' + path)
        oid = self._tree_oid(mirror, commit, path)
        if oid is None:
            if required:
                raise RuntimeError('missing source input ' + path + ' @ ' + commit)
            return None
        return self._blob(mirror, oid)


def _merge_static_task_result(result, task_plan, groups, apt_requested, apt_upgrade_tasks,
                              vcs, issues):
    """Preserve the old sorted-task aggregation order, without shared worker writes."""
    logical, plan, own_groups, own_apt, own_upgrades, own_vcs, own_issues = result
    if logical in task_plan:
        raise RuntimeError('duplicate static analysis task identity: ' + logical)
    task_plan[logical] = plan
    for key, group in own_groups.items():
        previous = groups.get(key)
        if previous is None:
            groups[key] = group
            continue
        if (previous['target'] != group['target']
                or previous['requirements'] != group['requirements']
                or previous['constraints'] != group['constraints']
                or previous['preferred_versions'] != group['preferred_versions']
                or previous['no_deps'] is not group['no_deps']):
            raise RuntimeError('inconsistent static pip closure identity: ' + key)
        previous['required'] = previous['required'] or group['required']
        for task in group['tasks']:
            if task not in previous['tasks']:
                previous['tasks'].append(task)
        previous['steps'].extend(group['steps'])
    apt_requested.update(own_apt)
    apt_upgrade_tasks.update(own_upgrades)
    vcs.update(own_vcs)
    issues.extend(own_issues)


def git_file(mirror, commit, path, *, required=False):
    path=path.removeprefix('./')
    if not path or path.startswith('/') or '\\' in path or '\x00' in path or '..' in Path(path).parts:
        raise ValueError('unsafe Git dependency file: '+path)
    raw=invoke(['git','--git-dir',mirror,'ls-tree',commit,'--',path],capture=True).strip()
    if not raw:
        if required: raise RuntimeError('missing source input '+path+' @ '+commit)
        return None
    if not re.fullmatch(r'100(?:644|755) blob [0-9a-f]{40}\t.+',raw):
        raise RuntimeError('dependency source is not a regular Git file: '+path)
    result=subprocess.check_output(['git','--git-dir',str(mirror),'show',commit+':'+path],timeout=60)
    if len(result)>MAX_SOURCE: raise RuntimeError('source metadata too large: '+path)
    return result.decode('utf-8')



def git_files_named(mirror, commit, basename, *, limit=64):
    """List pinned regular Git files by basename without repository-specific paths."""
    if (not isinstance(basename,str) or not basename or '/' in basename or '\\' in basename
            or basename in {'.','..'} or type(limit) is not int or limit<1):
        raise ValueError('invalid Git basename search')
    raw=invoke(['git','--git-dir',mirror,'ls-tree','-r','--name-only',commit],capture=True)
    rows=[]
    for item in raw.splitlines():
        path=item.strip()
        if path and Path(path).name==basename:
            if path.startswith('/') or '..' in Path(path).parts or '\\' in path:
                raise RuntimeError('unsafe Git tree path')
            rows.append(path)
            if len(rows)>limit:raise RuntimeError('Git basename search exceeds finite bound: '+basename)
    return sorted(set(rows))

def _git_fetch(folder, repo, refspecs, *, explicit_tags=False, timeout=3600, refetch=False):
    """Fetch immutable GitHub refs quietly with bounded in-process retries.

    A failed network transfer is retried inside the same preparation so a transient
    GitHub/DNS/TLS failure cannot force an operator to restart the whole acquisition.
    The caller still verifies every requested commit/ref after the fetch.
    """
    if not REPO.fullmatch(repo):
        raise RuntimeError('untrusted Git repo')
    refs=tuple(str(value) for value in refspecs)
    if not refs or any(not value or '\x00' in value or '\n' in value or '\r' in value for value in refs):
        raise RuntimeError('invalid Git fetch refspec')
    command=['git','-c','protocol.file.allow=never','--git-dir',str(folder),'fetch',
             '--quiet','--no-recurse-submodules','--no-auto-maintenance','--no-write-fetch-head',
             '--depth=1']
    if refetch:
        # Git may otherwise decline to transfer an already-present commit even
        # when a reachable tree/blob object is absent from a retained mirror.
        # --refetch obtains the pinned object's entire closure again.
        command.append('--refetch')
    if not explicit_tags:command.append('--no-tags')
    command.extend(['https://github.com/'+repo+'.git',*refs])
    last_detail='unknown git fetch failure'
    for attempt in range(1,DOWNLOAD_ATTEMPTS+1):
        try:
            result=subprocess.run(command,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                  timeout=timeout)
            if result.returncode==0:
                return
            last_detail=(result.stderr or result.stdout or ('exit status '+str(result.returncode))).strip()
        except subprocess.TimeoutExpired as exc:
            last_detail='timeout after '+str(timeout)+'s'
            if exc.stderr:
                last_detail+=': '+str(exc.stderr)[-500:]
        last_detail=last_detail[-500:]
        if attempt<DOWNLOAD_ATTEMPTS:
            delay=DOWNLOAD_RETRY_BACKOFF[attempt-1]
            print(f'[pool] git fetch retry {attempt+1}/{DOWNLOAD_ATTEMPTS} in {delay}s: {repo}: {last_detail}',
                  file=sys.stderr,flush=True)
            time.sleep(delay)
    raise RuntimeError('Git fetch failed after '+str(DOWNLOAD_ATTEMPTS)+' attempts for '+repo+': '+last_detail)


def _git_has_commit(folder, commit):
    if not COMMIT.fullmatch(str(commit)):
        raise RuntimeError('invalid pinned Git commit')
    return subprocess.run(
        ['git','--git-dir',str(folder),'cat-file','-e',str(commit)+'^{commit}'],
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0


def _git_tree_closure_issue(folder, commits):
    """Prove every pinned commit's reachable trees and blobs exist.

    ``cat-file -e <sha>^{commit}`` proves only the commit header: a retained
    shallow/borrowed object store can still lack the trees needed by checkout.
    A scoped connectivity check audits the complete object closure without
    depending on unrelated dangling objects or fetching from the network.
    """
    refs = tuple(sorted(set(commits)))
    if not refs or any(not isinstance(ref, str) or COMMIT.fullmatch(ref) is None for ref in refs):
        raise RuntimeError('invalid pinned Git tree-closure inputs')
    try:
        result = subprocess.run(
            ['git', '--git-dir', str(folder), 'fsck', '--full', '--connectivity-only',
             '--no-reflogs', '--no-progress', '--no-dangling', *refs],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3600)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError('pinned Git tree-closure verification timed out') from exc
    if result.returncode == 0:
        return None
    return (result.stderr or result.stdout or ('git fsck exited '+str(result.returncode)))[-2000:]


def _git_ensure_complete(folder, repo, commits):
    """Repair missing objects only from the same immutable, pinned Git refs.

    Never accept a commit object as proof of the corresponding source tree.
    A failed refetch is fatal; no alternate source, static approximation or
    non-identical revision is substituted.
    """
    refs = tuple(sorted(set(commits)))
    if not REPO.fullmatch(repo) or not refs or any(COMMIT.fullmatch(ref) is None for ref in refs):
        raise RuntimeError('invalid pinned Git mirror requirements')
    missing = [ref for ref in refs if not _git_has_commit(folder, ref)]
    if missing:
        _git_fetch(folder, repo, missing)
    issue = _git_tree_closure_issue(folder, refs)
    if issue is not None:
        # Repeating a normal fetch is insufficient: Git can decide the commit
        # already exists although a nested tree or blob was lost on recovery.
        print('[pool] incomplete pinned Git object graph; refetching exact commits: '
              + repo, flush=True)
        _git_fetch(folder, repo, refs, refetch=True)
        issue = _git_tree_closure_issue(folder, refs)
        if issue is not None:
            raise RuntimeError('pinned Git tree/blob closure remains incomplete for '
                               + repo + ': ' + issue)
    for ref in refs:
        if not _git_has_commit(folder, ref):
            raise RuntimeError('pinned Git commit disappeared after verification: ' + repo + '@' + ref)


def mirror_commits(root, repo, commits, *, label='git'):
    if not REPO.fullmatch(repo) or not commits or any(not COMMIT.fullmatch(x) for x in commits):
        raise RuntimeError('untrusted Git repo/commit')
    folder=root/label/(repo.replace('/','_')+'.git')
    folder.parent.mkdir(exist_ok=True)
    if folder.exists() or folder.is_symlink():
        if folder.is_symlink() or not folder.is_dir():
            raise RuntimeError('unsafe retained Git mirror')
        if invoke(['git','--git-dir',folder,'rev-parse','--is-bare-repository'],capture=True).strip()!='true':
            raise RuntimeError('retained Git repository is not bare')
    else:
        invoke(['git','init','--bare','--quiet',folder])
    _git_ensure_complete(folder, repo, commits)
    # A bare mirror fetched by raw commit SHA has no heads.  `git clone`
    # then considers it an empty repository, despite having every Git object,
    # and a subsequent checkout fails with "unable to read tree".  Publish
    # verified, immutable commit refs under a private namespace so local
    # metadata checkouts have a real advertised source graph.
    for ref in sorted(commits):
        name = 'refs/heads/gpttrace-pinned-' + ref
        invoke(['git', '--git-dir', folder, 'update-ref', name, ref])
    return folder



def _source_requires_version_refs(mirror, commit):
    """Detect generic source-version tooling that reads Git refs at build time."""
    needles=('setuptools_scm','versioneer','git describe','git tag --','git for-each-ref')
    for filename in ('pyproject.toml','setup.cfg','setup.py','versioneer.py','_version.py'):
        text=git_file(mirror,commit,filename)
        if text and any(token in text for token in needles):
            return True
    return False


def ensure_version_refs(folder, repo, commits):
    """Freeze tag refs only for sources whose build metadata consumes Git refs."""
    if not any(_source_requires_version_refs(folder,commit) for commit in commits):
        return {}
    _git_fetch(folder,repo,['+refs/tags/*:refs/tags/*'],explicit_tags=True)
    raw=invoke(['git','--git-dir',folder,'show-ref','--tags','-d'],capture=True)
    refs={}
    for line in raw.splitlines():
        match=re.fullmatch(r'([0-9a-f]{40})\s+(refs/tags/[^\s]+)',line)
        if match:refs[match.group(2)]=match.group(1)
    if not refs:
        raise RuntimeError('source version metadata requires Git tags but none were frozen: '+repo)
    return dict(sorted(refs.items()))

def _acquire_git_mirrors(stage, repositories, *, label='git', freeze_version_refs=False):
    """Fetch independent repositories concurrently within the acquisition I/O budget."""
    ordered=[(repo,tuple(sorted(commits))) for repo,commits in sorted(repositories.items()) if commits]
    if not ordered:return {},{}
    try:
        cpu_capacity=len(os.sched_getaffinity(0))
    except OSError as exc:
        raise RuntimeError('CPU affinity is unavailable for Git acquisition') from exc
    if cpu_capacity<1:
        raise RuntimeError('CPU affinity is empty for Git acquisition')
    # Git fetch performs pack inflation/indexing and filesystem writes, unlike the
    # metadata-only HTTP resolver. Bound Git concurrency by actual CPU capacity.
    workers=min(_acquisition_workers(),cpu_capacity,len(ordered))
    phase = 'Git mirrors: ' + label
    if _POOL_PROGRESS is not None:
        _pool_progress(phase,0,len(ordered),'repositories',f'{workers} workers')
    else:
        print(f'[pool] {label} mirrors: {len(ordered)} repositories with {workers} workers',flush=True)
    def acquire(repo,commits):
        mirror=mirror_commits(stage,repo,set(commits),label=label)
        refs=ensure_version_refs(mirror,repo,commits) if freeze_version_refs else {}
        return repo,mirror,refs
    futures=[];results={};refs={}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers,
                                               thread_name_prefix=label+'-mirror') as executor:
        futures=[executor.submit(acquire,repo,commits) for repo,commits in ordered]
        try:
            for future in concurrent.futures.as_completed(futures):
                repo,mirror,version_refs=future.result()
                results[repo]=mirror;refs[repo]=version_refs
                _pool_progress(phase,len(results),len(ordered),'repositories',f'{workers} workers')
        except BaseException:
            for future in futures:future.cancel()
            raise
    return ({repo:results[repo] for repo,_commits in ordered},
            {repo:refs[repo] for repo,_commits in ordered})


def ensure_commit(stage,repo,commit,*,label='git-extra'):
    folder=stage/label/(repo.replace('/','_')+'.git')
    # The same full-tree requirement applies to dynamically discovered VCS
    # dependencies; the old commit-header-only check could accept a broken CAS.
    return mirror_commits(stage,repo,{commit},label=label)


def vcs_reference(value):
    """Recognize both pip legacy URLs and PEP 508 direct Git references."""
    value = value.strip()
    match = re.fullmatch(r'(?:[A-Za-z0-9_.-]+(?:\[[^]\n]+\])?\s*@\s*)?(git\+https://[^\s]+)', value)
    if match:
        return match.group(1)
    return None


def parse_requirements(text, filename, get_file, *, seen=None, constraint=False):
    """Return requirements, VCS references and CONSTRAINTS independently."""
    seen = set() if seen is None else seen
    key = (filename, constraint)
    if key in seen: return set(), set(), set()
    seen.add(key)
    specs, git, constraints = set(), set(), set()
    for original in text.replace('\\\n', '').splitlines():
        value = original.strip()
        if not value or value.startswith('#'): continue
        if value.startswith(('-r ', '--requirement ', '-c ', '--constraint ')):
            flag, child = value.split(maxsplit=1)
            if child.startswith(('/', 'http')) or '..' in Path(child).parts:
                raise RuntimeError('unsafe pip included requirements: ' + value)
            sub = str(Path(filename).parent / child)
            is_constraint = constraint or flag in ('-c', '--constraint')
            a, b, c = parse_requirements(get_file(sub, required=True), sub, get_file,
                                          seen=seen, constraint=is_constraint)
            specs.update(a); git.update(b); constraints.update(c)
            continue
        if value.startswith(('-e ', '--editable ')):
            target = value.split(maxsplit=1)[1]
            ref = vcs_reference(target)
            if ref:
                if constraint: raise RuntimeError('VCS dependency in constraints')
                git.add(ref)
                continue
            if target in ('.', './') or target.startswith(('./', '.[', '/testbed')):
                continue
            raise RuntimeError('unresolved editable dependency: ' + value)
        ref = vcs_reference(value)
        if ref:
            if constraint: raise RuntimeError('VCS dependency in constraints')
            git.add(ref)
            continue
        if value.startswith('-') or value.startswith(('https://', 'http://')):
            raise RuntimeError('unsupported pip requirement directive: ' + value)
        # A comment after whitespace is not part of a PEP 508 requirement.
        value = re.split(r'\s+#', value, maxsplit=1)[0].strip()
        (constraints if constraint else specs).add(value)
    return specs, git, constraints



def _poetry_version_spec(name, value):
    """Translate the finite Poetry constraint forms used by pinned inputs to PEP 440."""
    if not isinstance(value, str):
        raise ValueError('Poetry dependency version is not a string: ' + name)
    value = value.strip()
    if value in ('', '*'):
        return name
    if '||' in value:
        raise ValueError('unsupported Poetry disjunction for ' + name)
    if value.startswith('^'):
        base = value[1:]
        if not re.fullmatch(r'\d+(?:\.\d+){0,3}(?:[A-Za-z0-9.+-]*)?', base):
            raise ValueError('unsupported Poetry caret version for ' + name + ': ' + value)
        release = base.split('-', 1)[0].split('+', 1)[0]
        numeric = []
        for part in release.split('.'):
            match = re.match(r'(\d+)', part)
            if not match: break
            numeric.append(int(match.group(1)))
        while len(numeric) < 3: numeric.append(0)
        major, minor, patch = numeric[:3]
        if major:
            upper = f'{major + 1}.0.0'
        elif minor:
            upper = f'0.{minor + 1}.0'
        else:
            upper = f'0.0.{patch + 1}'
        return name + '>=' + base + ',<' + upper
    if value.startswith('~') and not value.startswith('~='):
        base = value[1:]
        if not re.fullmatch(r'\d+(?:\.\d+){0,3}(?:[A-Za-z0-9.+-]*)?', base):
            raise ValueError('unsupported Poetry tilde version for ' + name + ': ' + value)
        numeric = [int(x) for x in re.findall(r'^\d+|\.(\d+)', base) if x != '']
        # re.findall with a capture is awkward for the first component; derive
        # the release again without ever evaluating project code.
        release = base.split('-', 1)[0].split('+', 1)[0]
        parts = [int(re.match(r'\d+', x).group()) for x in release.split('.') if re.match(r'\d+', x)]
        if len(parts) <= 1:
            upper = f'{parts[0] + 1}.0.0'
        else:
            upper = f'{parts[0]}.{parts[1] + 1}.0'
        return name + '>=' + base + ',<' + upper
    if re.fullmatch(r'\d+(?:\.\d+)*(?:[A-Za-z0-9.+-]*)?', value):
        return name + '==' + value
    if re.fullmatch(r'\d+(?:\.\d+)*\.\*', value):
        return name + '==' + value
    if value.startswith(('=', '<', '>', '!', '~=')):
        return name + value
    # Comma-separated standard constraints such as ">=1,<2".
    if any(value.startswith(prefix) for prefix in ('>=', '<=', '!=', '==')):
        return name + value
    raise ValueError('unsupported Poetry dependency version for ' + name + ': ' + value)


def _normalized_package_name(value):
    return re.sub(r'[-_.]+', '-', str(value)).lower()


def _self_extra_reference(requirement, project_name):
    """Return extras for a local self-reference, or None for a normal requirement."""
    if not isinstance(requirement, str) or not isinstance(project_name, str) or not project_name:
        return None
    head = requirement.split(';', 1)[0].strip()
    match = re.fullmatch(r'([A-Za-z0-9_.-]+)(?:\[([^]]*)\])?', head)
    if not match or _normalized_package_name(match.group(1)) != _normalized_package_name(project_name):
        return None
    extras = tuple(x.strip() for x in (match.group(2) or '').split(',') if x.strip())
    return extras


def static_project(file, *, extra_groups=()):
    """Interpret declarative pyproject metadata without executing a backend.

    PEP 621 self-referential extras (for example a project extra referenced
    from another local extra) are recursively expanded from the same pinned file. They
    must never cause the fetcher to resolve a different, published copy of the
    project from PyPI.
    """
    if not file: return set(),set(),[]
    issues=[]; deps=set();git=set()
    data=tomllib.loads(file)
    project=data.get('project',{})
    if not isinstance(project, dict):
        return set(),set(),['invalid PEP621 project table']
    raw_dependencies = project.get('dependencies', [])
    if not isinstance(raw_dependencies, list):
        issues.append('invalid PEP621 dependencies')
    else:
        deps.update(raw_dependencies)
    build_requires = data.get('build-system',{}).get('requires',[])
    if not isinstance(build_requires, list): issues.append('invalid build-system requires')
    for k in ('dependencies','optional-dependencies'):
        if k in project.get('dynamic',[]):issues.append('dynamic PEP621 '+k)

    optional = project.get('optional-dependencies',{})
    if optional is None: optional = {}
    if not isinstance(optional, dict):
        issues.append('invalid PEP621 optional-dependencies table')
        optional = {}
    project_name = project.get('name')
    visited=set()
    def add_pep621_group(group, stack=()):
        if group in stack:
            issues.append('recursive PEP621 self extra: '+' -> '.join((*stack,group)))
            return
        if group in visited:
            return
        items=optional.get(group)
        if items is None:
            return
        if not isinstance(items,list):
            issues.append('invalid PEP621 optional dependency group '+group)
            return
        visited.add(group)
        for item in items:
            if not isinstance(item,str):
                issues.append('non-string PEP621 optional dependency in '+group)
                continue
            nested=_self_extra_reference(item,project_name)
            if nested is not None:
                for child in nested:
                    add_pep621_group(child,(*stack,group))
                continue
            deps.add(item)
    requested_groups = set(optional) if '*' in extra_groups else set(extra_groups)
    for group in sorted(requested_groups):
        add_pep621_group(group)

    pdm=data.get('tool',{}).get('pdm',{})
    for group,items in pdm.get('dev-dependencies',{}).items():
        if group in extra_groups or '*' in extra_groups:
            if isinstance(items, list): deps.update(items)
            else: issues.append('invalid PDM dependency group '+group)
    poetry=data.get('tool',{}).get('poetry',{})
    poetry_extras = poetry.get('extras', {}) if isinstance(poetry.get('extras', {}), dict) else {}
    selected_optional = set()
    for group,names in poetry_extras.items():
        if group in extra_groups or '*' in extra_groups:
            if isinstance(names,list): selected_optional.update(str(name) for name in names)
            else: issues.append('invalid Poetry extra '+group)
    poetry_dependencies = poetry.get('dependencies', {})
    if isinstance(poetry_dependencies, dict):
        for name,spec in poetry_dependencies.items():
            if name=='python':continue
            optional_dep = isinstance(spec,dict) and spec.get('optional') is True
            if optional_dep and name not in selected_optional:
                continue
            try:
                if isinstance(spec,str):
                    deps.add(_poetry_version_spec(name,spec))
                elif isinstance(spec,dict):
                    if 'git' in spec:
                        url = spec.get('git')
                        ref = spec.get('rev') or spec.get('tag') or spec.get('branch')
                        if (not isinstance(url,str) or
                                not re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?',url)):
                            raise ValueError('untrusted Poetry Git dependency '+name)
                        direct = name+' @ git+'+url
                        if isinstance(ref,str) and ref: direct += '@'+ref
                        git.add(vcs_reference(direct) or direct)
                    elif isinstance(spec.get('version'),str):
                        deps.add(_poetry_version_spec(name,spec['version']))
                    else:
                        raise ValueError('unresolved Poetry dependency '+name)
                else:
                    raise ValueError('unresolved Poetry dependency '+name)
            except ValueError as exc:
                issues.append(str(exc))
    elif poetry_dependencies:
        issues.append('invalid Poetry dependencies table')
    poetry_dev = poetry.get('dev-dependencies',{})
    if ('dev' in extra_groups or 'test' in extra_groups or '*' in extra_groups):
        if isinstance(poetry_dev,dict):
            for name,spec in poetry_dev.items():
                try:
                    if isinstance(spec,str): deps.add(_poetry_version_spec(name,spec))
                    elif isinstance(spec,dict) and isinstance(spec.get('version'),str):
                        deps.add(_poetry_version_spec(name,spec['version']))
                    else: issues.append('unresolved Poetry dev dependency '+name)
                except ValueError as exc: issues.append(str(exc))
        elif poetry_dev:
            issues.append('invalid Poetry dev dependency table')
    for row in list(deps):
        if not isinstance(row,str):
            deps.remove(row); issues.append('non-string Python dependency metadata'); continue
        ref=vcs_reference(row)
        if ref:
            deps.remove(row);git.add(ref)
    return deps,git,issues

def setup_cfg_static(source, *, extras=()):
    """Read declarative setuptools requirements (no package execution)."""
    if not source: return set(), []
    parsed = configparser.ConfigParser(interpolation=None)
    try: parsed.read_string(source)
    except configparser.Error as exc: return set(), ['invalid setup.cfg: ' + str(exc)]
    specs = set()
    def add(section, key):
        for raw in parsed.get(section, key, fallback='').splitlines():
            value = raw.strip()
            if value and not value.startswith('#'): specs.add(value)
    add('options', 'install_requires')
    add('options', 'setup_requires')
    if parsed.has_section('options.extras_require'):
        for group in parsed.options('options.extras_require'):
            if group in extras or '*' in extras: add('options.extras_require', group)
    return specs, []


def setup_static(source, *, extras=(), get_file=None, python_version=None, setup_argv=None):
    """Evaluate a bounded subset of setuptools metadata without executing it.

    The evaluator models setup.py as a script (``__name__ == '__main__'``),
    follows only statically-audited Python control/data flow, and virtualizes
    file reads through the pinned Git reader.  User functions are interpreted
    only through the same bounded statement/expression surface; arbitrary
    project code is never imported or executed.
    """
    import ast
    import copy
    import posixpath
    if not source: return set(), []
    try: tree = ast.parse(source)
    except SyntaxError: return set(), ['unparseable setup.py']

    unresolved = object()
    argv = tuple(setup_argv) if setup_argv is not None else ('setup.py','egg_info')
    if (not argv or argv[0] != 'setup.py' or
            not all(isinstance(item,str) and '\x00' not in item for item in argv)):
        return set(), ['invalid static setup.py invocation']
    env = {'__name__':'__main__','__file__':'setup.py'}
    setup_calls=[]
    control_issues=[]
    target_version = None
    if python_version is not None:
        match = re.fullmatch(r'(\d+)\.(\d+)(?:\.(\d+))?', str(python_version))
        if not match:
            return set(), ['invalid target Python version for setup.py: '+str(python_version)]
        target_version = tuple(int(x or 0) for x in match.groups())

    functions={node.name:node for node in tree.body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))}
    active_functions=set()
    imports={}
    for node in tree.body:
        if isinstance(node,ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name.split('.')[0]]=alias.name
        elif isinstance(node,ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name!='*':imports[alias.asname or alias.name]=node.module+'.'+alias.name

    def symbol(node):
        if isinstance(node,ast.Name):return imports.get(node.id,node.id)
        if isinstance(node,ast.Attribute):
            base=symbol(node.value)
            return None if base is None else base+'.'+node.attr
        return None

    def virtual_path(value):
        if not isinstance(value,str) or '\x00' in value or '\\' in value:
            raise ValueError('unsafe setup.py metadata path')
        # ``abspath(__file__)`` is deliberately virtualized to the pinned Git
        # checkout root; host absolute paths must never influence acquisition.
        normalized=posixpath.normpath(value)
        if normalized in ('','.'):return '.'
        if normalized.startswith('/') or normalized=='..' or normalized.startswith('../'):
            raise ValueError('unsafe setup.py metadata path')
        return normalized.removeprefix('./')

    def safe_path(name):
        name=virtual_path(name)
        if name=='.':raise ValueError('setup.py metadata path names a directory')
        if get_file is None:
            raise ValueError('setup.py file-backed metadata requires pinned source reader')
        value=get_file(name,required=True)
        if not isinstance(value,str):
            raise ValueError('setup.py metadata file is not text: '+name)
        return value

    class StaticReturn(BaseException):
        def __init__(self,value):self.value=value

    def evaluate(node, visiting=frozenset()):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bool, int, float, type(None))):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in visiting or node.id not in env or env[node.id] is unresolved:
                raise ValueError('unresolved setup.py name ' + node.id)
            return copy.deepcopy(env[node.id])
        if isinstance(node, ast.List):
            return [evaluate(item,visiting) for item in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(evaluate(item,visiting) for item in node.elts)
        if isinstance(node, ast.Set):
            return set(evaluate(item,visiting) for item in node.elts)
        if isinstance(node, ast.Dict):
            result={}
            for key,value in zip(node.keys,node.values):
                key_value=evaluate(key,visiting)
                if not isinstance(key_value,str):
                    raise ValueError('non-string setup.py mapping key')
                try:result[key_value]=evaluate(value,visiting)
                except (TypeError,ValueError,KeyError,IndexError):result[key_value]=unresolved
            return result
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return evaluate(node.left,visiting)+evaluate(node.right,visiting)
        if isinstance(node, ast.Attribute):
            name=symbol(node)
            if name in ('sys.version_info',):
                if target_version is None:
                    raise ValueError('target Python required for sys.version_info')
                return target_version
            if name in ('sys.argv',):return argv
        if isinstance(node, ast.Subscript):
            base=evaluate(node.value,visiting)
            index=evaluate(node.slice,visiting)
            return base[index]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op,ast.USub):
            value=evaluate(node.operand,visiting)
            if not isinstance(value,(int,float)): raise ValueError('non-numeric setup.py unary expression')
            return -value
        if isinstance(node, ast.IfExp):
            return evaluate(node.body if condition(node.test) else node.orelse,visiting)
        if isinstance(node,ast.ListComp):
            if len(node.generators)!=1 or node.generators[0].is_async or not isinstance(node.generators[0].target,ast.Name):
                raise ValueError('dynamic setup.py comprehension')
            generator=node.generators[0]
            values=evaluate(generator.iter,visiting)
            if not isinstance(values,(list,tuple,set)) or len(values)>4096:
                raise ValueError('dynamic setup.py comprehension')
            name=generator.target.id;had=name in env;previous=env.get(name)
            result=[]
            try:
                for value in values:
                    env[name]=copy.deepcopy(value)
                    if all(condition(item) for item in generator.ifs):result.append(evaluate(node.elt,visiting))
            finally:
                if had:env[name]=previous
                else:env.pop(name,None)
            return result
        if isinstance(node, ast.Call):
            callee=symbol(node.func)
            if isinstance(node.func,ast.Name) and node.func.id in functions:
                return call_function(functions[node.func.id],node.args,node.keywords)
            if callee in ('str','builtins.str') and len(node.args)==1 and not node.keywords:
                return str(evaluate(node.args[0],visiting))
            if callee in ('len','builtins.len') and len(node.args)==1 and not node.keywords:
                return len(evaluate(node.args[0],visiting))
            if callee in ('list','builtins.list','tuple','builtins.tuple','set','builtins.set') and len(node.args)<=1 and not node.keywords:
                value=[] if not node.args else evaluate(node.args[0],visiting)
                return {'list':list,'builtins.list':list,'tuple':tuple,'builtins.tuple':tuple,
                        'set':set,'builtins.set':set}[callee](value)
            if callee in ('pathlib.Path','Path') and len(node.args)==1 and not node.keywords:
                value=evaluate(node.args[0],visiting)
                return ('__pinned_path__',virtual_path(value))
            if callee in ('open','builtins.open','codecs.open','io.open'):
                if not node.args:raise ValueError('setup.py open path is absent')
                path=evaluate(node.args[0],visiting)
                if isinstance(path,tuple) and len(path)==2 and path[0]=='__pinned_path__':path=path[1]
                return ('__pinned_file__',virtual_path(path))
            if callee in ('os.path.join','posixpath.join') or callee=='join' and imports.get('join')=='os.path.join':
                parts=[evaluate(item,visiting) for item in node.args]
                if not all(isinstance(item,str) for item in parts):raise ValueError('dynamic setup.py path join')
                return virtual_path(posixpath.join(*parts))
            if callee in ('os.path.dirname','posixpath.dirname') or callee=='dirname' and imports.get('dirname')=='os.path.dirname':
                if len(node.args)!=1:raise ValueError('dynamic setup.py dirname')
                value=evaluate(node.args[0],visiting)
                if not isinstance(value,str):raise ValueError('dynamic setup.py dirname')
                return posixpath.dirname(value) or '.'
            if callee in ('os.path.abspath','posixpath.abspath') or callee=='abspath' and imports.get('abspath')=='os.path.abspath':
                if len(node.args)!=1:raise ValueError('dynamic setup.py abspath')
                value=evaluate(node.args[0],visiting)
                return virtual_path(value)
            if callee in ('pkg_resources.parse_requirements',):
                if len(node.args)!=1 or node.keywords:raise ValueError('dynamic parse_requirements invocation')
                value=evaluate(node.args[0],visiting)
                if isinstance(value,tuple) and len(value)==2 and value[0]=='__pinned_file__':value=safe_path(value[1])
                if not isinstance(value,str):raise ValueError('dynamic parse_requirements input')
                Requirement,_,_,_,_=_packaging_symbols();result=[]
                for raw in value.splitlines():
                    raw=raw.strip()
                    if not raw or raw.startswith('#'):continue
                    try:result.append(str(Requirement(raw)))
                    except Exception as exc:raise ValueError('invalid setup.py parsed requirement: '+raw) from exc
                return result
            if isinstance(node.func,ast.Attribute) and not node.keywords:
                owner=evaluate(node.func.value,visiting);method=node.func.attr
                if method=='open' and isinstance(owner,tuple) and len(owner)==2 and owner[0]=='__pinned_path__':
                    return ('__pinned_file__',owner[1])
                if method=='read_text' and isinstance(owner,tuple) and len(owner)==2 and owner[0]=='__pinned_path__':
                    if node.args: raise ValueError('setup.py read_text arguments are unsupported')
                    return safe_path(owner[1])
                if method=='read' and isinstance(owner,tuple) and len(owner)==2 and owner[0]=='__pinned_file__':
                    if node.args:raise ValueError('setup.py file read arguments are unsupported')
                    return safe_path(owner[1])
                if method=='readlines' and isinstance(owner,tuple) and len(owner)==2 and owner[0]=='__pinned_file__':
                    if node.args:raise ValueError('setup.py file readlines arguments are unsupported')
                    return safe_path(owner[1]).splitlines(keepends=True)
                if method=='strip' and isinstance(owner,str) and not node.args:return owner.strip()
                if method=='splitlines' and isinstance(owner,str) and not node.args:return owner.splitlines()
                if method=='startswith' and isinstance(owner,str) and len(node.args) in (1,2,3):
                    return owner.startswith(*(evaluate(item,visiting) for item in node.args))
                if method=='endswith' and isinstance(owner,str) and len(node.args) in (1,2,3):
                    return owner.endswith(*(evaluate(item,visiting) for item in node.args))
                if method=='intersection' and isinstance(owner,(set,list,tuple)) and len(node.args)==1:
                    return set(owner).intersection(evaluate(node.args[0],visiting))
            raise ValueError('dynamic setup.py metadata expression')
        raise ValueError('dynamic setup.py metadata expression')

    def condition(node):
        if isinstance(node,ast.Constant) and isinstance(node.value,bool): return node.value
        if isinstance(node,ast.UnaryOp) and isinstance(node.op,ast.Not): return not condition(node.operand)
        if isinstance(node,ast.BoolOp):
            values=[condition(v) for v in node.values]
            return all(values) if isinstance(node.op,ast.And) else any(values)
        if isinstance(node,ast.Compare) and len(node.ops)==len(node.comparators)==1:
            left=evaluate(node.left);right=evaluate(node.comparators[0]);op=node.ops[0]
            if isinstance(op,ast.Eq): return left==right
            if isinstance(op,ast.NotEq): return left!=right
            if isinstance(op,ast.Lt): return left<right
            if isinstance(op,ast.LtE): return left<=right
            if isinstance(op,ast.Gt): return left>right
            if isinstance(op,ast.GtE): return left>=right
            if isinstance(op,ast.Is): return left is right
            if isinstance(op,ast.IsNot): return left is not right
            if isinstance(op,ast.In): return left in right
            if isinstance(op,ast.NotIn): return left not in right
        value=evaluate(node)
        if isinstance(value,(bool,str,int,float,list,tuple,set,dict,type(None))):return bool(value)
        raise ValueError('dynamic setup.py condition')

    def merge_static_dependency_branches(node):
        """Accept an unknown condition only when both dependency outcomes are identical."""
        allowed = {'install_requires', 'setup_requires'}
        def assignments(statements):
            values = {}
            if not statements:return None
            for statement in statements:
                if (not isinstance(statement,ast.Assign) or len(statement.targets)!=1
                        or not isinstance(statement.targets[0],ast.Name)):
                    return None
                name=statement.targets[0].id
                if name not in allowed or name in values:return None
                try:requirements=evaluate(statement.value)
                except (TypeError,ValueError,KeyError,IndexError):return None
                if (not isinstance(requirements,(list,tuple))
                        or not all(isinstance(req,str) for req in requirements)):return None
                values[name]=requirements
            return values
        true_branch=assignments(node.body);false_branch=assignments(node.orelse)
        if true_branch is None or false_branch is None or true_branch!=false_branch:return False
        for name in true_branch:env[name]=list(true_branch[name])
        return True

    def bound_target(target,value):
        if isinstance(target,ast.Name):env[target.id]=copy.deepcopy(value);return True
        return False

    def assigned_names(node):
        names=set()
        for child in ast.walk(node):
            if isinstance(child,ast.Name) and isinstance(child.ctx,ast.Store):names.add(child.id)
            if (isinstance(child,ast.Call) and isinstance(child.func,ast.Attribute)
                    and isinstance(child.func.value,ast.Name) and child.func.attr in ('append','extend')):
                names.add(child.func.value.id)
        return names

    def is_setup_call(call):
        return isinstance(call,ast.Call) and symbol(call.func) in {
            'setup','setuptools.setup','distutils.core.setup',
        }

    def call_function(function,args,keywords):
        if function.name in active_functions:raise ValueError('recursive setup.py helper')
        if function.args.vararg or function.args.kwarg or function.args.kwonlyargs:
            raise ValueError('dynamic setup.py helper signature')
        positional=[evaluate(item) for item in args]
        named={kw.arg:evaluate(kw.value) for kw in keywords if kw.arg is not None}
        if any(kw.arg is None for kw in keywords):raise ValueError('dynamic setup.py helper arguments')
        params=[arg.arg for arg in function.args.args]
        required=len(params)-len(function.args.defaults)
        if len(positional)>len(params):raise ValueError('setup.py helper argument mismatch')
        values={}
        for index,value in enumerate(positional):values[params[index]]=value
        for name,value in named.items():
            if name not in params or name in values:raise ValueError('setup.py helper argument mismatch')
            values[name]=value
        defaults=dict(zip(params[required:],function.args.defaults))
        for name in params:
            if name not in values:
                if name not in defaults:raise ValueError('setup.py helper argument mismatch')
                values[name]=evaluate(defaults[name])
        saved=copy.deepcopy(env);active_functions.add(function.name)
        try:
            env.update(copy.deepcopy(values))
            try:
                for statement in function.body:apply_statement(statement,in_function=True)
            except StaticReturn as returned:
                return returned.value
            return None
        finally:
            env.clear();env.update(saved);active_functions.remove(function.name)

    def apply_statement(node, *, in_function=False):
        if isinstance(node,(ast.Import,ast.ImportFrom,ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Pass)):
            return
        if isinstance(node,ast.Assign):
            try:value=evaluate(node.value)
            except (TypeError,ValueError,KeyError,IndexError):value=unresolved
            for target in node.targets:
                if isinstance(target,ast.Name):env[target.id]=copy.deepcopy(value)
            return
        if isinstance(node,ast.AnnAssign) and isinstance(node.target,ast.Name) and node.value is not None:
            try:env[node.target.id]=evaluate(node.value)
            except (TypeError,ValueError,KeyError,IndexError):env[node.target.id]=unresolved
            return
        if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call):
            call=node.value
            if is_setup_call(call):
                setup_calls.append((call,{key:unresolved if value is unresolved else copy.deepcopy(value) for key,value in env.items()}));return
            if isinstance(call.func,ast.Name) and call.func.id in functions:
                try:call_function(functions[call.func.id],call.args,call.keywords)
                except (TypeError,ValueError,KeyError,IndexError):
                    if any(is_setup_call(child) for child in ast.walk(functions[call.func.id])):
                        control_issues.append('setup.py setup helper cannot be resolved statically')
                return
            if (isinstance(call.func,ast.Attribute) and isinstance(call.func.value,ast.Name)
                    and call.func.attr in ('append','extend') and not call.keywords
                    and call.func.value.id in env and env[call.func.value.id] is not unresolved):
                if len(call.args)!=1:
                    env[call.func.value.id]=unresolved;return
                try:value=evaluate(call.args[0])
                except (TypeError,ValueError,KeyError,IndexError):env[call.func.value.id]=unresolved;return
                current=env.get(call.func.value.id,unresolved)
                if not isinstance(current,list):env[call.func.value.id]=unresolved;return
                if call.func.attr=='append':current.append(value)
                elif isinstance(value,(list,tuple)):current.extend(value)
                else:env[call.func.value.id]=unresolved
            return
        if isinstance(node,ast.If):
            try:selected=node.body if condition(node.test) else node.orelse
            except (TypeError,ValueError,KeyError,IndexError):
                if merge_static_dependency_branches(node):return
                if any(is_setup_call(child) for child in ast.walk(node)):
                    control_issues.append('setup.py invokes setup under an unresolved condition')
                for name in assigned_names(node):env[name]=unresolved
                return
            for child in selected:apply_statement(child,in_function=in_function)
            return
        if isinstance(node,(ast.With,ast.AsyncWith)):
            saved={}
            for item in node.items:
                if not isinstance(item.optional_vars,(ast.Name,type(None))):
                    for name in assigned_names(node):env[name]=unresolved
                    return
                if item.optional_vars is not None:
                    name=item.optional_vars.id;saved[name]=(name in env,env.get(name))
                    try:env[name]=evaluate(item.context_expr)
                    except (TypeError,ValueError,KeyError,IndexError):env[name]=unresolved
            try:
                for child in node.body:apply_statement(child,in_function=in_function)
            finally:
                for name,(had,value) in saved.items():
                    if had:env[name]=value
                    else:env.pop(name,None)
            return
        if isinstance(node,ast.For):
            try:values=evaluate(node.iter)
            except (TypeError,ValueError,KeyError,IndexError):
                for name in assigned_names(node):env[name]=unresolved
                return
            if not isinstance(values,(list,tuple,set)) or len(values)>4096 or not isinstance(node.target,ast.Name):
                for name in assigned_names(node):env[name]=unresolved
                return
            name=node.target.id;had=name in env;previous=env.get(name)
            try:
                for value in values:
                    env[name]=copy.deepcopy(value)
                    for child in node.body:apply_statement(child,in_function=in_function)
                for child in node.orelse:apply_statement(child,in_function=in_function)
            finally:
                if had:env[name]=previous
                else:env.pop(name,None)
            return
        if isinstance(node,ast.Try):
            # Both the normal path and every handler are possible without executing
            # project code.  Dependency sets are unioned later across reached setup().
            for child in node.body:apply_statement(child,in_function=in_function)
            for handler in node.handlers:
                for child in handler.body:apply_statement(child,in_function=in_function)
            for child in node.orelse:apply_statement(child,in_function=in_function)
            for child in node.finalbody:apply_statement(child,in_function=in_function)
            return
        if isinstance(node,ast.Return) and in_function:
            raise StaticReturn(None if node.value is None else evaluate(node.value))
        if isinstance(node,(ast.AugAssign,ast.Delete,ast.While,ast.AsyncFor,ast.Match)):
            for name in assigned_names(node):env[name]=unresolved
            if any(is_setup_call(child) for child in ast.walk(node)):
                control_issues.append('setup.py invokes setup through unsupported control flow')
            return

    for statement in tree.body:apply_statement(statement)

    deps,issues=set(),list(control_issues)
    if not setup_calls:issues.append('setup.py has no statically reached setup invocation')

    def fields_from_call(call):
        fields={kw.arg:kw.value for kw in call.keywords if kw.arg is not None}
        for kw in call.keywords:
            if kw.arg is not None:continue
            try:mapping=evaluate(kw.value)
            except (TypeError,ValueError,KeyError,IndexError) as exc:
                issues.append('setup.py computes **kwargs dynamically: '+str(exc));continue
            if not isinstance(mapping,dict):
                issues.append('setup.py **kwargs is not a mapping');continue
            for key,value in mapping.items():
                if key in fields:continue
                if value is unresolved:fields[key]=ast.Name(id='__unresolved_setup_kwarg__',ctx=ast.Load())
                else:
                    try:fields[key]=ast.parse(repr(value),mode='eval').body
                    except SyntaxError:fields[key]=ast.Name(id='__unresolved_setup_kwarg__',ctx=ast.Load())
        return fields
    for node,snapshot in setup_calls:
        saved=env;env=snapshot
        try:
            fields=fields_from_call(node)
            for name in ('install_requires','setup_requires'):
                if name not in fields:continue
                try:values=evaluate(fields[name])
                except (TypeError,ValueError,KeyError,IndexError) as exc:
                    issues.append('setup.py computes '+name+' dynamically: '+str(exc));continue
                if isinstance(values,(list,tuple)) and all(isinstance(v,str) for v in values):deps.update(values)
                else:issues.append('setup.py unexpected '+name)
            if extras and 'extras_require' in fields:
                try:mapping=evaluate(fields['extras_require'])
                except (TypeError,ValueError,KeyError,IndexError) as exc:
                    issues.append('setup.py computes extras_require dynamically: '+str(exc));continue
                if not isinstance(mapping,dict):
                    issues.append('setup.py computes extras_require dynamically: extras_require is not a mapping');continue
                for group,values in mapping.items():
                    if group not in extras and '*' not in extras:continue
                    if isinstance(values,(list,tuple)) and all(isinstance(v,str) for v in values):deps.update(values)
                    else:issues.append('setup.py computes extras_require dynamically: dynamic setup.py extra '+str(group))
        finally:env=saved
    return deps,issues

def _setup_dependency_files(source, *, extras=()):
    """Find literal requirement files that feed setuptools dependency fields.

    The walk is generic data flow over module-level assignments, helper calls,
    ``with`` readers, and append/extend mutations.  It never executes project
    code and it only follows values reachable from dependency-bearing setup()
    arguments (including selected extras).
    """
    if not source:return set()
    try:tree=ast.parse(source)
    except SyntaxError:return set()
    assignments={};functions={};mutations=defaultdict(list);with_sources=defaultdict(list)
    def top_level_nodes(statements):
        for statement in statements:
            yield statement
            if isinstance(statement,(ast.With,ast.AsyncWith,ast.If,ast.For,ast.While,ast.Try)):
                for field in ('body','orelse','finalbody'):
                    children=getattr(statement,field,())
                    yield from top_level_nodes(children)
                for handler in getattr(statement,'handlers',()):
                    yield from top_level_nodes(handler.body)

    for node in top_level_nodes(tree.body):
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
            functions[node.name]=node
        elif isinstance(node,ast.Assign):
            for target in node.targets:
                if isinstance(target,ast.Name):assignments[target.id]=node.value
        elif isinstance(node,ast.AnnAssign) and isinstance(node.target,ast.Name) and node.value is not None:
            assignments[node.target.id]=node.value
        elif (isinstance(node,ast.Expr) and isinstance(node.value,ast.Call)
              and isinstance(node.value.func,ast.Attribute)
              and isinstance(node.value.func.value,ast.Name)
              and node.value.func.attr in {'append','extend'}):
            mutations[node.value.func.value.id].append(node.value)
        elif isinstance(node,(ast.With,ast.AsyncWith)):
            assigned=set()
            for child in node.body:
                for descendant in ast.walk(child):
                    if isinstance(descendant,(ast.Assign,ast.AnnAssign)):
                        targets=descendant.targets if isinstance(descendant,ast.Assign) else [descendant.target]
                        assigned.update(target.id for target in targets if isinstance(target,ast.Name))
            for name in assigned:
                with_sources[name].extend(item.context_expr for item in node.items)
    requirement_path=re.compile(r'(?i)(?:^|/)[A-Za-z0-9_.-]*(?:requirements?|requires?)[A-Za-z0-9_.-]*\.txt\Z')

    def literal_path(value):
        if not isinstance(value,str) or not requirement_path.search(value):return None
        path=Path(value)
        if path.is_absolute() or '..' in path.parts or '\\' in value:return None
        return path.as_posix().removeprefix('./')

    def walk_function(function,names,funcs):
        found=set()
        for child in function.body:
            found.update(walk(child,names,funcs))
        return found

    def walk(node, names=frozenset(), funcs=frozenset()):
        found=set()
        if node is None:return found
        if isinstance(node,ast.Constant):
            path=literal_path(node.value)
            if path:found.add(path)
            return found
        if isinstance(node,ast.Name):
            if node.id in names:return found
            nested=names|{node.id}
            if node.id in assignments:found.update(walk(assignments[node.id],nested,funcs))
            for mutation in mutations.get(node.id,()):found.update(walk(mutation,nested,funcs))
            for context in with_sources.get(node.id,()):found.update(walk(context,nested,funcs))
            return found
        if isinstance(node,ast.Call):
            found.update(walk(node.func,names,funcs))
            for item in (*node.args,*(kw.value for kw in node.keywords)):
                found.update(walk(item,names,funcs))
            if isinstance(node.func,ast.Name) and node.func.id in functions and node.func.id not in funcs:
                found.update(walk_function(functions[node.func.id],names,funcs|{node.func.id}))
            return found
        if isinstance(node,ast.Dict):
            for key,value in zip(node.keys,node.values):
                key_value=key.value if isinstance(key,ast.Constant) else None
                if key_value in {'install_requires','setup_requires'}:
                    found.update(walk(value,names,funcs))
                elif key_value=='extras_require':
                    found.update(walk(value,names,funcs))
                elif isinstance(key_value,str) and (key_value in extras or '*' in extras):
                    found.update(walk(value,names,funcs))
            return found
        for child in ast.iter_child_nodes(node):found.update(walk(child,names,funcs))
        return found

    roots=[]
    for node in ast.walk(tree):
        if isinstance(node,ast.Call) and getattr(node.func,'id',None)=='setup':
            for kw in node.keywords:
                if kw.arg in {'install_requires','setup_requires'}:
                    roots.append(kw.value)
                elif kw.arg=='extras_require':
                    if isinstance(kw.value,ast.Dict):
                        for key,value in zip(kw.value.keys,kw.value.values):
                            group=key.value if isinstance(key,ast.Constant) else None
                            if isinstance(group,str) and (group in extras or '*' in extras):roots.append(value)
                    else:
                        roots.append(kw.value)
                elif kw.arg is None:
                    roots.append(kw.value)
        if isinstance(node,ast.Assign):
            for target in node.targets:
                if (isinstance(target,ast.Subscript) and isinstance(target.slice,ast.Constant)
                        and target.slice.value in {'install_requires','setup_requires'}):roots.append(node.value)
                if (isinstance(target,ast.Subscript) and isinstance(target.slice,ast.Constant)
                        and target.slice.value=='extras_require'):roots.append(node.value)
    found=set()
    for root in roots:found.update(walk(root))
    return found


def setup_requirements_from_sources(source, get_file, *, extras=(), python_version=None, setup_argv=None):
    """Resolve safe setuptools metadata and literal file-backed dependencies."""
    deps, issues = setup_static(source, extras=extras, get_file=get_file, python_version=python_version, setup_argv=setup_argv)
    vcs=set()
    if not source or get_file is None or not issues:
        return deps,vcs,issues
    files=_setup_dependency_files(source,extras=extras)
    if not files:
        return deps,vcs,issues
    parsed_any=False
    for name in sorted(files):
        try:data=get_file(name,required=True)
        except (OSError,RuntimeError,ValueError) as exc:
            return deps,vcs,[*issues,'unable to read dependency metadata '+name+': '+str(exc)]
        if not isinstance(data,str):
            return deps,vcs,[*issues,'dependency metadata is not text: '+name]
        try:normal,remote,limits=parse_requirements(data,name,get_file)
        except (OSError,RuntimeError,ValueError) as exc:
            return deps,vcs,[*issues,'invalid dependency metadata '+name+': '+str(exc)]
        if limits:
            return deps,vcs,[*issues,'constraints are not valid install metadata: '+name]
        deps.update(normal);vcs.update(remote);parsed_any=True
    if not parsed_any:
        return deps,vcs,issues
    # A literal filename is not proof that an arbitrary helper returns its
    # contents unchanged or that every unresolved field has been evaluated.
    # Retain diagnostics until the exact expression is statically understood.
    return deps,vcs,issues


def git_requirements(mirror, commit, *, python_version=None):
    """Combine all declarative metadata sources, including tool-only pyprojects."""
    get_file = lambda path, required=False: git_file(mirror, commit, path, required=required)
    specs, vcs, issues = set(), set(), []
    pyproject = get_file('pyproject.toml')
    if pyproject:
        try:
            deps, remote, errors = static_project(pyproject)
            specs.update(deps); vcs.update(remote); issues.extend(errors)
        except (ValueError, TypeError) as exc:
            issues.append('invalid VCS pyproject.toml: '+str(exc))
    cfg, errors = setup_cfg_static(get_file('setup.cfg'))
    specs.update(cfg); issues.extend(errors)
    source = get_file('setup.py')
    if source:
        deps, remote, errors = setup_requirements_from_sources(
            source, get_file, python_version=python_version)
        specs.update(deps); vcs.update(remote); issues.extend(errors)
    if not (pyproject or source or get_file('setup.cfg')):
        issues.append('VCS source lacks Python build metadata')
    return specs, vcs, issues


def shell_segments(line):
    """Split shell operators without confusing quoted words with syntax."""
    tokens=_quoted_shell_tokens(line)
    segments=[];current=[];previous=None
    for raw in tokens:
        if raw in (';','\n','&&','||','|','&','|&'):
            if current:segments.append((current,previous,raw));current=[]
            previous=raw
        else:
            parsed=shlex.split(raw,posix=True)
            if len(parsed)!=1:raise ValueError('unsupported compound shell word')
            current.append(parsed[0])
    if current:segments.append((current,previous,None))
    return segments


def setup_script_invocations(commands):
    """Derive setup.py argv identities from the pinned official install stream."""
    invocations=[];local_pip=False
    for line in commands:
        for tokens,_previous,_next in shell_segments(line):
            position=_literal_command_index(tokens)
            if position>=len(tokens):continue
            executable=Path(tokens[position]).name
            if (re.fullmatch(r'python(?:3(?:\.\d+)?)?',executable)
                    and position+1<len(tokens) and Path(tokens[position+1]).name=='setup.py'):
                invocations.append(tuple(['setup.py',*tokens[position+2:]]));continue
            pip_position=None
            if executable in ('pip','pip3') and position+1<len(tokens) and tokens[position+1]=='install':
                pip_position=position
            elif (re.fullmatch(r'python(?:3(?:\.\d+)?)?',executable)
                    and tokens[position+1:position+3]==['-m','pip']
                    and position+3<len(tokens) and tokens[position+3]=='install'):
                pip_position=position+2
            if pip_position is None:continue
            parts=tokens[pip_position+2:]
            for index,item in enumerate(parts):
                if item in ('.','./') or item.startswith('.['):local_pip=True
                if item in ('-e','--editable','-ve','-ev') and index+1<len(parts):
                    target=parts[index+1]
                    if target in ('.','./') or target.startswith('.['):local_pip=True
    if local_pip:invocations.append(('setup.py','egg_info'))
    if not invocations:invocations.append(('setup.py','egg_info'))
    return tuple(dict.fromkeys(invocations))


def _literal_command_index(tokens):
    position=0
    while position<len(tokens) and re.match(r'^[A-Za-z_][A-Za-z_0-9]*=',tokens[position]):position+=1
    if position<len(tokens) and tokens[position]=='sudo':
        position+=1
        if position<len(tokens) and tokens[position] in ('-n','--non-interactive'):position+=1
    return position


def pip_commands(commands):
    """Parse ordered pip installs, preserving shell optionality and --no-deps."""
    specs, files, vcs, issues, local_extras, constraints, steps = set(), set(), set(), [], set(), set(), []
    for line in commands:
        try:
            segments=shell_segments(line)
        except (ValueError,RuntimeError):
            issues.append('unparseable shell command')
            continue
        for index,(tokens,previous,next_operator) in enumerate(segments):
            pip_index=None
            position=_literal_command_index(tokens)
            for pos in range(position,min(position+1,len(tokens))):
                token=tokens[pos]
                base=Path(token).name
                if base in ('pip','pip3') and pos+1 < len(tokens) and tokens[pos+1]=='install':
                    pip_index=pos
                    break
                if (base in ('python','python3') or re.fullmatch(r'python3\.\d+',base)) and pos+3 < len(tokens):
                    if tokens[pos+1:pos+3]==['-m','pip'] and tokens[pos+3]=='install':
                        pip_index=pos+2
                        break
            if pip_index is None:
                continue
            start = pip_index + 2
            parts=tokens[start:]
            optional = False
            if next_operator == '||' and index + 1 < len(segments):
                follower=segments[index+1][0]
                optional = follower in (['true'], [':'])
            ss, ff, vv, cc, ee = set(), set(), set(), set(), set()
            no_deps = False
            local_project = False
            i = 0
            while i < len(parts):
                arg = parts[i]
                if arg == '--no-deps':
                    no_deps = True; i += 1; continue
                if arg in ('-r', '--requirement', '-c', '--constraint'):
                    if i + 1 >= len(parts): issues.append('pip requirements filename absent'); break
                    (cc if arg in ('-c', '--constraint') else ff).add(parts[i+1]); i += 2; continue
                if arg.startswith('-r') and len(arg) > 2: ff.add(arg[2:]); i += 1; continue
                if arg.startswith('-c') and len(arg) > 2 and not arg.startswith('-config'):
                    cc.add(arg[2:]); i += 1; continue
                if arg in ('-e', '--editable', '-ve', '-ev'):
                    if i + 1 >= len(parts): issues.append('editable dependency missing'); break
                    target = parts[i+1]
                    ref = vcs_reference(target)
                    if ref: vv.add(ref)
                    elif target in ('.', './') or re.fullmatch(r'\./?\[[^]\n]+\]', target):
                        local_project = True
                        if '[' in target:
                            match=re.findall(r'\[([^]]+)\]', target)
                            if match: ee.update(t.strip() for t in match[0].split(',') if t.strip())
                    else: issues.append('unknown editable target ' + target)
                    i += 2; continue
                if arg in ('--no-build-isolation', '--no-use-pep517', '--upgrade',
                           '-U', '-q', '--quiet', '-v', '--verbose', '--prefer-binary',
                           '--no-warn-script-location', '--no-input'):
                    i += 1; continue
                if arg in ('--config-settings', '--upgrade-strategy', '--index-url', '--extra-index-url'):
                    if i + 1 >= len(parts): issues.append('pip option value absent: '+arg); break
                    if arg in ('--index-url', '--extra-index-url'):
                        issues.append('untrusted custom package index: ' + arg)
                    i += 2; continue
                if arg.startswith(('-C', '--config-settings=')):
                    i += 1; continue
                if arg.startswith('-'):
                    issues.append('unresolved pip option ' + arg); break
                if arg in ('.', './') or re.fullmatch(r'\./?\[[^]\n]+\]', arg):
                    local_project = True
                    if '[' in arg:
                        ee.update(value.strip() for value in arg.split('[', 1)[1][:-1].split(',')
                                  if value.strip())
                    i += 1; continue
                if arg.startswith(('./', '../', '/')):
                    issues.append('local dependency requires its own source identity: ' + arg)
                    i += 1; continue
                ref = vcs_reference(arg)
                if ref: vv.add(ref)
                elif arg.startswith(('https://', 'http://')):
                    issues.append('unresolved remote pip target ' + arg)
                else: ss.add(arg)
                i += 1
            specs.update(ss); files.update(ff); vcs.update(vv)
            constraints.update(cc); local_extras.update(ee)
            command = shlex.join(tokens[pip_index-2 if pip_index>=2 and tokens[pip_index-2:pip_index]==['-m','pip'] else pip_index:])
            steps.append({'requirements': ss, 'files': ff, 'constraints': cc,
                           'vcs': vv, 'local_extras': ee, 'no_deps': no_deps,
                           'local_project': local_project,
                           'optional': optional, 'command': command})
    return specs, files, vcs, issues, local_extras, constraints, steps



def make_commands(text, target, *, visiting=None):
    visiting=set() if visiting is None else visiting
    if target in visiting:raise RuntimeError('recursive Make dependency')
    visiting.add(target)
    rows={};current=None
    for line in text.splitlines():
        m=re.match(r'^([A-Za-z0-9_.-]+)\s*:\s*([^#]*)(?:#.*)?$',line)
        if m:current=m.group(1);rows[current]=(m.group(2).split(),[])
        elif line.startswith('\t') and current:
            rows[current][1].append(line[1:].lstrip('@-+'))
        elif line and not line.startswith((' ', '#')):current=None
    if target not in rows:raise RuntimeError('Make target not defined: '+target)
    commands=[]
    for dependency in rows[target][0]:
        if dependency in rows:commands+=make_commands(text,dependency,visiting=visiting.copy())
    return commands+rows[target][1]


def github_repository(url):
    """Canonicalize the finite HTTPS GitHub repository URL forms accepted as inputs."""
    if not isinstance(url,str):
        raise ValueError('Git repository URL must be text')
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme!='https' or parsed.netloc!='github.com' or parsed.query or parsed.fragment:
        raise ValueError('unsupported GitHub repository URL')
    repository=parsed.path.removeprefix('/').removesuffix('/')
    repository=repository.removesuffix('.git')
    if not REPO.fullmatch(repository):
        raise ValueError('unsupported GitHub repository path')
    return repository


def _git_submodule_entries(mirror, commit):
    """Read pinned gitlinks and their named HTTPS origins without executing project code.

    The names are necessary to override Git's submodule transport with the
    independently acquired, commit-verified local mirror.  Never trust
    .gitmodules to select a network destination during metadata evaluation.
    """
    from pathlib import PurePosixPath

    content = git_file(mirror, commit, '.gitmodules')
    if content is None:
        return ()
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(content)
    except configparser.Error as exc:
        raise RuntimeError('invalid pinned Git submodule configuration') from exc
    entries = []
    names, paths = set(), set()
    for section in parser.sections():
        match = re.fullmatch(r'submodule "([^"\x00-\x1f\x7f]+)"', section)
        if match is None:
            raise RuntimeError('unsupported pinned Git submodule section')
        name = match.group(1)
        path = parser.get(section, 'path', fallback='')
        url = parser.get(section, 'url', fallback='')
        normalized = PurePosixPath(path)
        if (not path or path.startswith('/') or '\\' in path
                or normalized.as_posix() != path
                or any(part in ('..', '.git') for part in normalized.parts)
                or not normalized.parts or any(ord(c) < 32 or ord(c) == 127 for c in path)
                or name in names or path in paths):
            raise RuntimeError('unsafe or ambiguous pinned Git submodule path/name')
        try:
            repository = github_repository(url)
        except (TypeError, ValueError) as exc:
            raise RuntimeError('unsupported Git submodule URL: ' + str(url)) from exc
        raw = invoke(['git', '--git-dir', mirror, 'ls-tree', commit, '--', path], capture=True).strip()
        expected = re.fullmatch(r'160000 commit ([0-9a-f]{40})\t(.+)', raw)
        if expected is None or expected.group(2) != path:
            raise RuntimeError('pinned Git submodule is not a matching gitlink: ' + path)
        names.add(name)
        paths.add(path)
        entries.append((name, path, repository, expected.group(1)))
    return tuple(sorted(entries, key=lambda entry: entry[1]))


def read_submodules(mirror, commit):
    """Preserve the existing public, direct-submodule tuple contract."""
    return [(path, repo, sha) for _name, path, repo, sha
            in _git_submodule_entries(mirror, commit)]


def _acquire_nested_submodules(stage, gitplan):
    """Acquire all transitive gitlinks and record their immutable identities.

    Level-order traversal batches independently pinned repositories while
    rejecting cycles, conflicts, and unbounded graphs.  No branch or implicit
    submodule URL is followed.
    """
    frontier = []
    identities = set()
    for root, plan in sorted(gitplan.items()):
        for path, value in sorted(plan['submodules'].items()):
            for commit in sorted(value['commits']):
                node = (value['repo'], commit)
                frontier.append((root, path, node, (node,)))
                identities.add(node)
    if len(identities) > MAX_VCS_CLOSURE:
        raise RuntimeError('pinned submodule graph exceeds its closure bound')
    seen = set()
    while frontier:
        required = defaultdict(set)
        following = []
        for root, prefix, node, ancestry in frontier:
            repo, commit = node
            visit = (root, prefix, repo, commit)
            if visit in seen:
                continue
            seen.add(visit)
            mirror = stage / 'git-extra' / (repo.replace('/', '_') + '.git')
            if mirror.is_symlink() or not mirror.is_dir():
                raise RuntimeError('pinned submodule mirror is missing or unsafe: ' + repo)
            for path, subrepo, sha in read_submodules(mirror, commit):
                child = (subrepo, sha)
                if child in ancestry:
                    raise RuntimeError('cyclic pinned Git submodule graph')
                full_path = prefix + '/' + path
                record = gitplan[root]['submodules'].setdefault(
                    full_path, {'repo': subrepo, 'commits': []})
                if record['repo'] != subrepo:
                    raise RuntimeError('nested submodule path changes repository identity: ' + full_path)
                if sha not in record['commits']:
                    record['commits'].append(sha)
                identities.add(child)
                if len(identities) > MAX_VCS_CLOSURE:
                    raise RuntimeError('pinned submodule graph exceeds its closure bound')
                required[subrepo].add(sha)
                following.append((root, full_path, child, (*ancestry, child)))
        if required:
            _acquire_git_mirrors(stage, required, label='git-extra')
        frontier = following


def _sed_basic_regex_to_python(pattern):
    """Translate the finite GNU sed BRE surface used by pinned recipes."""
    out=[];i=0
    while i<len(pattern):
        char=pattern[i]
        if char=='\\' and i+1<len(pattern):
            nxt=pattern[i+1]
            # BRE makes these operators special only when escaped.
            if nxt in '+?|(){}':out.append(nxt)
            else:out.append('\\'+nxt)
            i+=2;continue
        # In BRE these are literals unless escaped; Python treats them special.
        if char in '+?|(){}':out.append('\\'+char)
        else:out.append(char)
        i+=1
    return ''.join(out)


def _sed_substitution(expression, value, *, extended=False):
    """Apply bounded sed substitution/delete/insert forms used by pinned recipes."""
    if not expression:raise RuntimeError('empty dependency-file sed expression')
    if expression.startswith('s') and len(expression)>2:
        delimiter=expression[1]
        if delimiter.isalnum() or delimiter in {'\\','\n','\r'}:
            raise RuntimeError('unsupported sed substitution delimiter')
        parts=[];current=[];escaped=False
        for char in expression[2:]:
            if escaped:
                # Preserve the escape for regex/replacement semantics, except for
                # an escaped delimiter which only quotes the field separator.
                current.append(char if char==delimiter else '\\'+char);escaped=False;continue
            if char=='\\':escaped=True;continue
            if char==delimiter and len(parts)<2:
                parts.append(''.join(current));current=[];continue
            current.append(char)
        if escaped:current.append('\\')
        if len(parts)!=2:raise RuntimeError('unsupported sed substitution expression: '+expression)
        flags=''.join(current)
        if flags not in ('','g'):raise RuntimeError('unsupported sed substitution flags: '+flags)
        pattern=parts[0] if extended else _sed_basic_regex_to_python(parts[0])
        replacement=parts[1]
        def replace(match):
            out=[];index=0
            while index<len(replacement):
                char=replacement[index]
                if char=='&':out.append(match.group(0))
                elif char=='\\':
                    index+=1
                    if index==len(replacement):raise RuntimeError('incomplete sed replacement escape')
                    escaped=replacement[index]
                    if escaped.isdigit():out.append(match.group(int(escaped)) or '')
                    elif escaped in ('&','\\'):out.append(escaped)
                    elif escaped=='n':out.append('\n')
                    else:raise RuntimeError('unsupported sed replacement escape: '+escaped)
                else:out.append(char)
                index+=1
            return ''.join(out)
        try:
            output=[]
            for line in re.findall(r'[^\n]*\n|[^\n]+$', value):
                newline='\n' if line.endswith('\n') else ''
                content=line[:-1] if newline else line
                output.append(re.sub(pattern,replace,content,count=0 if flags=='g' else 1)+newline)
            return ''.join(output)
        except re.error as exc:raise RuntimeError('invalid sed dependency substitution') from exc
    delete=re.fullmatch(r'/((?:\\.|[^/])*)/d',expression)
    if delete:
        pattern=delete.group(1).replace('\\/','/')
        if not extended:pattern=_sed_basic_regex_to_python(pattern)
        try:return '\n'.join(line for line in value.split('\n') if re.search(pattern,line) is None)
        except re.error as exc:raise RuntimeError('invalid sed dependency deletion') from exc
    insert=re.fullmatch(r'1i(?:\\)?\s*(.*)',expression)
    if insert:return insert.group(1)+'\n'+value
    raise RuntimeError('unsupported dependency-file sed expression: '+expression)


def _quoted_shell_tokens(command):
    lexer=shlex.shlex(command,posix=False,punctuation_chars=';&|<>\n')
    lexer.whitespace=' \t\r'
    lexer.whitespace_split=True
    lexer.commenters=''
    try:return list(lexer)
    except ValueError as exc:raise RuntimeError('invalid shell quoting in dependency-file recipe') from exc


def _literal_shell_word(word):
    if word.startswith("'") and word.endswith("'"):
        return word[1:-1]
    if any(char in word for char in ('$', '`', '\\')):
        raise RuntimeError('dynamic echo content or shell word cannot be resolved statically')
    parts=shlex.split(word,posix=True)
    if len(parts)!=1:raise RuntimeError('unsupported compound shell word')
    return parts[0]


def literal_echo_appends(command):
    """Yield literal standalone echo appends, retaining quoted operator identity."""
    segment=[]
    for token in [*_quoted_shell_tokens(command),';']:
        if token not in {';','\n','&&','||','|','&','|&','{','}'}:
            segment.append(token);continue
        if len(segment)==4 and segment[0]=='echo' and segment[2]=='>>':
            yield _literal_shell_word(segment[1]),_literal_shell_word(segment[3])
        segment=[]


def _literal_dependency_file_guard(segment, normalized, exists):
    """Evaluate only literal file-existence tests for the dependency file in scope."""
    if not segment:return None
    try:words=[_literal_shell_word(word) for word in segment]
    except RuntimeError:return None
    candidate=None
    if len(words)==4 and words[0]=='[' and words[3]==']' and words[1] in ('-f','-e'):
        candidate=words[2]
    elif len(words)==3 and words[0]=='test' and words[1] in ('-f','-e'):
        candidate=words[2]
    if candidate is None:return None
    target=Path(candidate).as_posix().removeprefix('./')
    if target!=normalized:return None
    return bool(exists)


def transformed_source(repo, path, value, commands):
    """Interpret a finite literal edit surface in its original command order.

    Quoted command-looking strings never become executable edits. Literal
    existence guards for the exact dependency file are evaluated from the
    pinned Git snapshot; every other conditional remains fail-closed.
    No recipe or external source is executed by this interpreter.
    """
    del repo
    normalized=Path(path).as_posix().removeprefix('./')
    result=value
    def matches(word):
        return Path(_literal_shell_word(word)).as_posix().removeprefix('./')==normalized
    def conditional_allows(previous,guard):
        if previous in (None,';','\n'):return True
        if previous=='&&' and guard is not None:return guard
        if previous=='||' and guard is not None:return not guard
        raise RuntimeError('conditional dependency-file edit cannot be resolved statically')
    def apply(segment,previous,guard):
        nonlocal result
        if not segment:return
        if segment[0]=='sed':
            words=[_literal_shell_word(word) for word in segment]
            if not any(Path(word).as_posix().removeprefix('./')==normalized for word in words[1:]):return
            if not conditional_allows(previous,guard):return
            extended=len(words)>1 and words[1] in ('-E','--regexp-extended')
            offset=2 if extended else 1
            if len(words)!=offset+3 or words[offset]!='-i' or words[-1]!=normalized:
                raise RuntimeError('unsupported dependency-file sed invocation')
            if result is None:raise RuntimeError('sed dependency file does not exist')
            result=_sed_substitution(words[offset+1],result,extended=extended)
            return
        for index,word in enumerate(segment):
            if word not in ('>','>>') or index+1==len(segment) or not matches(segment[index+1]):continue
            if len(segment)!=4 or segment[0]!='echo' or index!=2:
                raise RuntimeError('unsupported dependency-file redirection')
            if not conditional_allows(previous,guard):return
            text=_literal_shell_word(segment[1])
            if text.startswith('-') or '\\' in text:
                raise RuntimeError('implementation-dependent echo semantics')
            if word=='>':result=text+'\n'
            else:result=(result or '')+text+'\n'
            return
    for command in commands:
        tokens=_quoted_shell_tokens(command);segment=[];previous=None;guard=None;index=0
        while index<len(tokens):
            token=tokens[index]
            if token=='{':
                current_guard=_literal_dependency_file_guard(segment,normalized,result is not None)
                apply(segment,previous,guard);segment=[];guard=current_guard
                try:end=tokens.index('}',index+1)
                except ValueError:raise RuntimeError('unclosed shell group')
                if end+2<len(tokens) and tokens[end+1] in ('>','>>') and matches(tokens[end+2]):
                    body=[_literal_shell_word(word) if word not in ('|','&&',';') else word
                          for word in tokens[index+1:end]]
                    expected=['tail','-n1',normalized,'|','grep','-q','.','&&','echo','',';']
                    if body!=expected or tokens[end+1]!='>>':
                        raise RuntimeError('unsupported dependency-file group redirection')
                    # Exact semantics of the bounded tail/grep/echo newline guard.
                    lines=(result or '').split('\n')
                    last=lines[-2] if result and result.endswith('\n') else lines[-1]
                    if last:result=(result or '')+'\n'
                    index=end+3;previous=';';guard=None;continue
                # A group with no outer redirection still requires control-flow
                # interpretation; do not silently apply an edit inside it.
                body=tokens[index+1:end]
                if any(word in ('sed','echo','printf','cat') for word in body):
                    if any(word.strip("\"'").removeprefix('./')==normalized for word in body):
                        raise RuntimeError('unsupported dependency-file shell group')
                index=end+1;previous=';';guard=None;continue
            if token in {';','\n','&&','||','|','&','|&'}:
                current_guard=_literal_dependency_file_guard(segment,normalized,result is not None)
                apply(segment,previous,guard);segment=[];guard=current_guard;previous=token
            else:segment.append(token)
            index+=1
        apply(segment,previous,guard)
    return result


def conda_yaml(script):
    for command in script:
        match=re.search(r"cat <<'([^']+)' > environment\.yml\n(.*?)\n\1(?:\n|$)",command,re.S)
        if match:return match.group(2)+'\n'
    return None


def conda_pip_split(content):
    lines=content.splitlines(keepends=True); out=[];pip=[];inside=False
    for line in lines:
        if re.match(r'^\s+- pip:\s*$',line):inside=True;continue
        if inside and re.match(r'^\s{4,}-\s*',line):pip.append(line.split('-',1)[1].strip());continue
        if inside and (not line.strip() or line.lstrip().startswith('#')):continue
        inside=False;out.append(line)
    return ''.join(out),pip


def _conda_python_minor(spec):
    """Return a Python major.minor only for an actual Conda package spec."""
    value=str(spec).strip()
    match=re.fullmatch(r'python(?:\s*[=<>!~]+\s*|\s+)(\d+\.\d+)(?:\.\d+|\.\*)?(?:[^\s]*)?',value,re.I)
    return match.group(1) if match else None


def _yaml_python_minor(content):
    if content is None:return None
    found=[]
    for line in content.splitlines():
        # Match a dependency item named exactly "python".  Names such as
        # meson-python must never be interpreted as interpreter constraints.
        match=re.match(r'^\s*-\s+python\s*(?:=|\s)\s*(\d+\.\d+)(?:\.\d+|\.\*)?(?:\s|#|$)',line,re.I)
        if match:found.append(match.group(1))
    if len(set(found))>1:
        raise RuntimeError('Conda YAML contains conflicting Python constraints')
    return found[-1] if found else None


def python_version(script):
    """Return the final Python minor from structured Conda recipe operations."""
    version=_yaml_python_minor(conda_yaml(script))
    direct=conda_direct_specs(script)
    if direct:
        direct_versions=[item for item in (_conda_python_minor(spec) for spec in direct) if item]
        if len(set(direct_versions))>1:
            raise RuntimeError('direct Conda create has conflicting Python constraints')
        if direct_versions:version=direct_versions[-1]
    for transaction in conda_post_install_specs(script):
        selected=[item for item in (_conda_python_minor(spec) for spec in transaction) if item]
        if len(set(selected))>1:
            raise RuntimeError('Conda install transaction has conflicting Python constraints')
        if selected:version=selected[-1]
    if version is None:
        raise RuntimeError('Conda environment has no Python constraint')
    return version


def conda_direct_specs(script):
    """Return literal package specs from a direct `conda create -n testbed ...`."""
    found=[]
    for command in script:
        try: segments=shell_segments(command)
        except ValueError: continue
        for tokens,_,_ in segments:
            if not tokens or Path(tokens[0]).name != 'conda' or len(tokens)<2 or tokens[1] != 'create':
                continue
            specs=[];i=2
            while i < len(tokens):
                token=tokens[i]
                if token in ('-n','--name','-p','--prefix'):
                    i += 2; continue
                if token in ('-y','--yes','-q','--quiet'):
                    i += 1; continue
                if token.startswith('-'):
                    raise RuntimeError('unsupported direct Conda create option: '+token)
                specs.append(token);i+=1
            if specs: found.append(specs)
    if len(found)>1: raise RuntimeError('multiple direct Conda create commands in one environment')
    return found[0] if found else None


def conda_post_install_specs(script):
    """Return package specs from literal post-create `conda install` transactions."""
    result=[]
    for command in script:
        try: segments=shell_segments(command)
        except ValueError: continue
        for tokens,_,_ in segments:
            pos=_literal_command_index(tokens)
            if pos+1>=len(tokens) or Path(tokens[pos]).name!='conda' or tokens[pos+1]!='install':continue
            specs=[];i=pos+2
            while i<len(tokens):
                token=tokens[i]
                if token in ('-n','--name','-p','--prefix'):
                    i+=2;continue
                if token in ('-y','--yes','-q','--quiet'):
                    i+=1;continue
                if token.startswith('-'):
                    raise RuntimeError('unsupported post-create Conda option: '+token)
                specs.append(token);i+=1
            if specs: result.append(specs)
    return result



def apt_recipe_operations(commands):
    """Extract install package names and upgrade intent from literal apt-get calls."""
    packages=set(); upgrades=[]
    for command in commands:
        try: segments=shell_segments(command)
        except ValueError:
            raise RuntimeError('unparseable APT shell command')
        for tokens,_,_ in segments:
            position=_literal_command_index(tokens)
            for pos in range(position,min(position+1,len(tokens))):
                token=tokens[pos]
                if Path(token).name != 'apt-get':
                    continue
                i=pos+1
                while i<len(tokens) and tokens[i].startswith('-'):
                    # All task recipes use flag-only options before the verb.
                    if tokens[i] in ('-o','--option'):
                        if i+1>=len(tokens): raise RuntimeError('APT option value absent')
                        i+=2
                    else:i+=1
                if i>=len(tokens): raise RuntimeError('APT operation absent')
                verb=tokens[i];rest=tokens[i+1:]
                if verb=='install':
                    j=0
                    while j<len(rest):
                        value=rest[j]
                        if value in ('-o','--option'):
                            j+=2;continue
                        if value.startswith('-'):
                            j+=1;continue
                        if not re.fullmatch(r'[A-Za-z0-9+._:-]+',value):
                            raise RuntimeError('untrusted APT package token: '+value)
                        packages.add(value);j+=1
                elif verb in ('upgrade','dist-upgrade','full-upgrade'):
                    upgrades.append(verb)
                elif verb in ('update','clean','autoclean'):
                    pass
                else:
                    raise RuntimeError('unsupported apt-get operation: '+verb)
    return packages,upgrades


class Pool:
    def __init__(self, stage):
        self.stage = Path(stage)
        self.objects = self.stage / 'objects' / 'sha256'
        self.objects.mkdir(parents=True,exist_ok=True)
        self.links = {}
        self.provenance = {}
        self.issues = []
        # Per-attempt indexes are rebuilt from verified retained content.
        self.by_url = {}
        self.by_sri = {}
        self.sri_verified = set()
        self.verified_objects = set()  # SHA-256 verified at acquisition or recovery
        self._verified_signatures = {}
        # Pip closures run concurrently. Mutable provenance/CAS indexes remain
        # process-local and are protected independently from network transfer.
        self._state_lock = threading.RLock()
        self._download_locks = {}
        # One ephemeral pip HTTP cache for the whole worker. It is deliberately
        # outside the staged pool and therefore can never become a published
        # dependency. Cross-group artifact reuse itself is handled by the CAS.
        self._pip_cache_context = tempfile.TemporaryDirectory(prefix='swegym-pip-cache-')
        self.pip_cache = Path(self._pip_cache_context.name)

    def verify_object(self, sha):
        """Reuse a digest only while the verified file identity remains unchanged."""
        if not isinstance(sha, str) or not SHA.fullmatch(sha):
            raise RuntimeError('invalid CAS SHA-256 identity')
        with self._state_lock:
            target = self.objects / sha[:2] / sha
            if target.parent.is_symlink():raise RuntimeError('unsafe CAS directory')
            info = target.lstat()
            if not stat.S_ISREG(info.st_mode):raise RuntimeError('unsafe CAS object')
            def signature(value):
                return (value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
            current = signature(info)
            if self._verified_signatures.get(sha) != current:
                if digest(target) != sha:raise RuntimeError('CAS bytes fail SHA-256 verification: '+sha)
                if signature(target.lstat()) != current:raise RuntimeError('CAS changed during verification')
                self._verified_signatures[sha] = current
            self.verified_objects.add(sha)
            return info.st_size

    def reference(self, sha, category, identity, size):
        with self._state_lock:
            target = self.objects / sha[:2] / sha
            if self.verify_object(sha) != size:
                raise RuntimeError('missing/invalid content-addressed dependency')
            self.links.setdefault(sha, {'path': target.relative_to(self.stage).as_posix(),
                                        'size': size, 'sha256': sha})
            refs = self.provenance.setdefault(category, {}).setdefault(identity, [])
            if sha not in refs:
                refs.append(sha)
            return sha

    def put(self, path, category, identity, *, verified_sha=None, durable=False):
        """Register one immutable artifact with a content-addressed hardlink.

        A digest is computed here only for third-party tools' output. Direct
        downloads already supplied their SHA-256 during streaming.
        """
        path = Path(path)
        if path.is_symlink() or not path.is_file():
            raise RuntimeError('unsafe downloaded artifact: ' + str(path))
        sha = verified_sha if verified_sha is not None else digest(path)
        if not SHA.fullmatch(sha):
            raise RuntimeError('invalid artifact SHA-256')
        size = path.stat().st_size
        with self._state_lock:
            target = self.objects / sha[:2] / sha
            target.parent.mkdir(exist_ok=True)
            if not target.exists():
                os.link(path, target)
            elif target.is_symlink() or not target.is_file() or target.stat().st_size != size:
                raise RuntimeError('content-addressed pool collision/changed object')
            if durable:
                # Persist the CAS hardlink before deleting its staging source.
                # Completed bytes survive ordinary worker/process failures.
                descriptor=os.open(target.parent,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:os.fsync(descriptor)
                finally:os.close(descriptor)
            self.verified_objects.add(sha)
            return self.reference(sha, category, identity, size)

    def coalesce_stage_file(self, path, sha):
        """Coalesce completed, disposable acquisition files immediately.

        Never use on writable Git refs, logs, or other mutable application state.
        The broker alone performs final verification and publishes ready/.
        """
        path = Path(path)
        target = self.objects / sha[:2] / sha
        if path.samefile(target):
            return
        import secrets
        temporary = path.parent / ('.pool-link-' + secrets.token_hex(16))
        os.link(target, temporary)
        try:
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()

    def download(self, url, category, identity, *, sha=None, sri=None):
        """Serialize shared content identities, including aliases at different URLs."""
        if sha is not None and (not isinstance(sha, str) or not SHA.fullmatch(sha)):
            raise RuntimeError('invalid expected artifact SHA-256')
        identities = {('url', url)}
        if sha is not None:
            identities.add(('sha256', sha))
        identities.update((algorithm, value.hex()) for algorithm, value in (sri_parts(sri) or ()))
        with self._state_lock:
            locks = [self._download_locks.setdefault(key, threading.Lock())
                     for key in sorted(identities)]
        with contextlib.ExitStack() as stack:
            for lock in locks:
                stack.enter_context(lock)
            return self._download_url_locked(url, category, identity, sha=sha, sri=sri)

    def _download_url_locked(self, url, category, identity, *, sha=None, sri=None):
        """Download once by SHA-256, SRI or URL, then share by reference.

        Trust a known digest before fetching bytes. If a URL is requested again
        under another task/recipe, record another reference instead of refetching.
        Distinct URLs with the same SRI share their existing content as well.
        """
        if sha is not None and not SHA.fullmatch(str(sha)):
            raise RuntimeError('invalid expected artifact SHA-256')
        sri_value = tuple(sri_parts(sri) or ())
        with self._state_lock:
            cached = None
            if sha is not None and (self.objects / sha[:2] / sha).is_file():
                cached = sha
            elif sri_value:
                for item in sri_value:
                    if item in self.by_sri:
                        cached = self.by_sri[item]
                        break
            elif url in self.by_url:
                cached = self.by_url[url]
            # Even when the known digest is new, a previously fetched URL may exist.
            if cached is None:
                cached = self.by_url.get(url)
        if cached is not None:
            target = self.objects / cached[:2] / cached
            self.verify_object(cached)
            if sha is not None and cached != sha:
                raise RuntimeError('conflicting expected checksum for existing download URL/SRI')
            target = self.objects / cached[:2] / cached
            matched_sri = verify_sri(target, sri) if sri_value else ()
            with self._state_lock:
                self.verified_objects.add(cached)
                if sri_value:
                    self.sri_verified.update((cached, part) for part in matched_sri)
                self.by_url[url] = cached
                for part in matched_sri:
                    existing = self.by_sri.setdefault(part, cached)
                    if existing != cached:
                        raise RuntimeError('conflicting SRI artifact identity')
            return self.reference(cached, category, identity, target.stat().st_size)

        # Independent of task/category: one stable URL gets one acquisition path.
        raw = self.stage / 'downloads' / hashlib.sha256(url.encode()).hexdigest()
        raw.parent.mkdir(exist_ok=True)
        known_hashes = {}
        # A URL-based old download can be reused ONLY when an independent
        # pinned digest/SRI verifies it. Unpinned bytes are fetched anew.
        actual = None
        if raw.exists() or raw.is_symlink():
            if raw.is_symlink() or not raw.is_file():
                raise RuntimeError('unsafe retained URL download')
            if sha is not None or sri is not None:
                candidate = digest(raw)
                try:
                    if (sha is not None and sha != candidate):
                        raise ValueError('retained checksum mismatch')
                    if sri is not None: verify_sri(raw,sri)
                except (ValueError,RuntimeError):
                    raw.unlink()  # Only our new, private candidate stage.
                else:
                    actual = candidate
            else:
                raw.unlink()
        if actual is None:
            actual = fetch(url, raw, sha=sha, sri=sri, integrity_digests=known_hashes)
        matched_sri = verify_sri(raw, sri) if sri_value else ()
        self.put(raw, category, identity, verified_sha=actual)
        self.coalesce_stage_file(raw, actual)
        with self._state_lock:
            self.by_url[url] = actual
            for algo, binary in [('sha256', bytes.fromhex(actual)), *known_hashes.items()]:
                token = (algo, binary)
                existing = self.by_sri.setdefault(token, actual)
                if existing != actual:
                    raise RuntimeError('conflicting content-addressed identity')
                self.sri_verified.add((actual, token))
            for part in matched_sri:
                existing = self.by_sri.setdefault(part, actual)
                if existing != actual:
                    raise RuntimeError('conflicting SRI artifact identity')
                self.sri_verified.add((actual, part))
        return actual

    def issue(self, where, description):
        self.issues.append(f'{where}: {description}')


# GPT_TRACE_SWEGYM_VERIFIED_RESUME_V1
# Copy a FAILED stage into a fresh candidate. Never modify the original.
def salvage_verified_stage(old, new, *, conda_artifacts=None):
    old, new = Path(old), Path(new)
    if (old.resolve()==new.resolve() or new.resolve().is_relative_to(old.resolve())
            or old.resolve().is_relative_to(new.resolve())):
        raise RuntimeError('source and candidate recovery stages must be distinct')
    if old.is_symlink() or not old.is_dir() or new.is_symlink():
        raise RuntimeError('unsafe interrupted dependency pool')
    if not (old/'STAGING').is_file() or (old/'STAGING').is_symlink():
        raise RuntimeError('unidentified interrupted dependency pool')
    # Check all paths before copying, including files we do not plan to reuse.
    # A mount/symlink/device may not redirect the trusted downloader elsewhere.
    for directory, subdirs, files in os.walk(old, topdown=True, followlinks=False):
        parent = Path(directory)
        for name in list(subdirs):
            path = parent / name
            # Disposable native build scratch is never salvaged. An aborted
            # worker may leave symlinks inside its isolated Conda environment;
            # examining those unrelated paths would incorrectly reject the CAS.
            if parent == old and name.startswith('.native-pip-') and path.is_dir() and not path.is_symlink():
                subdirs.remove(name)
                continue
            if path.is_symlink() or path.is_mount() or not path.is_dir():
                raise RuntimeError('unsafe retained dependency entry: ' + str(path))
        for name in files:
            path = parent / name
            if path.is_symlink() or path.is_mount() or not path.is_file():
                raise RuntimeError('unsafe retained dependency entry: ' + str(path))
    old_cas=old/'objects'/'sha256'
    good={}
    count=0
    if old_cas.is_dir():
        for obj in old_cas.glob('*/*'):
            sha=obj.name
            if (not SHA.fullmatch(sha) or obj.parent.name!=sha[:2]
                    or not obj.is_file()):
                raise RuntimeError('invalid retained CAS object path')
            if digest(obj)!=sha:
                print('[pool] skipping corrupt retained CAS object '+sha,flush=True)
                continue
            target=new/'objects'/'sha256'/sha[:2]/sha
            target.parent.mkdir(parents=True,exist_ok=True)
            os.link(obj,target)  # Verified immutable bytes, zero-copy reuse.
            good[(obj.stat().st_dev,obj.stat().st_ino)]=(sha,target)
            count+=1
    # Old workers (before per-completion CAS registration) left SHA-verified
    # Conda downloads in downloads/ but never inserted them into objects/.
    # Hash these files against the CURRENT validated lock before reuse. Partial
    # transfers or archives from another lock are not copied.
    conda_artifacts={} if conda_artifacts is None else conda_artifacts
    conda_recovered=0
    downloads=old/'downloads'
    if downloads.is_dir():
        for raw in downloads.iterdir():
            match=re.fullmatch(r'conda-([0-9a-f]{64})',raw.name)
            if match is None or not raw.is_file():continue
            sha=match.group(1)
            if sha not in conda_artifacts:continue
            if digest(raw)!=sha:
                print('[pool] skipping incomplete retained Conda archive '+sha,flush=True)
                continue
            target=new/'objects'/'sha256'/sha[:2]/sha
            if not target.exists():
                target.parent.mkdir(parents=True,exist_ok=True)
                os.link(raw,target)
                descriptor=os.open(target.parent,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:os.fsync(descriptor)
                finally:os.close(descriptor)
                conda_recovered+=1
            good[(raw.stat().st_dev,raw.stat().st_ino)]=(sha,target)
    # pip's HTTP response cache is not a source of trusted dependency identities.
    # It is only a performance hint: pip revalidates HTTP caching headers, and
    # final artifacts still require SHA-256 from the native PyPI report. Copy
    # rather than hardlink because the new pip worker can update cache entries.
    old_cache = old / 'pip-http-cache'
    if old_cache.is_dir():
        new_cache = new / 'pip-http-cache'
        for candidate in sorted(old_cache.rglob('*')):
            if candidate.is_dir():
                continue
            if not candidate.is_file() or candidate.is_symlink():
                raise RuntimeError('unsafe persisted native pip cache entry')
            destination = new_cache / candidate.relative_to(old_cache)
            destination.parent.mkdir(parents=True, exist_ok=True)
            before = digest(candidate)
            shutil.copyfile(candidate, destination)
            if digest(candidate) != before or digest(destination) != before:
                raise RuntimeError('native pip cache changed during verified recovery')
        print('[pool] restored native pip HTTP response cache', flush=True)
    # Git refs/packed objects can be mutated by a later fetch: COPY them, never
    # hardlink mutable Git objects to the failed stage.
    for kind in ('git','git-extra'):
        source=old/kind
        if source.is_dir():
            shutil.copytree(source,new/kind,dirs_exist_ok=True,copy_function=shutil.copy2)
    # Retain only files already hardlinked to a SHA-verified old CAS object.
    # Partial HTTP transfers, unconstrained downloads and pip scratch files
    # are deliberately excluded.
    for kind in ('downloads',):
        source=old/kind
        if not source.is_dir():continue
        for file in source.rglob('*'):
            if not file.is_file():continue
            identity=(file.stat().st_dev,file.stat().st_ino)
            if identity not in good:continue
            dest=new/kind/file.relative_to(source)
            dest.parent.mkdir(parents=True,exist_ok=True)
            os.link(good[identity][1],dest)
    # Reuse a logical pip plan only when it already belongs to this exact
    # resolver-policy schema and every referenced immutable object survived
    # SHA-256 validation. Resolver changes invalidate decisions, never CAS bytes.
    good_shas={value[0] for value in good.values()}
    old_metadata=old/'metadata'
    if old_metadata.is_dir():
        for plan_path in sorted(old_metadata.glob('pip-plan-*.json')):
            if plan_path.is_symlink() or not plan_path.is_file() or plan_path.stat().st_size>4*1024*1024:
                continue
            try:
                raw=plan_path.read_bytes(); plan=json.loads(raw)
                if (plan.get('optional_failed') or plan.get('artifact_model')!=PIP_ARTIFACT_MODEL
                        or plan.get('plan_schema')!=PIP_PLAN_SCHEMA):
                    continue
                _coerce_target(plan.get('target'))
                key = plan_path.name[len('pip-plan-'):-len('.json')]
                dependencies = _read_pip_plan_tree(old, key)
                artifact_shas={sha for completed in dependencies.values()
                               for sha in _pip_plan_artifact_shas(completed)}
                if not artifact_shas<=good_shas:
                    continue
                write_new(new/'metadata'/plan_path.name,raw)
            except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError,RuntimeError):
                continue

    # APT will verify these archives again against signed Kali indexes.
    # They are writable APT cache entries, so COPY instead of hardlinking them.
    old_debs=old/'apt'/'archives'
    if old_debs.is_dir():
        for deb in old_debs.glob('*.deb'):
            if (deb.stat().st_dev,deb.stat().st_ino) not in good:continue
            dest=new/'apt'/'archives'/deb.name
            dest.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(deb,dest)
    print('[pool] verified resume: '+str(count)+' CAS artifacts, '+str(conda_recovered)+' legacy Conda archives and retained Git mirrors',flush=True)
    return {value[0] for value in good.values()}


# GPT_TRACE_SWEGYM_CONDA_LOCK_V1
CONDA_LOCK_SCHEMA = 1
CONDA_LOCK_HOSTS = frozenset({'conda.anaconda.org', 'repo.anaconda.com'})


@functools.lru_cache(maxsize=1)
def _acquisition_workers():
    """Return the versioned I/O concurrency budget staged with the fetcher."""
    path=Path(__file__).resolve().parents[1]/'config/preparation.toml'
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('missing staged preparation controls')
    try:
        with path.open('rb') as stream:payload=tomllib.load(stream)
    except (OSError,tomllib.TOMLDecodeError) as exc:
        raise RuntimeError('invalid staged preparation controls') from exc
    workers=(payload.get('acquisition') or {}).get('workers')
    if type(workers) is not int or workers<1:
        raise RuntimeError('invalid acquisition worker control')
    return workers


def _conda_progress_interval():
    path=Path(__file__).resolve().parents[1]/'config/preparation.toml'
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('missing staged preparation controls')
    with path.open('rb') as stream:payload=tomllib.load(stream)
    seconds=(payload.get('acquisition') or {}).get('progress_interval_seconds')
    if type(seconds) is not int or seconds<1:
        raise RuntimeError('invalid acquisition progress interval')
    return seconds


def conda_recipe_fingerprint(script):
    return hashlib.sha256(json.dumps(script,sort_keys=True,separators=(',',':'),
        ensure_ascii=False).encode()).hexdigest()


def conda_expected_transaction_keys(env,script):
    post=conda_post_install_specs(script)
    if not post:return ['env-'+env]
    result=['env-'+env+'-base']
    for index in range(1,len(post)+1):
        result.append('env-'+env if index==len(post) else 'env-'+env+'-step'+str(index))
    return result


def _validate_conda_lock_url(url,name,version,build):
    parsed=urllib.parse.urlsplit(str(url))
    if (parsed.scheme!='https' or parsed.hostname not in CONDA_LOCK_HOSTS or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        raise RuntimeError('untrusted Conda lock URL: '+str(url))
    filename=Path(parsed.path).name
    expected=str(name)+'-'+str(version)+'-'+str(build)
    if filename not in (expected+'.conda',expected+'.tar.bz2'):
        raise RuntimeError('Conda lock package identity/URL mismatch: '+filename)
    return str(url)


def load_conda_lock(adapter,pins,contract):
    path=Path(adapter)/'conda-lock.json'
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('missing pinned SWE-Gym Conda lock; run scripts/generate_swegym_conda_lock.py')
    raw=path.read_bytes();lock_sha=hashlib.sha256(raw).hexdigest()
    try:lock=json.loads(raw)
    except ValueError as exc:raise RuntimeError('invalid SWE-Gym Conda lock JSON') from exc
    platform=lock.get('platform') if isinstance(lock,dict) else None
    image_prefix=lock.get('image_prefix') if isinstance(lock,dict) else None
    if (not isinstance(lock,dict) or lock.get('schema')!=CONDA_LOCK_SCHEMA
            or lock.get('kind')!='swe-gym-lite-conda-image-lock'
            or not isinstance(platform,str) or re.fullmatch(r'[A-Za-z0-9_.-]+',platform) is None
            or lock.get('contract_sha256')!=pins.get('contract_sha256')
            or not isinstance(image_prefix,str)
            or re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.',image_prefix) is None):
        raise RuntimeError('SWE-Gym Conda lock header differs from pinned contract')
    artifacts=lock.get('artifacts');environments=lock.get('environments')
    if (not isinstance(artifacts,dict) or not artifacts or len(artifacts)>50000
            or not isinstance(environments,dict)
            or set(environments)!=set(contract.get('environments',{}))):
        raise RuntimeError('SWE-Gym Conda lock coverage differs')
    by_url={}
    checked={}
    for sha,item in artifacts.items():
        if not isinstance(sha,str) or not SHA.fullmatch(sha) or not isinstance(item,dict):
            raise RuntimeError('invalid Conda lock artifact identity')
        if item.get('sha256')!=sha:
            raise RuntimeError('Conda lock artifact key/SHA mismatch')
        name=item.get('name');version=item.get('version');build=item.get('build')
        if not all(isinstance(value,str) and value for value in (name,version,build)):
            raise RuntimeError('incomplete Conda lock package identity')
        subdir=item.get('subdir')
        if not isinstance(subdir,str) or re.fullmatch(r'[A-Za-z0-9_.-]+',subdir) is None:
            raise RuntimeError('unsupported Conda lock package subdir')
        url=_validate_conda_lock_url(item.get('url'),name,version,build)
        previous=by_url.setdefault(url,sha)
        if previous!=sha:raise RuntimeError('Conda lock URL maps to conflicting SHA-256 values')
        checked[sha]={'name':name,'version':version,'build':build,'url':url,'sha256':sha,
                      'channel':item.get('channel'),'subdir':item.get('subdir')}
    native_subdirs={item['subdir'] for item in checked.values() if item['subdir']!='noarch'}
    if len(native_subdirs)!=1:
        raise RuntimeError('Conda lock must have exactly one native target subdir')
    tasks_by_env=defaultdict(list)
    for logical,task in contract.get('tasks',{}).items():tasks_by_env[task.get('env_hash')].append(logical)
    referenced=set()
    normalized_envs={}
    for env,recipe in contract['environments'].items():
        row=environments.get(env)
        if not isinstance(row,dict):raise RuntimeError('invalid Conda lock environment '+env)
        candidates=sorted(tasks_by_env.get(env,[]))
        instance=row.get('instance_id')
        if instance not in candidates:
            raise RuntimeError('Conda lock environment references unrelated task image: '+env)
        expected_image=image_prefix+instance.replace('__','_s_')
        if row.get('image')!=expected_image or re.fullmatch(r'sha256:[0-9a-f]{64}',str(row.get('image_digest'))) is None:
            raise RuntimeError('invalid Conda lock image provenance: '+env)
        script=recipe.get('original_script')
        if row.get('recipe_sha256')!=conda_recipe_fingerprint(script):
            raise RuntimeError('Conda lock recipe fingerprint differs: '+env)
        expected_keys=conda_expected_transaction_keys(env,script)
        transactions=row.get('transactions')
        if not isinstance(transactions,list) or [x.get('key') if isinstance(x,dict) else None for x in transactions]!=expected_keys:
            raise RuntimeError('Conda lock transaction sequence differs: '+env)
        normalized=[]
        for transaction in transactions:
            python=transaction.get('python');packages=transaction.get('packages')
            if python not in PYTHONS or not isinstance(packages,list) or not packages or len(packages)!=len(set(packages)):
                raise RuntimeError('invalid Conda lock transaction: '+transaction.get('key','?'))
            names=set();solution=[]
            for sha in packages:
                if sha not in checked:raise RuntimeError('Conda lock transaction references unknown archive')
                item=checked[sha]
                if item['name'] in names:raise RuntimeError('duplicate package name in Conda lock transaction')
                names.add(item['name']);solution.append(item)
                referenced.add(sha)
            if conda_solution_python(solution)!=python:
                raise RuntimeError('Conda lock transaction Python metadata differs')
            normalized.append({'key':transaction['key'],'python':python,'packages':list(packages)})
        if normalized[-1]['python']!=python_version(script):
            raise RuntimeError('Conda lock final Python differs from contract: '+env)
        normalized_envs[env]={**row,'transactions':normalized}
    if referenced!=set(checked):raise RuntimeError('Conda lock has unreferenced archive records')
    return {**lock,'artifacts':checked,'environments':normalized_envs},lock_sha


class _CondaTransferProgress:
    """Thread-safe completed-artifact and real network-byte counters."""
    def __init__(self,total,reused,interval):
        self.lock=threading.Lock()
        self.total=total
        self.completed=reused
        self.failed=0
        self.active=0
        self.network_bytes=0
        self.started=time.monotonic()
        self.last_time=self.started
        self.last_bytes=0
        self.interval=interval

    def start(self):
        with self.lock:self.active+=1

    def bytes(self,count):
        with self.lock:self.network_bytes+=count

    def finish(self,success):
        with self.lock:
            self.active-=1
            if success:self.completed+=1
            else:self.failed+=1

    def report(self,*,force=False):
        with self.lock:
            now=time.monotonic()
            elapsed=now-self.last_time
            if not force and elapsed<self.interval:return
            rate=(self.network_bytes-self.last_bytes)/elapsed if elapsed>0 else 0
            total_rate=self.network_bytes/(now-self.started) if now>self.started else 0
            if _POOL_PROGRESS is not None:
                _pool_progress('Conda archives',self.completed,self.total,'verified',
                               f'{self.failed} failed, {self.active} active')
            else:
                print(f'[pool] Conda progress: {self.completed}/{self.total} verified, '
                      f'{self.failed} failed, {self.active} active, '
                      f'{self.network_bytes/1048576:.1f} MiB transferred, '
                      f'{rate/1048576:.2f} MiB/s interval, '
                      f'{total_rate/1048576:.2f} MiB/s average',flush=True)
            self.last_time=now
            self.last_bytes=self.network_bytes


def acquire_locked_conda(pool,lock):
    """Download and DURABLY publish each verified Conda artifact immediately."""
    artifacts=lock['artifacts'];references=defaultdict(set)
    for env,row in lock['environments'].items():
        for transaction in row['transactions']:
            for sha in transaction['packages']:references[sha].add(transaction['key'])
    missing=[sha for sha in sorted(references)
             if not (pool.objects/sha[:2]/sha).is_file()]
    print('[pool] Conda lock: '+str(len(lock['environments']))+' environments, '
          +str(sum(len(row['transactions']) for row in lock['environments'].values()))
          +' transactions, '+str(len(references))+' unique archives',flush=True)
    progress=_CondaTransferProgress(len(references),len(references)-len(missing),
                                    _conda_progress_interval())
    progress.report(force=True)
    def transfer(sha):
        progress.start()
        try:
            raw=pool.stage/'downloads'/('conda-'+sha)
            actual=fetch(artifacts[sha]['url'],raw,sha=sha,on_block=progress.bytes)
            if actual!=sha:raise RuntimeError('Conda lock download identity changed')
            # Registration MUST precede raw.unlink() and completion accounting.
            # No other download needs to succeed for these bytes to be reusable.
            pool.put(raw,'conda',sorted(references[sha])[0],verified_sha=sha,durable=True)
            raw.unlink()
        except BaseException:
            progress.finish(False)
            raise
        progress.finish(True)
        return sha
    if missing:
        workers=min(_acquisition_workers(),len(missing))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers,
                                                   thread_name_prefix='conda-lock') as executor:
            pending={executor.submit(transfer,sha) for sha in missing}
            first_error=None
            while pending:
                finished,pending=concurrent.futures.wait(
                    pending,timeout=progress.interval,return_when=concurrent.futures.FIRST_COMPLETED)
                for future in finished:
                    if future.cancelled():continue
                    try:future.result()
                    except BaseException as exc:
                        if first_error is None:first_error=exc
                if first_error is not None:
                    for future in pending:future.cancel()
                progress.report()
            progress.report(force=True)
            if first_error is not None:raise first_error
    else:
        progress.report(force=True)
    # Only provenance bookkeeping remains; every archive is already in verified
    # CAS and is reusable even if a later stage of the fetch fails.
    for sha in sorted(references):
        item=artifacts[sha]
        for identity in sorted(references[sha]):
            pool.download(item['url'],'conda',identity,sha=sha)
    plans={};base_python={}
    for env,row in sorted(lock['environments'].items()):
        keys=[]
        for transaction in row['transactions']:
            key=transaction['key'];keys.append(key)
            solution=[artifacts[sha] for sha in transaction['packages']]
            write_new(pool.stage/'metadata'/('conda-'+key+'.json'),
                      json.dumps(solution,sort_keys=True,separators=(',',':')))
        plans[env]=keys;base_python[env]=row['transactions'][0]['python']
    return plans,base_python


def conda_solution_python(resolved):
    """Return the major.minor Python actually selected by one Conda transaction."""
    rows=[row for row in resolved if _normalized_package_name(row.get('name',''))=='python']
    if len(rows)!=1:raise RuntimeError('Conda solution does not contain exactly one Python package')
    match=re.match(r'^(\d+)\.(\d+)',str(rows[0].get('version','')))
    if not match:raise RuntimeError('Conda solution has invalid Python version')
    return match.group(1)+'.'+match.group(2)


def conda_solution_full_python(resolved):
    """Return the exact locked Python patch release for one transaction."""
    rows=[row for row in resolved if _normalized_package_name(row.get('name',''))=='python']
    if len(rows)!=1 or not re.fullmatch(r'\d+\.\d+\.\d+',str(rows[0].get('version',''))):
        raise RuntimeError('Conda solution does not contain one full Python version')
    return str(rows[0]['version'])


def _target_debian_architecture():
    architecture=_golden_target().architecture
    mapping={'x86_64':'amd64','aarch64':'arm64'}
    try:return mapping[architecture]
    except KeyError as exc:raise RuntimeError('unsupported golden architecture for Debian packages: '+architecture) from exc


def apt_closure(pool,packages):
    """Signed Kali APT resolution from the golden's real installed inventory.

    Uses an isolated APT state/list/archive directory and only download-only
    operations. Ubuntu's installed status and package lists never participate.
    """
    deb_arch=_target_debian_architecture()
    stage=pool.stage;apt=stage/'apt';apt.mkdir(exist_ok=True)
    for name in ('lists','archives','partial','sourceparts'):(apt/name).mkdir(exist_ok=True)
    (apt/'lists'/'partial').mkdir(exist_ok=True)
    (apt/'archives'/'partial').mkdir(exist_ok=True)
    key_sha=pool.download('https://archive.kali.org/archive-key.asc','apt','signing-key')
    key_path=pool.objects/key_sha[:2]/key_sha
    imported=invoke(['gpg','--show-keys','--with-colons',key_path],capture=True)
    if KALI_SIGNING_FPR not in [row.split(':')[9] for row in imported.splitlines() if row.startswith('fpr:')]:
        raise RuntimeError('Kali signing key fingerprint differs')
    ring=apt/'kali.gpg'
    with ring.open('xb') as output:
        subprocess.run(['gpg','--dearmor'],input=key_path.read_bytes(),stdout=output,check=True)
    sources=apt/'sources.list'
    write_new(sources,'deb [arch='+deb_arch+' signed-by='+str(ring)+'] https://http.kali.org/kali kali-last-snapshot main contrib non-free non-free-firmware\n')
    golden=Path(__file__).resolve().parents[1]/'golden-packages.txt'
    if golden.is_symlink() or not golden.is_file():
        raise RuntimeError('authenticated golden package inventory is missing')
    contents=golden.read_bytes()
    expected=_golden_dependency()['apt_package_manifest_sha256']
    if hashlib.sha256(contents).hexdigest()!=expected:
        raise RuntimeError('golden package inventory SHA-256 differs')
    status_rows=[]
    for line in contents.decode('utf-8').splitlines():
        fields=line.strip().split()
        if len(fields)!=2:
            raise RuntimeError('golden package inventory line is malformed')
        name,version=fields
        if (not re.fullmatch(r'[A-Za-z0-9+._:-]+',name) or
                not re.fullmatch(r'[A-Za-z0-9+._:~+-]+',version)):
            raise RuntimeError('unsafe installed Debian identity')
        name,separator,qualified=name.partition(':')
        architecture=qualified if separator else deb_arch
        if architecture not in (deb_arch,'all'):
            raise RuntimeError('golden package is foreign-architecture: '+name)
        status_rows.append('Package: '+name+'\nVersion: '+version+'\nArchitecture: '
                           +architecture+'\nStatus: install ok installed\n')
    status=apt/'status'
    write_new(status,'\n'.join(status_rows)+'\n')
    opts=['-o','Dir::Etc::sourcelist='+str(sources),'-o','Dir::Etc::sourceparts=-',
          '-o','Dir::State::Lists='+str(apt/'lists'),'-o','Dir::State::status='+str(status),
          '-o','Dir::Cache::Archives='+str(apt/'archives'),
          '-o','APT::Get::AllowUnauthenticated=false',
          '-o','Acquire::AllowInsecureRepositories=false',
          '-o','APT::Architectures='+deb_arch,'-o','APT::Get::Assume-Yes=true']
    invoke(['apt-get',*opts,'update'])
    invoke(['apt-get',*opts,'--download-only','--reinstall','-y','--no-remove','install',*sorted(packages)])
    debs=sorted((apt/'archives').glob('*.deb'))
    if not debs:
        raise RuntimeError('signed Kali resolution lacks any required new Debian archives')
    meta=[]
    for path in debs:
        control=subprocess.check_output(['dpkg-deb','-f',str(path)],text=True,timeout=90)
        fields={}
        for field in ('Package','Version','Architecture'):
            found=re.search(r'^'+field+r':\s*(\S+)\s*$',control,flags=re.M)
            if not found:raise RuntimeError('APT archive missing '+field+': '+path.name)
            fields[field]=found.group(1)
        sha=pool.put(path,'apt','kali-last-snapshot')
        meta.append({'sha256':sha,'package':fields['Package'],
                     'version':fields['Version'],'architecture':fields['Architecture']})
    write_new(stage/'metadata'/'apt-closure.json',json.dumps({
        'requested':sorted(packages),'resolved':meta,
        'golden_package_inventory_sha256':expected},sort_keys=True))


def _packaging_symbols():
    """Use the explicit packaging dependency required by target_environment."""
    from packaging.markers import default_environment
    from packaging.requirements import Requirement
    from packaging.specifiers import SpecifierSet
    from packaging.version import Version, InvalidVersion
    return Requirement, SpecifierSet, Version, InvalidVersion, default_environment


@functools.lru_cache(maxsize=1)
def _target_environment_module():
    adapter=Path(__file__).resolve().parents[1]/'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym'
    module_path=adapter/'target_environment.py'
    spec=importlib.util.spec_from_file_location('swegym_target_environment',module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError('target environment model is unavailable')
    module=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=module
    spec.loader.exec_module(module)
    return module


@functools.lru_cache(maxsize=1)
def _golden_target():
    dependency=_golden_dependency()
    try:
        target=_target_environment_module().TargetEnvironment.from_dict(
            dependency['target_environment'])
        if target.source!='verified-target-interpreter':
            raise ValueError('golden target source differs')
        return target
    except (KeyError,TypeError,ValueError) as exc:
        raise RuntimeError('verified Kali target environment identity is invalid') from exc


def _locked_target(lock, env_hash, transaction_key):
    try:
        return _target_environment_module().locked_transaction_target(
            lock,env_hash,transaction_key,base_target=_golden_target())
    except (KeyError,TypeError,ValueError) as exc:
        raise RuntimeError('unable to derive exact locked target environment') from exc


def _coerce_target(value):
    module=_target_environment_module()
    if isinstance(value,module.TargetEnvironment):return value
    if isinstance(value,dict):
        try:return module.TargetEnvironment.from_dict(value)
        except (TypeError,ValueError) as exc:raise RuntimeError('invalid serialized target environment') from exc
    # Legacy helper callers may provide an exact patch version.  Production
    # callers pass transaction-derived TargetEnvironment objects so the Python
    # artifact identity is never inferred from a minor version.
    text=str(value)
    if re.fullmatch(r'\d+\.\d+\.\d+',text) is None:
        raise RuntimeError('target dependency resolution requires an exact Python patch identity')
    adapter=Path(__file__).resolve().parents[1]/'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym'
    lock=json.loads((adapter/'conda-lock.json').read_bytes())
    matches=[(sha,item) for sha,item in lock.get('artifacts',{}).items()
             if item.get('name')=='python' and str(item.get('version'))==text]
    if len(matches)!=1:
        raise RuntimeError('exact Python version does not identify one locked interpreter artifact: '+text)
    sha,_item=matches[0]
    return module.conda_target(full_version=text,base_target=_golden_target(),
                               python_artifact_sha256=sha,source='locked-conda-version:'+text)


def _target_provenance(value):
    return _coerce_target(value)


def _target_marker_environment(value):
    return _coerce_target(value).markers


class _SingleFlightCache:
    """Deduplicate concurrent immutable metadata work without serializing unrelated keys."""
    def __init__(self):
        self._lock=threading.Lock()
        self._values={}
        self._pending={}

    def peek(self,key):
        """Read only completed immutable metadata, never wait for network work."""
        with self._lock:
            return self._values.get(key)

    def get_or_compute(self,key,producer):
        with self._lock:
            if key in self._values:return self._values[key]
            future=self._pending.get(key)
            owner=future is None
            if owner:
                future=concurrent.futures.Future()
                self._pending[key]=future
        if not owner:return future.result()
        try:
            value=producer()
        except BaseException as exc:
            with self._lock:
                self._pending.pop(key,None)
                future.set_exception(exc)
            raise
        with self._lock:
            self._values[key]=value
            self._pending.pop(key,None)
            future.set_result(value)
        return value


def _memo_get_or_compute(cache,key,producer):
    if cache is None:return producer()
    if isinstance(cache,_SingleFlightCache):return cache.get_or_compute(key,producer)
    if key not in cache:cache[key]=producer()
    return cache[key]


_PYPI_JSON_CACHE=_SingleFlightCache()


def _pypi_json(url, *, limit=16*1024*1024):
    def load():
        raw=_read_https(url,timeout=90,limit=limit,user_agent='gpt-trace-dependency-pool/3',
                        expected_host='pypi.org')
        try:return json.loads(raw)
        except ValueError as exc:raise RuntimeError('invalid PyPI metadata JSON') from exc
    return _PYPI_JSON_CACHE.get_or_compute((url,limit),load)


_PYPI_SIMPLE_CACHE=_SingleFlightCache()


def _pypi_simple_project(name):
    """Read PyPI's compact PEP 691/700 project index for canonical release identities."""
    normalized=_normalized_package_name(name)
    def load():
        url='https://pypi.org/simple/'+urllib.parse.quote(normalized,safe='')+'/'
        raw=_read_https(url,timeout=90,limit=16*1024*1024,
                        user_agent='gpt-trace-dependency-pool/4',expected_host='pypi.org',
                        accept='application/vnd.pypi.simple.v1+json')
        try:payload=json.loads(raw)
        except ValueError as exc:raise RuntimeError('invalid PyPI Simple API JSON') from exc
        meta=payload.get('meta');versions=payload.get('versions')
        if (not isinstance(meta,dict) or not isinstance(meta.get('api-version'),str)
                or not re.fullmatch(r'1\.\d+',meta['api-version'])
                or _normalized_package_name(payload.get('name',''))!=normalized
                or not isinstance(versions,list) or not all(isinstance(row,str) for row in versions)):
            raise RuntimeError('unsupported/incomplete PyPI Simple API project metadata: '+name)
        return tuple(versions)
    return _PYPI_SIMPLE_CACHE.get_or_compute(normalized,load)


def _canonical_pypi_release(name,version_text):
    """Map a PEP 440 exact pin to the one stored PyPI release identity."""
    _,_,Version,InvalidVersion,_=_packaging_symbols()
    try:wanted=Version(version_text)
    except InvalidVersion as exc:raise RuntimeError('invalid exact PyPI version: '+version_text) from exc
    matches=[]
    for stored in _pypi_simple_project(name):
        try:
            if Version(stored)==wanted:matches.append(stored)
        except InvalidVersion:
            continue
    if len(matches)!=1:
        raise RuntimeError('exact PyPI requirement does not identify one stored release: '
                           +name+'=='+version_text)
    return matches[0]


def _pypi_exact_release(name,version_text):
    """Fetch an exact release directly; consult the project index only for an alias 404."""
    _,_,Version,InvalidVersion,_=_packaging_symbols()
    try:wanted=Version(version_text)
    except InvalidVersion as exc:raise RuntimeError('invalid exact PyPI version: '+version_text) from exc
    quoted_name=urllib.parse.quote(name,safe='')
    def endpoint(stored):
        return ('https://pypi.org/pypi/'+quoted_name+'/'
                +urllib.parse.quote(stored,safe='')+'/json')
    stored=version_text
    try:
        payload=_pypi_json(endpoint(stored))
    except urllib.error.HTTPError as exc:
        if exc.code!=404:raise
        stored=_canonical_pypi_release(name,version_text)
        payload=_pypi_json(endpoint(stored))
    info=payload.get('info');files=payload.get('urls')
    if not isinstance(info,dict) or not isinstance(files,list):
        raise RuntimeError('PyPI release metadata is incomplete for '+name+'=='+version_text)
    try:same_version=Version(str(info.get('version','')))==wanted
    except InvalidVersion:same_version=False
    if (_normalized_package_name(info.get('name',''))!=_normalized_package_name(name) or not same_version):
        raise RuntimeError('PyPI release metadata identity differs for '+name+'=='+version_text)
    return str(info['version']),payload


def _constraint_specifiers(name, constraints, python_version):
    Requirement,_,_,_,_=_packaging_symbols()
    env=_target_marker_environment(python_version)
    result=[]
    normalized=_normalized_package_name(name)
    for row in constraints:
        try:req=Requirement(row)
        except Exception as exc:raise RuntimeError('invalid pip constraint: '+row) from exc
        if _normalized_package_name(req.name)!=normalized:continue
        if req.url:raise RuntimeError('URL constraints are unsupported for source fallback')
        if req.marker is not None and not req.marker.evaluate(env):continue
        result.append(req.specifier)
    return result


# GPT_TRACE_SWEGYM_CONSERVATIVE_VERSION_POLICY_V2
def normalize_legacy_source_requirement(value):
    """Preserve packaging 21.3 ``>=N.*`` semantics for modern candidates.

    packaging 21.3 accepted this non-standard spelling through LegacySpecifier.
    For the PEP 440-valid release candidates admitted by this resolver, its
    inclusive lower bound begins at ``N.dev0`` when prereleases are considered.
    ``>=N.dev0`` therefore preserves the historical candidate set, unlike
    ``==N`` (too narrow) or ``>=N`` (drops prereleases of N).  No other invalid
    wildcard operator is rewritten.
    """
    if not isinstance(value,str):raise RuntimeError('non-string source dependency metadata')
    Requirement,_,_,_,_=_packaging_symbols()
    try:return str(Requirement(value))
    except Exception as original:
        head,separator,marker=value.partition(';')
        rewritten=re.sub(
            r'(?<![=!<>~])>=\s*(\d+(?:\.\d+)*)\.\*(?=\s*(?:[,)]|$))',
            lambda match: '>='+match.group(1)+'.dev0',
            head,
        )
        if rewritten==head:
            raise RuntimeError('invalid source dependency metadata: '+value) from original
        candidate=rewritten+(separator+marker if separator else '')
        try:return str(Requirement(candidate))
        except Exception as exc:
            raise RuntimeError('invalid source dependency metadata: '+value) from exc


def _parse_wheel_filename(value):
    from packaging.utils import parse_wheel_filename
    return parse_wheel_filename(value)


def _parse_sdist_filename(value):
    from packaging.utils import parse_sdist_filename
    return parse_sdist_filename(value)


def _cached_python_versions(pool, name):
    """Return exact Python-package versions already represented by the pip pool."""
    normalized=_normalized_package_name(name);found=set()
    shared=pool.stage/'wheels'/'shared'
    if shared.is_dir():
        for wheel in shared.glob('*.whl'):
            if wheel.is_symlink() or not wheel.is_file():continue
            try:wheel_name,version,_,_=_parse_wheel_filename(wheel.name)
            except Exception:continue
            if _normalized_package_name(wheel_name)==normalized:found.add(str(version))
    metadata=pool.stage/'metadata'
    if metadata.is_dir():
        for path in metadata.glob('pip-plan-*.json'):
            if path.is_symlink() or not path.is_file():continue
            try:plan=json.loads(path.read_bytes())
            except (OSError,ValueError,TypeError):continue
            rows=(plan.get('packages',[]) if isinstance(plan,dict) and isinstance(plan.get('packages'),list)
                  else plan.get('source_archives',[]) if isinstance(plan,dict) else ())
            for row in rows:
                if (not isinstance(row,dict) or _normalized_package_name(row.get('name',''))!=normalized
                        or not isinstance(row.get('version'),str)
                        or not SHA.fullmatch(str(row.get('sha256','')))):
                    continue
                target=pool.objects/row['sha256'][:2]/row['sha256']
                if target.is_file() and not target.is_symlink():found.add(row['version'])
    return found


def _cached_python_versions_snapshot(pool):
    """Freeze reusable package-version preferences before concurrent closure solving."""
    result=defaultdict(set)
    shared=pool.stage/'wheels'/'shared'
    if shared.is_dir():
        for wheel in shared.glob('*.whl'):
            if wheel.is_symlink() or not wheel.is_file():continue
            try:wheel_name,version,_,_=_parse_wheel_filename(wheel.name)
            except Exception:continue
            result[_normalized_package_name(wheel_name)].add(str(version))
    metadata=pool.stage/'metadata'
    if metadata.is_dir():
        for path in metadata.glob('pip-plan-*.json'):
            if path.is_symlink() or not path.is_file():continue
            try:plan=json.loads(path.read_bytes())
            except (OSError,ValueError,TypeError):continue
            if (not isinstance(plan,dict) or plan.get('optional_failed')
                    or plan.get('plan_schema')!=PIP_PLAN_SCHEMA):
                continue
            rows=plan.get('packages',[])
            if not isinstance(rows,list):continue
            for row in rows:
                if (not isinstance(row,dict) or not isinstance(row.get('name'),str)
                        or not isinstance(row.get('version'),str)
                        or not SHA.fullmatch(str(row.get('sha256','')))):
                    continue
                target=pool.objects/row['sha256'][:2]/row['sha256']
                if target.is_file() and not target.is_symlink():
                    result[_normalized_package_name(row['name'])].add(row['version'])
    return {name:frozenset(versions) for name,versions in result.items()}


def _select_source_release(pool, requirement, python_version, constraints=()):
    Requirement,SpecifierSet,Version,InvalidVersion,_=_packaging_symbols()
    normalized_requirement=normalize_legacy_source_requirement(requirement)
    try:req=Requirement(normalized_requirement)
    except Exception as exc:raise RuntimeError('invalid source fallback requirement: '+requirement) from exc
    if req.url:raise RuntimeError('source fallback does not accept URL requirements')
    env=_target_marker_environment(python_version)
    if req.marker is not None and not req.marker.evaluate(env):
        raise RuntimeError('source fallback selected an inactive marker: '+requirement)
    constraint_specs=_constraint_specifiers(req.name,constraints,python_version)
    target=Version(env['python_full_version'])
    exact_specs=[item for item in req.specifier if item.operator=='==' and '*' not in item.version]
    exact_text=exact_specs[0].version if len(exact_specs)==1 else None
    exact_version=None
    if exact_text is not None:
        try:exact_version=Version(exact_text)
        except InvalidVersion:exact_version=None
    if (exact_version is not None
            and all(not spec or spec.contains(exact_version,prereleases=None) for spec in constraint_specs)):
        stored_version,release=_pypi_exact_release(req.name,exact_text)
        releases={stored_version:release['urls']}
    else:
        project=_pypi_json('https://pypi.org/pypi/'+urllib.parse.quote(req.name,safe='')+'/json')
        releases=project.get('releases')
        if not isinstance(releases,dict):raise RuntimeError('PyPI project has no releases: '+req.name)
    candidates=[]
    for text,files in releases.items():
        try:version=Version(text)
        except InvalidVersion:continue
        if req.specifier and not req.specifier.contains(version,prereleases=None):continue
        if any(spec and not spec.contains(version,prereleases=None) for spec in constraint_specs):continue
        if not isinstance(files,list):continue
        source=[]
        for item in files:
            if (not isinstance(item,dict) or item.get('packagetype')!='sdist'
                    or item.get('yanked') is True and exact_text is None):continue
            digests=item.get('digests') or {};sha=str(digests.get('sha256',''))
            if not SHA.fullmatch(sha):continue
            requires_python=item.get('requires_python')
            if requires_python is not None and requires_python != '':
                if not _requires_python_compatible(requires_python,target):continue
            url=item.get('url')
            if not isinstance(url,str) or urllib.parse.urlsplit(url).hostname!='files.pythonhosted.org':continue
            filename=str(item.get('filename') or '')
            rank=0 if filename.endswith('.tar.gz') else 1 if filename.endswith('.zip') else 2
            source.append((rank,filename,item))
        if source:
            source.sort(key=lambda x:(x[0],x[1]))
            candidates.append((version,text,source[0][2]))
    if not candidates:
        raise RuntimeError('no compatible hash-addressed source distribution: '+requirement)
    combined=SpecifierSet(','.join(str(spec) for spec in [req.specifier,*constraint_specs] if str(spec)))
    admitted=set(combined.filter([row[0] for row in candidates],prereleases=None))
    candidates=[row for row in candidates if row[0] in admitted]
    if not candidates:raise RuntimeError('no compatible source version after prerelease policy: '+requirement)
    # Pool reuse has priority over choosing another version. Candidate rows
    # already satisfy the complete requirement/constraint/target-Python
    # intersection. If several compatible versions are cached, reuse the newest
    # cached one deterministically.
    candidates.sort(key=lambda row:row[0])
    cached_versions=set()
    for text in _cached_python_versions(pool,req.name):
        try:cached_versions.add(Version(text))
        except InvalidVersion:continue
    cached=[row for row in candidates if row[0] in cached_versions]
    if cached:
        selected=cached[-1]
    else:
        # Match pip's normal preference: an unpinned range, including ``>=X``,
        # selects the newest compatible non-yanked release.  Treating ``>=X`` as
        # a minimum-version preference causes pathological version ladders when
        # sibling requirements constrain the same transitive dependencies.
        selected=candidates[-1]
    _,version_text,item=selected
    return req,version_text,item


def _source_archive_files(path, filename):
    """Read only small root metadata/requirements files from a pinned source archive."""
    import tarfile
    import zipfile
    wanted={'PKG-INFO','setup.py','setup.cfg','pyproject.toml'}
    result={}; roots=set(); paths=set(); total=0
    def validate_name(name):
        from pathlib import PurePosixPath
        rel=PurePosixPath(name)
        if (not name or '\\' in name or '\x00' in name or rel.is_absolute()
                or '..' in rel.parts or name.rstrip('/')!=rel.as_posix()):
            raise RuntimeError('unsafe source archive path')
        return rel
    def accept(rel,size):
        if len(rel.parts)<2:return False
        name=rel.name
        selected=((len(rel.parts)==2 and name in wanted) or
                  (name.lower().endswith('.txt') and re.fullmatch(r'[A-Za-z0-9_.-]*(?:requirements?|requires?)[A-Za-z0-9_.-]*\.txt',name,re.I)))
        if selected and size>2*1024*1024:
            raise RuntimeError('source metadata file exceeds security limit')
        return bool(selected)
    def keep(rel,data):
        nonlocal total
        relative='/'.join(rel.parts[1:])
        if relative in result or rel.parts[0] in roots and rel.as_posix() in paths:
            raise RuntimeError('duplicate source archive metadata')
        roots.add(rel.parts[0]);paths.add(rel.as_posix())
        if len(roots)!=1:raise RuntimeError('ambiguous source archive metadata roots')
        total+=len(data)
        if total>MAX_SOURCE:raise RuntimeError('source archive metadata exceeds security limit')
        result[relative]=data
    if filename.endswith(('.tar.gz','.tar.bz2','.tar.xz','.tgz')):
        with tarfile.open(path,'r:*') as archive:
            for member in archive:
                rel=validate_name(member.name)
                if not accept(rel,member.size):continue
                if not member.isfile():raise RuntimeError('source metadata is not a regular file')
                stream=archive.extractfile(member)
                if stream is not None:keep(rel,stream.read(2*1024*1024+1))
    elif filename.endswith('.zip'):
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                name=info.filename;rel=validate_name(name)
                if not accept(rel,info.file_size):continue
                if stat.S_ISLNK(info.external_attr>>16):raise RuntimeError('source metadata is a symlink')
                keep(rel,archive.read(info))
    else:raise RuntimeError('unsupported source archive: '+filename)
    return result


def _sdist_pyproject_requirements(source, *, extras=()):
    """Read declarative build/runtime requirements without invoking a backend."""
    try:data=tomllib.loads(source)
    except (TypeError,tomllib.TOMLDecodeError) as exc:
        raise RuntimeError('invalid source pyproject.toml') from exc
    result=set();issues=[]
    build=data.get('build-system',{})
    if build:
        rows=build.get('requires',[])
        if not isinstance(rows,list) or not all(isinstance(item,str) for item in rows):
            raise RuntimeError('source build-system.requires is not a string list')
        result.update(rows)
    project=data.get('project',{})
    if isinstance(project,dict):
        rows=project.get('dependencies',[])
        if rows:
            if not isinstance(rows,list) or not all(isinstance(item,str) for item in rows):
                raise RuntimeError('source project.dependencies is not a string list')
            result.update(rows)
        dynamic=project.get('dynamic',[])
        if isinstance(dynamic,list) and 'dependencies' in dynamic:
            issues.append('dynamic PEP621 dependencies')
        optional=project.get('optional-dependencies',{})
        if isinstance(optional,dict):
            for group in extras:
                rows=optional.get(group,[])
                if rows and (not isinstance(rows,list) or not all(isinstance(item,str) for item in rows)):
                    raise RuntimeError('source optional dependency group is invalid: '+str(group))
                result.update(rows or [])
    return result,issues


def acquire_source_distribution(pool, requirement, plan_key, target, *, constraints=()):
    """Acquire one compatible PyPI sdist and inspect only non-executing metadata."""
    import email.parser
    target=_coerce_target(target)
    req,selected,item=_select_source_release(pool,requirement,target,constraints)
    version_url='https://pypi.org/pypi/'+urllib.parse.quote(req.name,safe='')+'/'+urllib.parse.quote(selected,safe='')+'/json'
    metadata=_pypi_json(version_url)
    urls=metadata.get('urls') or []
    expected_sha=str((item.get('digests') or {}).get('sha256',''))
    exact=[row for row in urls if isinstance(row,dict) and row.get('packagetype')=='sdist'
           and str((row.get('digests') or {}).get('sha256',''))==expected_sha]
    if not exact:raise RuntimeError('selected PyPI source disappeared: '+requirement)
    source_item=sorted(exact,key=lambda row:str(row.get('filename','')))[0]
    url=source_item.get('url');filename=str(source_item.get('filename') or '')
    if urllib.parse.urlsplit(str(url)).hostname!='files.pythonhosted.org':
        raise RuntimeError('untrusted PyPI source archive host: '+str(url))
    sha=pool.download(url,'python-source',plan_key,sha=expected_sha)
    source=pool.objects/sha[:2]/sha
    candidates=_source_archive_files(source,filename)
    requirements=set();provides_extra=set();dynamic_issues=[]
    info=metadata.get('info') or {}
    authoritative=False
    if 'PKG-INFO' in candidates:
        _name,_version,embedded_requirements,embedded_extras=_core_metadata_fields(
            candidates['PKG-INFO'],expected_name=req.name,expected_version=selected,target=target)
        parsed=email.parser.Parser().parsestr(candidates['PKG-INFO'].decode('utf-8'),headersonly=True)
        metadata_version=tuple(int(part) for part in parsed['Metadata-Version'].split('.'))
        dynamic={field.lower() for field in parsed.get_all('Dynamic',[])}
        if dynamic & {'requires-dist','requires-python','provides-extra'}:
            dynamic_issues.append('dynamic sdist dependency metadata')
        authoritative=metadata_version>=(2,2) and not dynamic_issues
        if authoritative:
            requirements.update(embedded_requirements)
            provides_extra.update(embedded_extras)
    try:text_files={name:data.decode('utf-8') for name,data in candidates.items()}
    except UnicodeDecodeError as exc:raise RuntimeError('source metadata is not valid UTF-8') from exc
    def get_file(name,required=False):
        name=str(name).removeprefix('./')
        if not name or Path(name).is_absolute() or '..' in Path(name).parts or '\\' in name:
            raise RuntimeError('unsafe sdist metadata file reference')
        value=text_files.get(name)
        if value is None and required:raise RuntimeError('missing sdist dependency file: '+name)
        return value
    if 'pyproject.toml' in text_files:
        deps,issues=_sdist_pyproject_requirements(text_files['pyproject.toml'],extras=set(req.extras))
        requirements.update(deps);dynamic_issues.extend(issues)
    if 'setup.cfg' in text_files:
        deps,issues=setup_cfg_static(text_files['setup.cfg'],extras=set(req.extras))
        if issues:raise RuntimeError('invalid source setup.cfg: '+repr(issues))
        requirements.update(deps)
    if 'setup.py' in text_files and not authoritative:
        deps,remote,issues=setup_requirements_from_sources(
            text_files['setup.py'],get_file,extras=set(req.extras),python_version=target.python_full_version)
        if remote:raise RuntimeError('sdist setup.py contains VCS dependency: '+requirement)
        requirements.update(deps);dynamic_issues.extend(issues)
    if not authoritative and 'setup.py' not in text_files and 'setup.cfg' not in text_files:
        project=tomllib.loads(text_files.get('pyproject.toml','')).get('project')
        if not isinstance(project,dict) or 'dependencies' not in project:
            dynamic_issues.append('source runtime dependencies are not statically established')
    if not authoritative and not ({'setup.py','setup.cfg','pyproject.toml'} & text_files.keys()):
        dynamic_issues.append('legacy sdist does not establish complete dependency metadata')
    if dynamic_issues:
        raise RuntimeError('source metadata requires isolated target evaluation: '+requirement+': '+'; '.join(dynamic_issues))
    clean=set()
    for row in sorted(requirements):
        if not isinstance(row,str):raise RuntimeError('non-string source dependency: '+requirement)
        clean.add(normalize_legacy_source_requirement(row))
    extras=sorted(x for x in provides_extra|set(req.extras) if isinstance(x,str) and re.fullmatch(r'[A-Za-z0-9_.-]+',x))
    if not clean and not ({'setup.py','PKG-INFO','setup.cfg','pyproject.toml'}&text_files.keys()):
        raise RuntimeError('source archive has no inspectable dependency metadata')
    return {'name':req.name,'version':selected,'requested':requirement,
            'filename':filename,'url':url,'sha256':sha,'requirements':sorted(clean),
            'provides_extra':extras,'metadata_mode':'static-core-metadata'}


def acquire_pinned_sdist(pool, requirement, plan_key, python_version, *, constraints=()):
    """Backward-compatible exact-pin wrapper around the generic source resolver."""
    Requirement,_,_,_,_=_packaging_symbols()
    try:req=Requirement(requirement)
    except Exception as exc:raise RuntimeError('invalid pinned source requirement: '+requirement) from exc
    if len(list(req.specifier))!=1 or not str(req.specifier).startswith('==') or '*' in str(req.specifier):
        raise RuntimeError('sdist fallback requires an exact pinned version: '+requirement)
    return acquire_source_distribution(pool,requirement,plan_key,python_version,constraints=constraints)


PIP_PLAN_SCHEMA = 21
PIP_RESOLVER_POLICY = 'mandatory-native-rust-solver-v1-soft-pins'


def _pip_worker_controls():
    """CPU quota, cpuset, available memory and I/O concurrency are separate."""
    io_workers=_acquisition_workers()
    try:
        cpu_capacity=len(os.sched_getaffinity(0))
    except OSError as exc:
        raise RuntimeError('CPU affinity unavailable for Rust graph solvers') from exc
    if cpu_capacity < 1:
        raise RuntimeError('empty CPU affinity for Rust graph solvers')
    policy_path=Path(__file__).resolve().parents[1]/'config/preparation.toml'
    if policy_path.is_symlink() or not policy_path.is_file():
        raise RuntimeError('missing versioned Rust solver resource policy')
    with policy_path.open('rb') as stream:
        policy=tomllib.load(stream)
    worker_mb=policy['acquisition'].get('pip_solver_worker_memory_mb')
    reserve_mb=policy['build'].get('memory_reserve_mb')
    if (type(worker_mb) is not int or worker_mb < 1
            or type(reserve_mb) is not int or reserve_mb < 0):
        raise RuntimeError('invalid versioned Rust solver memory policy')
    info=Path('/proc/meminfo').read_text().splitlines()
    available=[int(line.split()[1])*1024 for line in info if line.startswith('MemAvailable:')]
    if len(available)!=1 or available[0] < 1:
        raise RuntimeError('kernel MemAvailable is unavailable')
    free_memory=available[0]
    # Compute restrictions from the actual process cgroup and *all* ancestors.
    scope=next((line.partition('::')[2] for line in Path('/proc/self/cgroup').read_text().splitlines()
                if line.startswith('0::')),None)
    if scope is not None:
        root=Path('/sys/fs/cgroup')
        current=root/scope.lstrip('/')
        while True:
            max_cpu=current/'cpu.max'
            if max_cpu.is_file():
                quota=max_cpu.read_text().split()
                if len(quota)!=2:raise RuntimeError('invalid cgroup CPU quota')
                if quota[0]!='max':
                    q,p=map(int,quota)
                    if q<=0 or p<=0:raise RuntimeError('invalid cgroup CPU quota')
                    cpu_capacity=min(cpu_capacity,max(1,(q+p-1)//p))
            max_mem=current/'memory.max'
            if max_mem.is_file():
                limit=max_mem.read_text().strip()
                if limit!='max':
                    used=int((current/'memory.current').read_text().strip())
                    free_memory=min(free_memory,max(0,int(limit)-used))
            if current==root:break
            if current==current.parent or not current.is_relative_to(root):
                raise RuntimeError('invalid cgroup resource ancestry')
            current=current.parent
    available_bytes=max(0,free_memory-reserve_mb*1048576)
    if available_bytes < worker_mb*1048576:
        raise RuntimeError('insufficient verified memory budget for one Rust Pip solver worker')
    memory_capacity=available_bytes//(worker_mb*1048576)
    return min(cpu_capacity,memory_capacity),io_workers


def _metadata_prefetch_width(closure_workers,metadata_workers):
    """Fairly divide global metadata capacity across active closure workers."""
    if type(closure_workers) is not int or closure_workers<1 or type(metadata_workers) is not int or metadata_workers<1:
        raise RuntimeError('invalid Pip worker capacity')
    return max(1,(metadata_workers+closure_workers-1)//closure_workers)


class _ResolverActivity:
    """Grow per-closure prefetch automatically as the resolver batch drains."""
    def __init__(self,metadata_workers):
        if type(metadata_workers) is not int or metadata_workers<1:
            raise RuntimeError('invalid Pip metadata worker capacity')
        self.metadata_workers=metadata_workers;self.active=0;self.lock=threading.Lock()
    def enter(self):
        with self.lock:self.active+=1
    def leave(self):
        with self.lock:
            if self.active<1:raise RuntimeError('Pip resolver activity underflow')
            self.active-=1
    def width(self):
        with self.lock:active=max(1,self.active)
        return max(1,(self.metadata_workers+active-1)//active)


def _target_fingerprint(target):
    target=_coerce_target(target)
    return hashlib.sha256(json.dumps(target.as_dict(),sort_keys=True,separators=(',',':')).encode()).hexdigest()


def _canonical_pip_preferences(values):
    """Validated, stable target-local preferences. Never impose them as constraints."""
    if values is None or values == {}:
        return {}
    if not isinstance(values, dict):
        raise ValueError('invalid pip preference mapping')
    _, _, Version, InvalidVersion, _ = _packaging_symbols()
    clean = {}
    for name, versions in sorted(values.items()):
        if (not isinstance(name, str) or name != _normalized_package_name(name)
                or not isinstance(versions, (tuple, list)) or not versions):
            raise ValueError('invalid pip preferred project/version sequence')
        checked = []
        for raw in versions:
            if not isinstance(raw, str) or not raw:
                raise ValueError('invalid preferred release identity')
            try:
                version = str(Version(raw))
            except InvalidVersion as exc:
                raise ValueError('invalid preferred PEP 440 version') from exc
            if version not in checked:
                checked.append(version)
        clean[name] = checked
    return clean


def pip_group_key(target, reqs, constraints=(), no_deps=False, *, preferred_versions=None):
    """Identity of a logical solve, including exact target and resolver policy."""
    target=_coerce_target(target)
    payload={'schema':PIP_PLAN_SCHEMA,'resolver':PIP_RESOLVER_POLICY,'runtime':_resolver_runtime_identity(),
             'target':target.as_dict(),'requirements':sorted(set(reqs)),
             'constraints':sorted(set(constraints)),'no_deps':bool(no_deps),
             'preferred_versions':_canonical_pip_preferences(preferred_versions)}
    return hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()[:20]


@functools.lru_cache(maxsize=1)
def _resolver_runtime_identity():
    import packaging
    # Source identity is identical on Acer and Fossil. The actual executable is
    # separately sealed on Fossil and checked by the mandatory Rust bridge.
    root = Path(__file__).resolve().parents[1]
    source_files = ('rust/verified-resolver/Cargo.toml',
                    'rust/verified-resolver/Cargo.lock',
                    'rust/verified-resolver/src/main.rs',
                    'scripts/verified_resolver_bridge.py')
    return {'packaging': packaging.__version__,
            'python': '.'.join(map(str, sys.version_info[:3])),
            'native_solver_source_sha256': {
                relative: digest(root / relative) for relative in source_files}}


@functools.lru_cache(maxsize=1)
def _native_pip_timeouts():
    """Read operational deadlines from the staged, versioned preparation policy."""
    path = Path(__file__).resolve().parents[1] / 'config/preparation.toml'
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('missing staged native pip timeout policy')
    with path.open('rb') as stream:
        policy = tomllib.load(stream).get('acquisition')
    if not isinstance(policy, dict):
        raise RuntimeError('invalid native pip acquisition controls')
    total = policy.get('pip_total_timeout_seconds')
    stall = policy.get('pip_stall_timeout_seconds')
    if (type(total) is not int or total < 1 or type(stall) is not int
            or stall < 1 or stall >= total):
        raise RuntimeError('invalid native pip total/stall timeout controls')
    return total, stall


# Native pip is responsible for PyPI resolution; the surrounding pipeline still
# owns immutable source selection, SHA-256 CAS, manifests and task provenance.
_NATIVE_POOL_LOCK = threading.RLock()


def _native_pool_runtime(pool):
    """Private, non-root host scratch for exact locked interpreters (no KVM)."""
    with _NATIVE_POOL_LOCK:
        runtime = getattr(pool, '_native_runtime', None)
        if runtime is not None:
            return runtime
        if not isinstance(getattr(pool, 'conda_lock', None), dict):
            raise RuntimeError('native resolver needs the validated locked Conda transactions')
        temporary = tempfile.TemporaryDirectory(prefix='.native-pip-', dir=pool.stage)
        root = Path(temporary.name)
        home = root / 'home'
        home.mkdir(mode=0o700)
        # CacheControl's HTTP response cache is disposable, but must survive
        # interrupted acquisition attempts. Its contents are never published as
        # dependency artifacts: successful installs still require PyPI SHA-256.
        pip_cache = pool.stage / 'pip-http-cache'
        if pip_cache.is_symlink() or (pip_cache.exists() and not pip_cache.is_dir()):
            raise RuntimeError('unsafe persistent native pip HTTP cache')
        pip_cache.mkdir(mode=0o700, exist_ok=True)
        npm_configs = {name: root / ('npm-' + name + '.conf') for name in ('user', 'global')}
        for path in npm_configs.values():
            write_new(path, b'')
        environ = {
            'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
            'HOME': str(home), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
            'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1',
            'PIP_CONFIG_FILE': '/dev/null', 'PIP_DISABLE_PIP_VERSION_CHECK': '1',
            'PIP_NO_INPUT': '1', 'PIP_INDEX_URL': 'https://pypi.org/simple',
            'PIP_CACHE_DIR': str(pip_cache),
            'CONDARC': '/dev/null', 'CONDA_PKGS_DIRS': str(root / 'conda-pkgs'),
            'CONDA_ENVS_DIRS': str(root / 'envs'),
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0',
            'NPM_CONFIG_USERCONFIG': str(npm_configs['user']),
            'NPM_CONFIG_GLOBALCONFIG': str(npm_configs['global']),
        }
        native = {'context': temporary, 'root': root, 'env': environ,
                  'prefixes': {}, 'bootstrapped': False}
        pool._native_runtime = native
        return native


def _native_seed_wheelhouse(pool, runtime):
    """Expose only SHA-verified wheels from successful previous pip plans.

    Native pip still chooses its own candidates from PyPI and --find-links;
    this is an exact local copy of a previously authenticated artifact, not
    a substituted version or an invented source URL.
    """
    with _NATIVE_POOL_LOCK:
        folder = runtime['root'] / 'wheelhouse'
        folder.mkdir(exist_ok=True)
        seen = runtime.setdefault('wheelhouse_indexed_plans', set())
        indexed = runtime.setdefault('wheelhouse_records', {})
        for checkpoint in sorted((pool.stage / 'metadata').glob('pip-plan-*.json')):
            if checkpoint.is_symlink() or not checkpoint.is_file():
                raise RuntimeError('unsafe native wheelhouse checkpoint path')
            if checkpoint.name in seen:
                continue
            key = checkpoint.name[len('pip-plan-'):-len('.json')]
            plan = json.loads(checkpoint.read_bytes())
            if plan.get('optional_failed'):
                seen.add(checkpoint.name)
                continue
            # This validates the checkpoint tree, solver identity, and every
            # pinned source/artifact record before any wheel is offered to pip.
            records = _read_pip_plan_tree(pool.stage, key)
            for record in records.values():
                for artifact in record['packages']:
                    if artifact['kind'] != 'wheel':
                        continue
                    filename, sha, url = (artifact.get('filename'), artifact.get('sha256'),
                                          artifact.get('url'))
                    if (not isinstance(filename, str) or Path(filename).name != filename
                            or not filename.endswith('.whl') or not SHA.fullmatch(str(sha))
                            or not isinstance(url, str)):
                        raise RuntimeError('invalid reusable native pip wheel')
                    origin = urllib.parse.urlsplit(url)
                    if (origin.scheme != 'https' or origin.hostname != 'files.pythonhosted.org'
                            or origin.username or origin.password or origin.fragment
                            or urllib.parse.unquote(origin.path.rsplit('/', 1)[-1]) != filename):
                        raise RuntimeError('untrusted reusable native pip wheel URL')
                    pool.verify_object(sha)
                    identity = (sha, url, bool(artifact.get('yanked', False)))
                    prior = indexed.get(filename)
                    if prior is not None and prior[:2] != identity[:2]:
                        raise RuntimeError('ambiguous same-name native pip wheel artifact: ' + filename)
                    indexed[filename] = (sha, url, bool(identity[2] or (prior[2] if prior else False)))
                    destination = folder / filename
                    source = pool.objects / sha[:2] / sha
                    if not destination.exists():
                        os.link(source, destination)
                    elif destination.is_symlink() or not destination.samefile(source):
                        raise RuntimeError('native pip wheelhouse file changed')
            seen.add(checkpoint.name)
        return folder


def _native_report_origin(pool, runtime, reported_url, sha):
    """Normalize an authenticated PyPI HTTPS URL or a verified local wheel."""
    parsed = urllib.parse.urlsplit(reported_url)
    if parsed.scheme == 'https' and parsed.hostname == 'files.pythonhosted.org':
        if parsed.username or parsed.password or parsed.fragment:
            raise RuntimeError('native pip reported an unsafe PyPI artifact URL')
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                                       parsed.query, '')), False
    if parsed.scheme != 'file' or parsed.netloc or parsed.query or parsed.fragment:
        raise RuntimeError('native pip plan has unpinned/non-PyPI artifact: ' + reported_url)
    path = Path(urllib.parse.unquote(parsed.path))
    wheelhouse = runtime['root'] / 'wheelhouse'
    if path.parent != wheelhouse or path.is_symlink() or not path.is_file():
        raise RuntimeError('native pip selected an untrusted local distribution')
    expected = runtime.get('wheelhouse_records', {}).get(path.name)
    if expected is None or expected[0] != sha:
        raise RuntimeError('native pip local wheel lacks exact verified PyPI identity')
    source = pool.objects / sha[:2] / sha
    if not path.samefile(source):
        raise RuntimeError('native pip local wheel differs from SHA-verified CAS object')
    pool.verify_object(sha)
    return expected[1], expected[2]


class _NativePipByteProgress:
    """One terminal line for concurrent pip transfers, with real byte denominators.

    Pip's documented raw progress reports actual CURRENT and TOTAL bytes for
    individual downloads; TOTAL=0 means the server did not supply a size.
    Unknown future downloads make a global fetch percentage mathematically
    unavailable. Therefore the bar is strictly for one currently observed file.
    """
    _line = re.compile(rb'Progress ([0-9]+) of ([0-9]+)\s*\Z')

    def __init__(self, interval):
        if type(interval) is not int or interval < 1:
            raise RuntimeError('invalid Pip byte progress interval')
        self.interval = interval
        self.lock = threading.Lock()
        self.active = {}
        self.transferred = 0
        self.sample_bytes = 0
        self.sample_time = time.monotonic()
        self.stop_event = threading.Event()
        self.thread = None

    def begin(self, identity):
        with self.lock:
            if identity in self.active:
                raise RuntimeError('duplicate pip progress identity')
            self.active[identity] = {'current': 0, 'total': 0, 'seen': False}
            if self.thread is None:
                self.thread = threading.Thread(target=self._monitor, daemon=True,
                                               name='native-pip-byte-progress')
                self.thread.start()

    def observe(self, identity, line):
        match = self._line.fullmatch(line.strip())
        if match is None:
            return False
        current, total = map(int, match.groups())
        with self.lock:
            state = self.active[identity]
            previous = state['current'] if state['seen'] else 0
            # A smaller current count starts a NEW file, not negative bytes.
            delta = current if state['seen'] and current < previous else max(0, current - previous)
            self.transferred += delta
            state.update(current=current, total=total, seen=True)
        return True

    def snapshot(self):
        """Return immutable byte counters; never invent a global total."""
        with self.lock:
            observed = [
                (identity, row['current'], row['total'])
                for identity, row in self.active.items() if row['seen']
            ]
            known = [item for item in observed if item[2] > 0 and item[1] <= item[2]]
            # Show the largest currently observable transfer; no task-count weighting.
            selected = max(known, key=lambda row: (row[2], row[1], row[0])) if known else None
            return {'bytes': self.transferred, 'jobs': len(self.active),
                    'observed': len(observed), 'file': selected}

    def _render(self):
        now = time.monotonic()
        with self.lock:
            delta_time = now - self.sample_time
            speed = ((self.transferred - self.sample_bytes) / delta_time
                     if delta_time > 0 else 0.0)
            self.sample_time = now
            self.sample_bytes = self.transferred
        state = self.snapshot()
        prefix = ('[pool] Pip transfers: %.1f MiB observed | %.2f MiB/s | %d pip active | '
                  % (state['bytes'] / 1048576, speed / 1048576, state['jobs']))
        selected = state['file']
        if selected is None:
            return prefix + 'resolving / download size unknown (no global percent)'
        identity, current, total = selected
        width = 20
        filled = min(width, current * width // total)
        return (prefix + '%s [%s%s] %.1f%% (%.1f/%.1f MiB, this file only)' % (
            identity, '#' * filled, '-' * (width - filled),
            100 * current / total, current / 1048576, total / 1048576))

    def _monitor(self):
        while not self.stop_event.wait(self.interval):
            with self.lock:
                running = bool(self.active)
            if running:
                if _POOL_PROGRESS is not None:
                    _POOL_PROGRESS.pip_update(self.snapshot())
                else:
                    print('\r\x1b[K' + self._render(), end='', flush=True)

    def end(self, identity):
        with self.lock:
            if identity not in self.active:
                raise RuntimeError('unknown pip progress identity')
            self.active.pop(identity)
            remaining = bool(self.active)
        if not remaining:
            if _POOL_PROGRESS is not None:
                _POOL_PROGRESS.pip_update(self.snapshot())
            else:
                print('\r\x1b[K' + self._render(), flush=True)

    def close(self):
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join()


def _native_run_pip_with_byte_progress(command, runtime, environment, timeout):
    """Execute pip with bounded elapsed/stall budgets and byte-level feedback.

    A per-command total deadline prevents unbounded backtracking. An independent
    no-observed-activity deadline prevents a worker from holding a slot through
    silent network stalls. Both are configured, never inferred from task counts.
    Only a small diagnostic tail is retained for failures.
    """
    import signal
    total_limit, stall_limit = _native_pip_timeouts()
    total_limit = min(timeout, total_limit)
    with _NATIVE_POOL_LOCK:
        meter = runtime.get('_pip_byte_progress')
        if meter is None:
            meter = _NativePipByteProgress(_conda_progress_interval())
            runtime['_pip_byte_progress'] = meter
    identity = hashlib.sha256(
        ('\0'.join(command) + '\0' + str(threading.get_ident())).encode()).hexdigest()[:12]
    meter.begin(identity)
    tail = bytearray()
    errors = []
    activity_lock = threading.Lock()
    started = time.monotonic()
    last_activity = [started]
    last_progress = [None]
    process = None
    try:
        process = subprocess.Popen(command, cwd=runtime['root'], env=environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True)

        def consume():
            try:
                for line in iter(process.stdout.readline, b''):
                    is_progress = meter.observe(identity, line)
                    with activity_lock:
                        if is_progress:
                            # Repeated identical byte counters are not progress.
                            if last_progress[0] != line:
                                last_progress[0] = line
                                last_activity[0] = time.monotonic()
                        elif line.strip():
                            last_activity[0] = time.monotonic()
                    if is_progress:
                        continue
                    tail.extend(line)
                    if len(tail) > 65536:
                        del tail[:-65536]
            except BaseException as exc:
                errors.append(exc)
            finally:
                process.stdout.close()

        reader = threading.Thread(target=consume, daemon=True,
                                  name='native-pip-output-reader')
        reader.start()
        timed_out = None
        while process.poll() is None:
            now = time.monotonic()
            with activity_lock:
                idle = now - last_activity[0]
            elapsed = now - started
            if elapsed >= total_limit:
                timed_out = ('total', total_limit)
                break
            if idle >= stall_limit:
                timed_out = ('stall', stall_limit)
                break
            # Poll at the same versioned cadence as the progress display.
            remaining = min(total_limit - elapsed, stall_limit - idle,
                            _conda_progress_interval())
            try:
                process.wait(timeout=max(0.001, remaining))
            except subprocess.TimeoutExpired:
                pass
        if timed_out is not None:
            # Kill the entire PEP 517 subprocess group, including nested hooks.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            reader.join()
            kind, limit = timed_out
            if kind == 'stall':
                diagnostic = tail[-5000:].decode(errors='replace')
                raise RuntimeError('native pip emitted no new output/download bytes for '
                                   + str(limit) + ' seconds; last output: ' + diagnostic)
            raise subprocess.TimeoutExpired(command, limit, output=bytes(tail))
        reader.join()
        if errors:
            raise RuntimeError('pip output-reader failed: ' + str(errors[0])) from errors[0]
        if process.returncode:
            raise RuntimeError('native package command failed (exit '
                + str(process.returncode) + '): ' + tail[-5000:].decode(errors='replace'))
        return bytes(tail)
    finally:
        meter.end(identity)


def _native_run(argv, runtime, *, timeout=7200, interpreter=None):
    """Run an actual package tool with a complete, per-invocation interpreter PATH.

    Build backends and installed command entrypoints can invoke
    ``#!/usr/bin/env python`` regardless of their own executable name. Bind
    that name to the exact locked Python selected for this operation, without
    modifying global state or contaminating parallel target environments.
    The Miniconda prefix is discoverable even while its bootstrap is underway.
    """
    command = [str(arg) for arg in argv]
    if not command:
        raise RuntimeError('empty native package command')
    environment = dict(runtime['env'])
    base_bin = Path(runtime['root']) / 'conda' / 'bin'
    paths = [str(base_bin)]
    if interpreter is not None:
        selected = Path(interpreter)
        if (not selected.is_absolute() or not selected.is_file()
                or not os.access(selected, os.X_OK)):
            raise RuntimeError('native interpreter is not an executable absolute file: ' + str(selected))
        executable_dir = selected.parent
        if selected.name != 'python':
            # Never add an alias to a host-owned directory. Long /usr/bin/python3.X
            # names use a per-runtime, per-interpreter private launcher instead.
            identity = hashlib.sha256(os.fsencode(str(selected))).hexdigest()
            executable_dir = Path(runtime['root']) / 'python-launchers' / identity
            executable_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
            alias = executable_dir / 'python'
            try:
                alias.symlink_to(selected)
            except FileExistsError:
                pass
            if not alias.is_symlink() or os.readlink(alias) != str(selected):
                raise RuntimeError('native interpreter launcher identity mismatch')
        paths.insert(0, str(executable_dir))
    inherited = environment.get('PATH', '')
    if inherited:
        paths.append(inherited)
    environment['PATH'] = os.pathsep.join(paths)
    # The raw pip progress protocol reports CURRENT and TOTAL in real bytes.
    # A global task percentage is intentionally never inferred from group counts.
    for index in range(len(command) - 2):
        if command[index:index + 3] == ['-m', 'pip', 'install']:
            command.insert(index + 3, '--progress-bar=raw')
            return _native_run_pip_with_byte_progress(command, runtime, environment, timeout)
    output = subprocess.run(command, cwd=runtime['root'], env=environment,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=timeout)
    if output.returncode:
        raise RuntimeError('native package command failed (exit '
            + str(output.returncode) + '): ' + output.stdout[-5000:].decode(errors='replace'))
    return output.stdout


def _native_build_requirements(scratch):
    """Read the distributions installed by pip's real static and dynamic build hooks.

    --no-clean retains pip's isolated build environments. Each metadata command
    gets a private TMPDIR, so concurrent resolutions cannot exchange evidence.
    Each site-packages layer is recorded separately: different backends may need
    different versions of the same build distribution.
    """
    groups = set()
    for environment in sorted(Path(scratch).glob('pip-build-env-*')):
        if environment.is_symlink() or not environment.is_dir():
            raise RuntimeError('unsafe native build environment')
        layers = defaultdict(set)
        for path in environment.rglob('*'):
            if path.is_symlink():
                # Package entrypoints may legitimately be symlinks. Do not
                # inspect their contents or allow symlinks on metadata paths.
                # Directory symlinks could conceal an unrecorded build layer.
                if path.is_dir() or path.name == 'METADATA' or path.name.endswith('.dist-info'):
                    raise RuntimeError('symlink in native build metadata path')
                continue
            if path.name != 'METADATA' or not path.parent.name.endswith('.dist-info'):
                continue
            if not path.is_file() or path.stat().st_size > MAX_SOURCE:
                raise RuntimeError('invalid installed build metadata')
            name, version, _requires, _extras = _core_metadata_fields(path.read_bytes())
            requirement = _parse_registry_requirement(name + '==' + version)
            layers[path.parent.parent].add(str(requirement))
        for requirements in layers.values():
            groups.add(tuple(sorted(requirements)))
    return [list(group) for group in sorted(groups)]


def _native_metadata_command(argv, runtime, directory):
    """Execute the production pip command and capture its build-time closure."""
    with tempfile.TemporaryDirectory(prefix='build-metadata-', dir=directory) as temporary:
        local = {**runtime, 'env': {**runtime['env'], 'TMPDIR': temporary}}
        _native_run([*argv, '--no-clean'], local, interpreter=argv[0])
        return _native_build_requirements(temporary)


def _native_bootstrap(pool, runtime):
    if runtime['bootstrapped']:
        return runtime['root'] / 'conda' / 'bin' / 'conda'
    path = Path(__file__).resolve().parents[1] / 'config/preparation.toml'
    with path.open('rb') as stream:
        bootstrap = tomllib.load(stream)['bootstrap']
    name = bootstrap['miniconda_archive']
    sha = bootstrap['miniconda_sha256']
    if (not re.fullmatch(r'[A-Za-z0-9_.+-]+\.sh', name) or
            not SHA.fullmatch(str(sha))):
        raise RuntimeError('invalid pinned Miniconda bootstrap')
    pool.download('https://repo.anaconda.com/miniconda/' + name,
                  'bootstrap', 'miniconda-installer', sha=sha)
    archive = pool.objects / sha[:2] / sha
    pool.verify_object(sha)
    # The Miniconda installer validates $0 and requires its .sh basename.
    # Preserve the immutable CAS object: link its verified bytes into the
    # private bootstrap scratch instead of copying or renaming the CAS.
    installer = runtime['root'] / name
    os.link(archive, installer)
    destination = runtime['root'] / 'conda'
    _native_run(['/bin/bash', installer, '-b', '-p', destination], runtime)
    executable = destination / 'bin' / 'conda'
    if not executable.is_file():
        raise RuntimeError('pinned Miniconda bootstrap did not install conda')
    runtime['bootstrapped'] = True
    return executable


def _native_locked_python(pool, target):
    """Obtain actual CPython from the checked lock, not the Ubuntu host Python."""
    target = _coerce_target(target)
    runtime = _native_pool_runtime(pool)
    sha = target.python_artifact_sha256
    if sha is None:
        return None  # golden system interpreter uses pip's explicit cross-target mode
    if not SHA.fullmatch(sha):
        raise RuntimeError('target Python does not have a locked package identity')
    with _NATIVE_POOL_LOCK:
        if sha in runtime['prefixes']:
            return runtime['prefixes'][sha]
        candidates = []
        lock = pool.conda_lock
        for env in lock['environments'].values():
            for transaction in env['transactions']:
                packages = transaction['packages']
                if sha in packages:
                    candidates.append((len(packages), transaction['key'], packages))
        if not candidates:
            raise RuntimeError('locked target interpreter artifact absent from Conda transactions: '+sha)
        _length, key, packages = min(candidates, key=lambda row: (row[0], row[1]))
        if lock['artifacts'][sha]['version'] != target.python_full_version:
            raise RuntimeError('locked native Python differs from target identity')
        conda = _native_bootstrap(pool, runtime)
        archive_root = runtime['root'] / 'archives'
        archive_root.mkdir(exist_ok=True)
        explicit = []
        for package_sha in packages:
            item = lock['artifacts'][package_sha]
            pool.download(item['url'], 'conda', key, sha=package_sha)
            filename = urllib.parse.urlsplit(item['url']).path.rsplit('/', 1)[-1]
            if (not filename or Path(filename).name != filename or
                    not filename.endswith(('.conda', '.tar.bz2'))):
                raise RuntimeError('invalid locked Conda artifact filename')
            archive = archive_root / package_sha / filename
            archive.parent.mkdir(parents=True, exist_ok=True)
            if not archive.exists():
                os.link(pool.objects / package_sha[:2] / package_sha, archive)
            if digest(archive) != package_sha:
                raise RuntimeError('locked interpreter dependency was modified')
            explicit.append(archive.as_uri())
        explicit_file = runtime['root'] / ('python-' + sha + '.explicit')
        explicit_file.write_text('@EXPLICIT\n' + '\n'.join(explicit) + '\n')
        prefix = runtime['root'] / 'envs' / sha
        # Conda's installed entry-point shebang may use /usr/bin/env for a
        # long prefix. Invoke its own interpreter explicitly, independent of
        # the fetch host's PATH and kernel shebang length constraints.
        _native_run([conda.parent / 'python', '-m', 'conda',
                     'create', '--offline', '--yes', '--prefix', prefix,
                     '--file', explicit_file], runtime, timeout=14400,
                     interpreter=conda.parent / 'python')
        python = prefix / 'bin' / 'python'
        version = _native_run([python, '-c',
             'import platform; print(platform.python_version())'], runtime, interpreter=python).decode().strip()
        if version != target.python_full_version:
            raise RuntimeError('materialized locked interpreter has the wrong patch version')
        _native_run([python, '-m', 'pip', '--version'], runtime, interpreter=python)
        runtime['prefixes'][sha] = python
        return python



def _native_acquired_archive(pool,runtime,url,sha,category,key):
    """Import pip's HTTP-cache bytes into CAS instead of fetching them twice."""
    already=pool.objects/sha[:2]/sha
    if already.is_file():
        pool.verify_object(sha)
        with pool._state_lock:pool.by_url[url]=sha
        return pool.reference(sha,category,key,already.stat().st_size)
    with _NATIVE_POOL_LOCK:
        index=runtime.setdefault('http_content_index',{})
        cache_root=Path(runtime['env']['PIP_CACHE_DIR'])
        if cache_root.is_symlink() or not cache_root.is_dir():
            raise RuntimeError('unsafe native pip HTTP cache')
        for body in cache_root.rglob('*.body'):
            if body.is_symlink() or not body.is_file():
                raise RuntimeError('unsafe pip HTTP cache body')
            if body in runtime.setdefault('http_content_scanned',set()):
                continue
            index[digest(body)]=body
            runtime['http_content_scanned'].add(body)
        cached=index.get(sha)
        if cached is not None and cached.is_file() and digest(cached)==sha:
            # Never hardlink a mutable pip HTTP cache file into permanent CAS.
            target=pool.stage/'downloads'/('pip-cached-'+sha)
            if not target.exists():
                shutil.copyfile(cached,target)
            if digest(target)!=sha:
                raise RuntimeError('pip HTTP cache contents changed during archival')
            result=pool.put(target,category,key,verified_sha=sha,durable=True)
            with pool._state_lock:pool.by_url[url]=sha
            return result
    # The backend may explicitly mark an archive as non-cacheable. Downloading
    # its pinned bytes is then necessary; no unverified local data is accepted.
    return pool.download(url,category,key,sha=sha)


def _native_acquire_build_dependencies(pool,target,packages):
    """Acquire the observed PEP 517 closure before publishing its parent plan."""
    plans = {}
    groups = set()
    for row in packages:
        if row['kind']!='sdist':continue
        observed = row.get('build_requirements')
        if not isinstance(observed, list):
            raise RuntimeError('native source plan lacks observed build dependencies')
        for requirements in observed:
            if not isinstance(requirements, list) or not all(isinstance(item, str) for item in requirements):
                raise RuntimeError('invalid observed build dependency group')
            if requirements:
                groups.add(tuple(sorted(set(requirements))))
    for requires in sorted(groups):
        key=pip_group_key(target,requires)
        acquire_pip_group(pool,key,{
            'target':target.as_dict(),'requirements':sorted(set(requires)),
            'constraints':[],'no_deps':False,'required':True,
            'tasks':[],'steps':['observed PEP517 build environment']})
        plans[key] = digest(pool.stage/'metadata'/('pip-plan-'+key+'.json'))
    return plans



def _native_source_candidate_metadata(pool, candidate, key, target):
    """Read the *real target* PEP 517 metadata for one SHA-verified sdist.

    This path is used for every sdist under the verified graph solver. Wheels
    instead use PyPI's hash-verified core-metadata sidecars or their own METADATA.
    Neither the metadata hook nor the installer gets an unbounded mixed graph.
    """
    target = _coerce_target(target)
    if candidate['kind'] != 'sdist':
        raise RuntimeError('native source hook requires a source distribution')
    sha, url = _candidate_artifact_identity(candidate)
    filename = candidate['filename']
    parsed = urllib.parse.urlsplit(url)
    if (not isinstance(filename, str) or Path(filename).name != filename
            or filename in {'.', '..'}
            or not filename.endswith(('.tar.gz', '.tar.bz2', '.zip'))
            or parsed.scheme != 'https' or parsed.hostname != 'files.pythonhosted.org'
            or urllib.parse.unquote(parsed.path.rsplit('/', 1)[-1]) != filename
            or parsed.username or parsed.password or parsed.fragment):
        raise RuntimeError('untrusted native source archive identity')
    # The CAS is authoritative: pip never gets a downloaded archive without
    # verifying its expected digest and exact PyPI distribution provenance.
    actual = pool.download(url, 'python-source', key, sha=sha)
    if actual != sha:
        raise RuntimeError('native source artifact identity differs')
    pool.verify_object(sha)
    runtime = _native_pool_runtime(pool)
    python = _native_locked_python(pool, target)
    if python is None:
        raise RuntimeError('source metadata requires a locked target Python')
    root = (runtime['root'] / 'source-metadata' /
            _target_fingerprint(target) / sha)
    root.mkdir(parents=True, exist_ok=True)
    source = pool.objects / sha[:2] / sha
    archive = root / filename
    if not archive.exists():
        os.link(source, archive)
    if archive.is_symlink() or not archive.is_file() or not archive.samefile(source):
        raise RuntimeError('native source archive was replaced')
    report = root / 'pip-report.json'
    command = [python, '-m', 'pip', 'install', '--use-pep517', '--dry-run',
               '--ignore-installed', '--no-deps', '--report', report,
               archive]
    observed_builds = _native_metadata_command(command, runtime, root)
    data = json.loads(report.read_bytes())
    installs = data.get('install')
    if not isinstance(installs, list) or len(installs) != 1:
        raise RuntimeError('native single-source PEP 517 report is incomplete')
    installed = installs[0]
    metadata = installed.get('metadata')
    download = installed.get('download_info') or {}
    if not isinstance(metadata, dict) or not isinstance(download, dict):
        raise RuntimeError('native single-source report has invalid metadata')
    origin = download.get('url')
    location = urllib.parse.urlsplit(origin) if isinstance(origin, str) else None
    if (location is None or location.scheme != 'file' or location.netloc
            or location.query or location.fragment
            or Path(urllib.parse.unquote(location.path)) != archive):
        raise RuntimeError('native single-source report differs from verified CAS input')
    name = metadata.get('name')
    version = metadata.get('version')
    requirements = metadata.get('requires_dist') or []
    extras = metadata.get('provides_extra') or []
    if (not isinstance(name, str) or not isinstance(version, str)
            or _normalized_package_name(name) != _normalized_package_name(candidate['name'])
            or _packaging_symbols()[2](version) != _packaging_symbols()[2](candidate['version'])
            or not isinstance(requirements, list) or not all(isinstance(item, str) for item in requirements)
            or not isinstance(extras, list) or not all(isinstance(item, str) for item in extras)):
        raise RuntimeError('native single-source package identity/requirements differ')
    # The selected package's PEP 517 build environments were inspected before
    # TMPDIR cleanup. Their exact distributions are recursively acquired later.
    return {'kind': 'sdist', 'name': name, 'version': version,
            'filename': filename, 'url': url, 'sha256': sha,
            'requirements': sorted(set(normalize_legacy_source_requirement(row)
                                       for row in requirements)),
            'provides_extra': sorted(set(extras)),
            'build_requirements': observed_builds,
            **_candidate_yank_provenance(candidate)}


def _native_solver_cache(pool):
    """Share single-flight PyPI metadata and verified source results across groups."""
    with pool._state_lock:
        cache = getattr(pool, '_native_verified_solver_cache', None)
        if cache is None:
            cache = {'release_metadata': _SingleFlightCache(),
                     'artifact_metadata': _SingleFlightCache(),
                     'releases': _SingleFlightCache(),
                     'native_source_probe': _native_source_candidate_metadata,
                     'sources_require_locked_python': True}
            pool._native_verified_solver_cache = cache
        return cache


def _native_resolve_registry(pool, target, reqs, constraints, key, *, no_deps=False, preferred_versions=None):
    """Resolve the whole graph using verified PyPI metadata, not pip backtracking.

    The existing conflict-directed backjump solver chooses one globally valid
    candidate per distribution. Wheels are inspected without installation, and
    each source distribution uses one isolated PEP 517 --no-deps metadata hook.
    Large transitive graphs are never passed to a single pip install command.
    The completed artifact graph is independently validated by _write_pip_plan.
    """
    target = _coerce_target(target)
    if _POOL_PROGRESS is None:
        print('[pool] verified registry graph: ' + key + ' (' +
              str(len(set(reqs))) + ' direct requirements)', flush=True)
    cache = _native_solver_cache(pool)
    activity = cache.get('prefetch_controller')
    if activity is not None:
        activity.enter()
    try:
        return _resolve_registry_plan(pool, target, reqs, constraints, key,
                                      no_deps=no_deps, resolver_cache=cache,
                                      materialize=True, preferred_versions=preferred_versions)
    finally:
        if activity is not None:
            activity.leave()


def _native_project_requirements(metadata, target, extras):
    """Evaluate local extras once, including self references, for this target.

    Selected local dependencies become roots of separate resolver requests;
    retaining their ``extra`` markers there would silently deactivate them.
    """
    target = _coerce_target(target)
    Requirement = _packaging_symbols()[0]
    project = _normalized_package_name(metadata['name'])
    requirements = [Requirement(normalize_legacy_source_requirement(row))
                    for row in metadata.get('requires_dist') or []]
    selected = set(extras)
    while True:
        before = set(selected)
        for requirement in requirements:
            if (requirement.url is None and _normalized_package_name(requirement.name) == project
                    and _marker_active(requirement, target, selected)):
                if requirement.specifier and not requirement.specifier.contains(metadata['version'], prereleases=True):
                    raise RuntimeError('local self dependency rejects pinned project version')
                selected.update(requirement.extras)
        if selected == before:
            break
    dependencies = set(); remote = set()
    for requirement in requirements:
        if not _marker_active(requirement, target, selected):
            continue
        if requirement.url is None and _normalized_package_name(requirement.name) == project:
            continue
        requirement.marker = None
        if requirement.url is not None:
            reference = vcs_reference(str(requirement))
            if reference is None:
                raise RuntimeError('native project returned an unpinned non-Git direct URL')
            remote.add(reference)
        else:
            dependencies.add(str(requirement))
    return dependencies, remote


def _native_populate_submodules(pool, runtime, mirror, commit, checkout, ancestry=()):
    """Reproduce complete pinned submodule worktrees using local mirrors only.

    Every clone is restricted to the file transport, uses an exact checked
    gitlink, and performs no fetch.  Recursive sources are obtained from their
    pinned origins separately, so an arbitrary build backend cannot trigger an
    implicit upstream checkout through pip.
    """
    from pathlib import Path
    checkout = Path(checkout)
    entries_cache = runtime.setdefault('pinned_submodule_entries', {})
    identity = (str(mirror), commit)
    if identity not in entries_cache:
        entries_cache[identity] = _git_submodule_entries(mirror, commit)
    verified_mirrors = runtime.setdefault('pinned_submodule_mirrors', {})
    git_runtime = {**runtime, 'env': {**runtime['env'], 'GIT_ALLOW_PROTOCOL': 'file'}}
    for name, path, repo, sha in entries_cache[identity]:
        node = (repo, sha)
        if node in ancestry or len(ancestry) >= MAX_VCS_CLOSURE:
            raise RuntimeError('cyclic or unbounded pinned Git submodule checkout')
        relative = Path(path)
        destination = checkout / relative
        if not destination.resolve().is_relative_to(checkout.resolve()):
            raise RuntimeError('pinned submodule escapes its checkout')
        for parent in (checkout, *(checkout.joinpath(*relative.parts[:i])
                                   for i in range(1, len(relative.parts) + 1))):
            if parent.is_symlink():
                raise RuntimeError('pinned submodule path traverses a symlink')
        if node not in verified_mirrors:
            verified_mirrors[node] = mirror_commits(pool.stage, repo, {sha}, label='git-extra')
        source = verified_mirrors[node]
        # Initialize private worktree configuration so `git submodule status`
        # recognizes the checkout as initialized, not merely present on disk.
        # The override never modifies the authenticated upstream .gitmodules.
        _native_run(['git', '-C', checkout, 'config', '--local',
                     'submodule.' + name + '.url', str(source)], git_runtime)
        _native_run(['git', '-C', checkout, 'config', '--local',
                     'submodule.' + name + '.update', 'checkout'], git_runtime)
        # -c takes precedence even if the child clone has unexpected config.
        # GIT_ALLOW_PROTOCOL=file blocks every network transport in child Git.
        _native_run([
            'git', '-c', 'submodule.' + name + '.url=' + str(source),
            '-c', 'submodule.' + name + '.update=checkout',
            '-C', checkout, 'submodule', 'update', '--init', '--no-fetch',
            '--', path,
        ], git_runtime)
        actual = _native_run(['git', '-C', destination, 'rev-parse', 'HEAD'], git_runtime).decode().strip()
        if actual != sha:
            raise RuntimeError('materialized Git submodule differs from pinned gitlink: ' + path)
        _native_populate_submodules(pool, runtime, source, sha, destination, (*ancestry, node))

def _native_local_metadata(pool,target,mirror,commit,commands,extras):
    """Run the pinned local project's real build backend for metadata only.

    This replaces attempting to emulate arbitrary setup.py dataflow. The source
    checkout is private to an unprivileged host process; it cannot alter the
    original immutable Git mirror or the system's Python environments.
    """
    target=_coerce_target(target)
    runtime=_native_pool_runtime(pool)
    python=_native_locked_python(pool,target)
    if python is None:
        raise RuntimeError('local project metadata requires a locked target interpreter')
    identity=hashlib.sha256(json.dumps({
        'mirror':str(mirror),'commit':commit,'target':target.as_dict(),
        'commands':commands,'extras':sorted(extras)},sort_keys=True).encode()).hexdigest()
    completed = runtime.setdefault('local_metadata', {})
    if identity in completed:
        dependencies, remote = completed[identity]
        return set(dependencies), set(remote)
    checkout=runtime['root']/'local-sources'/identity
    checkout.parent.mkdir(exist_ok=True)
    _native_run(['git','clone','--quiet','--shared','--no-checkout',str(mirror),str(checkout)],runtime)
    _native_run(['git','-C',str(checkout),'checkout','--quiet','--detach',commit],runtime)
    _native_populate_submodules(pool, runtime, mirror, commit, checkout)
    from pathlib import Path
    for entry in checkout.rglob('*'):
        if (not entry.is_file() or entry.is_symlink() or entry.stat().st_size>12*1024*1024
                or entry.name not in {'setup.py','setup.cfg','pyproject.toml'}):
            continue
        # Exact supported textual setup transformations, never shell execution.
        rel=entry.relative_to(checkout).as_posix()
        try:old=entry.read_text()
        except UnicodeError:continue
        updated=transformed_source('metadata',rel,old,commands)
        if updated is not None and updated!=old:
            entry.write_text(updated)
    report=runtime['root']/'plans'/('local-'+identity+'.json')
    report.parent.mkdir(parents=True, exist_ok=True)
    argv=[python,'-m','pip','install','--use-pep517','--dry-run','--ignore-installed','--no-deps',
          '--report',report,str(checkout)+('['+','.join(sorted(extras))+']' if extras else '')]
    observed = _native_metadata_command(argv, runtime, report.parent)
    _native_acquire_build_dependencies(pool, target, [
        {'kind': 'sdist', 'build_requirements': observed}])
    result=json.loads(report.read_text())
    installs=result.get('install') or []
    if len(installs)!=1:
        raise RuntimeError('local project metadata produced an ambiguous plan')
    dependencies, remote = _native_project_requirements(installs[0]['metadata'], target, extras)
    completed[identity] = (frozenset(dependencies), frozenset(remote))
    return dependencies,remote

_STATIC_LOCAL_METADATA_LOCK = threading.Lock()


def _static_native_local_metadata(*args):
    """Serialize local PEP 517 scratch mutations, not their own internal I/O workers.

    A separate lock is essential: holding _NATIVE_POOL_LOCK while invoking a
    resolver would deadlock its metadata executor when it needs that lock.
    """
    with _STATIC_LOCAL_METADATA_LOCK:
        return _native_local_metadata(*args)


def _native_close(pool):
    runtime = getattr(pool, '_native_runtime', None)
    if runtime is not None:
        progress = runtime.get('_pip_byte_progress')
        if progress is not None:
            progress.close()
        runtime['context'].cleanup()
        pool._native_runtime = None
    # Only the successful acquisition path calls _native_close. Do not carry
    # disposable pip response-cache bytes into published dependency inventory.
    cache = pool.stage / 'pip-http-cache'
    if cache.is_symlink():
        raise RuntimeError('unsafe native pip cache cleanup path')
    if cache.is_dir():
        shutil.rmtree(cache)

def _validate_pip_plan_graph(plan):
    """Independently check the complete recorded graph before checkpoint/reuse."""
    target=_coerce_target(plan['target'])
    expected_policy={'schema':PIP_PLAN_SCHEMA,'name':PIP_RESOLVER_POLICY,
                     'target_fingerprint':_target_fingerprint(target),'runtime':_resolver_runtime_identity()}
    if plan.get('resolver_policy')!=expected_policy:
        raise ValueError('pip checkpoint resolver policy/runtime differs')
    if type(plan.get('no_deps')) is not bool:raise ValueError('invalid pip checkpoint no_deps')
    for field in ('requested','constraints'):
        if not isinstance(plan.get(field),list) or not all(isinstance(row,str) for row in plan[field]):
            raise ValueError('invalid pip checkpoint '+field)
    constraints=_constraint_map(plan['constraints'],target)
    records={}
    for row in plan['packages']:
        name=_normalized_package_name(row['name'])
        if name in records:raise ValueError('duplicate package in pip closure: '+name)
        if not isinstance(row.get('requirements'),list) or not all(isinstance(raw,str) for raw in row['requirements']):
            raise ValueError('invalid pip closure dependency metadata')
        records[name]=row
    pending=[_parse_registry_requirement(raw) for raw in plan['requested']]
    pending=[req for req in pending if _marker_active(req,target)]
    extras=defaultdict(set);expanded={};reached=set()
    while pending:
        req=pending.pop();name=_normalized_package_name(req.name)
        record=records.get(name)
        if record is None or not _candidate_satisfies(record,[req],constraints.get(name,[])):
            raise ValueError('pip closure does not satisfy '+str(req))
        reached.add(name);extras[name].update(req.extras)
        active=frozenset(extras[name])
        if expanded.get(name)==active:continue
        expanded[name]=active
        if plan['no_deps']:continue
        for raw in record['requirements']:
            dep=_parse_registry_requirement(raw)
            if _marker_active(dep,target,active):pending.append(dep)
    if reached!=set(records):raise ValueError('pip closure has unreferenced packages')


def _pip_plan_artifact_shas(plan):
    if not isinstance(plan,dict) or plan.get('optional_failed'):
        raise ValueError('pip plan is not a successful reusable closure')
    packages=plan.get('packages')
    if not isinstance(packages,list):
        raise ValueError('pip plan has invalid package artifacts')
    shas=[]
    for row in packages:
        if (not isinstance(row,dict) or row.get('kind') not in {'wheel','sdist'}
                or not isinstance(row.get('name'),str) or not isinstance(row.get('version'),str)
                or not isinstance(row.get('filename'),str) or Path(row['filename']).name!=row['filename']
                or not SHA.fullmatch(str(row.get('sha256','')))):
            raise ValueError('invalid pip package artifact row')
        shas.append(row['sha256'])
    required_builds = set()
    for row in packages:
        for requirements in row.get('build_requirements', []):
            if requirements:
                required_builds.add(pip_group_key(plan['target'], requirements))
    if required_builds != set(plan.get('build_plans', {})):
        raise ValueError('pip checkpoint omits or adds observed build dependency plans')
    _validate_pip_plan_graph(plan)
    return shas


def _marker_active(requirement,target,extras=()):
    if requirement.marker is None:return True
    # Extras add requirements to the base distribution; they cannot remove its
    # dependencies, including explicit `extra == ""` metadata.
    contexts=sorted({'', *extras})
    for extra in contexts:
        env=dict(target.markers);env['extra']=extra
        try:
            if requirement.marker.evaluate(env):return True
        except Exception as exc:
            raise RuntimeError('unable to evaluate PEP 508 marker: '+str(requirement)) from exc
    return False


def _parse_registry_requirement(value):
    Requirement,_,_,_,_=_packaging_symbols()
    normalized=normalize_legacy_source_requirement(str(value))
    try:req=Requirement(normalized)
    except Exception as exc:raise RuntimeError('invalid registry requirement: '+str(value)) from exc
    if req.url:raise RuntimeError('registry resolver does not accept direct URLs: '+str(value))
    return req


def _constraint_map(rows,target):
    result=defaultdict(list)
    for row in sorted(set(rows)):
        req=_parse_registry_requirement(row)
        if not _marker_active(req,target):continue
        result[_normalized_package_name(req.name)].append(req)
    return result


def _wheel_rank(filename,target):
    try:_name,_version,_build,tags=_parse_wheel_filename(filename)
    except Exception:return None
    order={tag:index for index,tag in enumerate(target.tags)}
    ranks=[order[str(tag)] for tag in tags if str(tag) in order]
    return min(ranks) if ranks else None


def _requires_python_compatible(raw, target_python):
    """Check the target against PyPI's declared Requires-Python without guessing.

    Historical registries contain versions quoted as strings, e.g. >= '2.7',
    and inclusive lower-bound wildcards such as >=3.5.*. Only these precise
    *syntactic* anomalies are normalized. The full original conjunction is
    then parsed and evaluated by packaging; any other invalidity is fatal.
    """
    _, SpecifierSet, _, _, _ = _packaging_symbols()
    if not isinstance(raw, str) or not raw.strip():
        raise RuntimeError('invalid Requires-Python metadata: ' + repr(raw))
    value = raw.strip()
    try:
        spec = SpecifierSet(value)
    except ValueError as exc:
        pieces = []
        changed = False
        for part in value.split(','):
            token = part.strip()
            # The quote must surround the *whole* version operand. Matching
            # quotation marks and no embedded whitespace, escapes or extra
            # suffixes prevent discarding meaningful constraints.
            quoted = re.fullmatch(
                r'''(===|~=|==|!=|<=|>=|<|>)\s*(['"])([^\s'"\\,]+)\2''', token)
            if quoted is not None:
                normalized = quoted.group(1) + quoted.group(3)
                try:
                    # A quoted operand is accepted ONLY if the unquoted
                    # comparator has legitimate packaging syntax. The old
                    # inclusive wildcard exception is checked separately.
                    SpecifierSet(normalized)
                except ValueError:
                    if re.fullmatch(r'>=\s*\d+(?:\.\d+)*\.\*', normalized) is None:
                        raise RuntimeError('invalid Requires-Python metadata: ' + repr(value)) from exc
                token = normalized
                changed = True
            inclusive_lower = re.fullmatch(r'>=\s*(\d+(?:\.\d+)*)\.\*', token)
            if inclusive_lower is not None:
                token = '>=' + inclusive_lower.group(1)
                changed = True
            pieces.append(token)
        if not changed:
            raise RuntimeError('invalid Requires-Python metadata: ' + repr(value)) from exc
        try:
            spec = SpecifierSet(','.join(pieces))
        except ValueError as malformed:
            raise RuntimeError('invalid Requires-Python metadata: ' + repr(value)) from malformed
    return spec.contains(target_python, prereleases=True)


def _release_artifacts(name,version,files,target,*,allow_yanked=False):
    """Return deterministic compatible artifacts for one release, wheel first.

    PyPI contains historical release buckets with files whose filename identity
    belongs to a neighbouring release.  Such files are not candidates for this
    release.  Apply target-wheel admission before interpreting metadata so an
    irrelevant foreign-platform wheel cannot poison an otherwise valid project.
    """
    _,SpecifierSet,Version,_,_=_packaging_symbols()
    release_version=Version(version);python=Version(target.python_full_version)
    wheels=[];sources=[]
    if not isinstance(files,list):return []
    for item in files:
        if not isinstance(item,dict) or item.get('yanked') is True and not allow_yanked:continue
        sha=str((item.get('digests') or {}).get('sha256',''))
        url=item.get('url');filename=str(item.get('filename') or '')
        if not SHA.fullmatch(sha) or not isinstance(url,str):continue
        parsed=urllib.parse.urlsplit(url)
        if parsed.scheme!='https' or parsed.hostname!='files.pythonhosted.org':continue
        packagetype=item.get('packagetype')
        if packagetype=='bdist_wheel' and filename.endswith('.whl'):
            try:
                wheel_name,wheel_version,_,tags=_parse_wheel_filename(filename)
            except ValueError:
                continue
            order={tag:index for index,tag in enumerate(target.tags)}
            ranks=[order[str(tag)] for tag in tags if str(tag) in order]
            if not ranks:
                continue
            if (_normalized_package_name(wheel_name)!=_normalized_package_name(name)
                    or wheel_version!=release_version):
                continue
            requires_python=item.get('requires_python')
            if requires_python is not None and requires_python != '':
                if not _requires_python_compatible(requires_python,python):continue
            wheels.append((min(ranks),filename,item))
            continue
        if packagetype=='sdist':
            try:
                source_name,source_version=_parse_sdist_filename(filename)
            except ValueError:
                pass
            else:
                if (_normalized_package_name(source_name)!=_normalized_package_name(name)
                        or source_version!=release_version):
                    continue
            requires_python=item.get('requires_python')
            if requires_python is not None and requires_python != '':
                if not _requires_python_compatible(requires_python,python):continue
            rank=0 if filename.endswith('.tar.gz') else 1 if filename.endswith('.zip') else 2
            sources.append((rank,filename,item))
    wheels.sort(key=lambda row:(row[0],row[1]));sources.sort(key=lambda row:(row[0],row[1]))
    return ([{'kind':'wheel','name':name,'version':version,'filename':filename,'item':item}
             for _,filename,item in wheels]
            or [{'kind':'sdist','name':name,'version':version,'filename':filename,'item':item}
                for _,filename,item in sources])


def _registry_release_candidates(name,target,cache=None,*,allow_yanked=False):
    """Cache target-compatible artifacts; distinguish active/yanked candidate sets.

    Yanked versions are never considered while an active candidate meets the
    actual target and constraints (PEP 592). Cache keys encode this policy.
    """
    _,_,Version,InvalidVersion,_=_packaging_symbols()
    target=_coerce_target(target)
    cache_key=(_normalized_package_name(name),_target_fingerprint(target),bool(allow_yanked))
    def load():
        project=_pypi_json('https://pypi.org/pypi/'+urllib.parse.quote(name,safe='')+'/json')
        releases=project.get('releases')
        if not isinstance(releases,dict):raise RuntimeError('PyPI project has no releases: '+name)
        result=[]
        for text,files in releases.items():
            try:version=Version(text)
            except InvalidVersion:continue
            artifacts=_release_artifacts(name,text,files,target,allow_yanked=allow_yanked)
            if artifacts:result.append((version,artifacts[0]))
        return tuple(sorted(result,key=lambda row:row[0]))
    return _memo_get_or_compute(cache,cache_key,load)


def _exact_registry_pin(requirements,constraints):
    """Return one literal exact pin only when the full active specifier set accepts it."""
    _,_,Version,InvalidVersion,_=_packaging_symbols()
    pins=[]
    for req in [*requirements,*constraints]:
        for specifier in req.specifier:
            if specifier.operator=='==' and '*' not in specifier.version:
                pins.append(specifier.version)
    if len(set(pins))!=1:return None
    text=pins[0]
    try:version=Version(text)
    except InvalidVersion:return None
    if any(req.specifier and not req.specifier.contains(version,prereleases=None)
           for req in [*requirements,*constraints]):
        return None
    return text


def _registry_exact_release_candidate(name,version_text,target,cache=None):
    """Resolve an exact pin from its release endpoint without downloading the full project index."""
    _,_,Version,InvalidVersion,_=_packaging_symbols()
    target=_coerce_target(target)
    cache_key=('exact',_normalized_package_name(name),version_text,_target_fingerprint(target))
    def load():
        stored_version,payload=_pypi_exact_release(name,version_text)
        info=payload['info'];files=payload['urls']
        artifacts=_release_artifacts(name,stored_version,files,target,allow_yanked=True)
        if not artifacts:return tuple()
        artifact={**artifacts[0], '_release_info':{
            'requires_dist':info.get('requires_dist'),
            'provides_extra':info.get('provides_extra')}}
        return ((Version(stored_version),artifact),)
    return _memo_get_or_compute(cache,cache_key,load)


def _candidate_versions(pool,name,requirements,constraints,target,release_cache=None,preferred_versions=None):
    _,SpecifierSet,Version,InvalidVersion,_=_packaging_symbols()
    exact=_exact_registry_pin(requirements,constraints)
    universe=(_registry_exact_release_candidate(name,exact,target,release_cache) if exact is not None
              else _registry_release_candidates(name,target,release_cache))
    combined=SpecifierSet(','.join(str(req.specifier) for req in [*requirements,*constraints] if str(req.specifier)))
    admitted=set(combined.filter([row[0] for row in universe],prereleases=None))
    def allowed(row):return row[0] in admitted
    candidates=[row for row in universe if allowed(row)]
    if not candidates and exact is None:
        # PEP 592 permits a historical yanked release *only if* no compatible
        # active release satisfies these exact constraints and target tags.
        # This is an explicit deterministic resolver policy, not a package-name
        # exception, an unverified replacement dependency or a silent omission.
        withdrawn=[row for row in _registry_release_candidates(name,target,release_cache,allow_yanked=True)
                   if row[1]['item'].get('yanked') is True]
        admitted=set(combined.filter([row[0] for row in withdrawn],prereleases=None))
        candidates=[row for row in withdrawn if allowed(row)]
        if candidates:
            print('[pool] WARNING: '+name+' has no compatible non-yanked PyPI release '
                  'for this target and active constraints; selecting a withdrawn '
                  'hash-addressed historical artifact (PEP 592)',flush=True)
    if not candidates:return []
    # An earlier installed version is tried first if compatible. If a
    # transitive dependency requires another version, the solver may change it.
    explicit=set()
    for text in (preferred_versions or {}).get(_normalized_package_name(name),()):
        try:explicit.add(Version(text))
        except InvalidVersion as exc:raise RuntimeError('invalid pip preferred version') from exc
    cached=set()
    for text in _cached_python_versions(pool,name):
        try:cached.add(Version(text))
        except InvalidVersion:continue
    reused=[row for row in candidates if row[0] in explicit]
    reused=sorted(reused,key=lambda row:row[0],reverse=True)
    cached_rows=sorted((row for row in candidates if row[0] in cached and row[0] not in explicit),
                       key=lambda row:row[0],reverse=True)
    if reused or cached_rows:
        rest=[row for row in reversed(candidates) if row[0] not in cached and row[0] not in explicit]
        return [row[1] for row in [*reused,*cached_rows,*rest]]
    # Pip prefers the newest compatible release for every non-exact range,
    # including a lone inclusive lower bound.  This is also essential for broad
    # historical requirements such as ``awscli>=...``: walking thousands of
    # releases from the oldest upward creates an avoidable resolver ladder.
    return [row[1] for row in reversed(candidates)]


def _core_metadata_fields(raw, *, expected_name=None, expected_version=None, target=None):
    import email.parser
    if not isinstance(raw,(bytes,bytearray)) or len(raw)>MAX_SOURCE:
        raise RuntimeError('Python core metadata exceeds security limit')
    try:text=bytes(raw).decode('utf-8')
    except UnicodeDecodeError as exc:raise RuntimeError('Python core metadata is not valid UTF-8') from exc
    parsed=email.parser.Parser().parsestr(text,headersonly=True)
    if parsed.defects:raise RuntimeError('malformed Python core metadata headers')
    for field in ('Metadata-Version','Name','Version'):
        if len(parsed.get_all(field) or [])!=1:
            raise RuntimeError('Python core metadata requires a unique '+field)
    if len(parsed.get_all('Requires-Python') or [])>1:
        raise RuntimeError('duplicate Requires-Python metadata')
    metadata_version=parsed.get('Metadata-Version')
    if not re.fullmatch(r'[12]\.\d+',metadata_version or ''):
        raise RuntimeError('unsupported Python core metadata version')
    name=parsed.get('Name');version=parsed.get('Version')
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?',name or ''):
        raise RuntimeError('invalid Python core metadata name identity')
    if not isinstance(name,str) or not name or not isinstance(version,str) or not version:
        raise RuntimeError('Python core metadata lacks package identity')
    _,_,Version,InvalidVersion,_=_packaging_symbols()
    try:parsed_version=Version(version)
    except InvalidVersion as exc:raise RuntimeError('invalid Python core metadata version identity') from exc
    if expected_name is not None and _normalized_package_name(name)!=_normalized_package_name(expected_name):
        raise RuntimeError('Python core metadata name identity differs')
    if expected_version is not None and parsed_version!=Version(expected_version):
        raise RuntimeError('Python core metadata version identity differs')
    requires_python=parsed.get('Requires-Python')
    if target is not None and requires_python and not _requires_python_compatible(requires_python,Version(target.python_full_version)):
        raise RuntimeError('Python core metadata Requires-Python rejects target')
    return name,version,parsed.get_all('Requires-Dist') or [],parsed.get_all('Provides-Extra') or []


def _wheel_core_metadata(path, *, expected_name=None, expected_version=None, target=None):
    import zipfile
    path=Path(path)
    try:
        with zipfile.ZipFile(path) as archive:
            # Wheel Core Metadata lives in a top-level *.dist-info directory.
            # Vendor-bundled packages may contain their own nested *.dist-info
            # directories, which must never be mistaken for the wheel's own.
            names=[member.filename for member in archive.infolist()
                   if member.filename.endswith('.dist-info/METADATA')
                   and member.filename.count('/')==1
                   and '..' not in member.filename.split('/')]
            if len(names)!=1:
                raise RuntimeError('wheel has no unique root dist-info/METADATA: '
                                   +path.name+' ('+str(len(names))+' root entries)')
            info=archive.getinfo(names[0])
            if info.file_size>MAX_SOURCE:raise RuntimeError('wheel metadata exceeds security limit')
            raw=archive.read(names[0])
    except zipfile.BadZipFile as exc:raise RuntimeError('invalid wheel archive') from exc
    _name,_version,requirements,extras=_core_metadata_fields(raw,expected_name=expected_name,
        expected_version=expected_version,target=target)
    directory=names[0].split('/')[0].removesuffix('.dist-info')
    try:directory_name,directory_version,_,_=_parse_wheel_filename(directory+'-py3-none-any.whl')
    except ValueError as exc:raise RuntimeError('invalid wheel dist-info identity') from exc
    Version=_packaging_symbols()[2]
    if _normalized_package_name(directory_name)!=_normalized_package_name(_name) or directory_version!=Version(_version):
        raise RuntimeError('wheel dist-info identity differs from core metadata')
    return requirements,extras


def _pep658_candidate_metadata(candidate, target=None):
    """Return hash-verified artifact-specific Core Metadata when PyPI publishes it."""
    item=candidate['item'];descriptor=item.get('core-metadata')
    if descriptor is False or descriptor is None:return None
    if not isinstance(descriptor,dict) or not SHA.fullmatch(str(descriptor.get('sha256',''))):
        raise RuntimeError('invalid PyPI core-metadata identity')
    _artifact_sha,url=_candidate_artifact_identity(candidate)
    raw=_read_https(url+'.metadata',timeout=90,limit=MAX_SOURCE,
                    user_agent='gpt-trace-dependency-pool/4',expected_host='files.pythonhosted.org')
    if hashlib.sha256(raw).hexdigest()!=descriptor['sha256']:
        raise RuntimeError('PyPI core-metadata SHA-256 mismatch')
    name,version,requirements,extras=_core_metadata_fields(raw,expected_name=candidate['name'],
        expected_version=candidate['version'],target=target)
    _,_,Version,InvalidVersion,_=_packaging_symbols()
    try:same_version=Version(version)==Version(candidate['version'])
    except InvalidVersion:same_version=False
    if _normalized_package_name(name)!=_normalized_package_name(candidate['name']) or not same_version:
        raise RuntimeError('PyPI core-metadata package identity differs')
    return requirements,extras


def _candidate_artifact_identity(candidate):
    item=candidate['item'];sha=str((item.get('digests') or {}).get('sha256',''));url=item.get('url')
    if not SHA.fullmatch(sha) or not isinstance(url,str):
        raise RuntimeError('candidate artifact lacks immutable identity')
    return sha,url


def _candidate_yank_provenance(candidate):
    """Retain PyPI withdrawal status/reason in every immutable package plan."""
    item=candidate['item']
    if item.get('yanked') is not True:return {}
    reason=item.get('yanked_reason')
    if reason is not None and not isinstance(reason,str):
        raise RuntimeError('invalid PyPI yanked reason metadata')
    return {'yanked':True,'yanked_reason':reason or ''}


def _materialize_candidate_metadata(pool,candidate,key,target,cache):
    """Download one chosen artifact and read its authoritative embedded metadata."""
    identity=(_target_fingerprint(target),candidate['kind'],_normalized_package_name(candidate['name']),
              candidate['version'],candidate['filename'],_candidate_artifact_identity(candidate))
    def materialize():
        sha,url=_candidate_artifact_identity(candidate)
        if candidate['kind']=='wheel':
            actual=pool.download(url,'python',key,sha=sha)
            path=pool.objects/actual[:2]/actual
            requirements,extras=_wheel_core_metadata(path,expected_name=candidate['name'],
                expected_version=candidate['version'],target=target)
            return {'kind':'wheel','name':candidate['name'],'version':candidate['version'],
                    'filename':candidate['filename'],'sha256':actual,'url':url,
                    'requirements':[normalize_legacy_source_requirement(row) for row in requirements],
                    'provides_extra':sorted(set(extras)),
                    **_candidate_yank_provenance(candidate)}
        source=acquire_source_distribution(pool,candidate['name']+'=='+candidate['version'],key,target)
        if source['sha256']!=sha:
            raise RuntimeError('selected source distribution identity changed during resolution')
        return {'kind':'sdist','name':source['name'],'version':source['version'],
                'filename':source['filename'],'sha256':source['sha256'],'url':source['url'],
                'requirements':source['requirements'],'provides_extra':source['provides_extra'],
                **_candidate_yank_provenance(candidate)}
    record=_memo_get_or_compute(cache,identity,materialize)
    artifact=pool.objects/record['sha256'][:2]/record['sha256']
    if artifact.is_symlink() or not artifact.is_file():
        raise RuntimeError('cached resolver metadata lost its content-addressed artifact')
    category='python-source' if record['kind']=='sdist' else 'python'
    pool.reference(record['sha256'],category,key,artifact.stat().st_size)
    return record


def _candidate_probe_identity(candidate,target,no_deps):
    """One identity for release metadata and read-only compatibility probes."""
    return (_target_fingerprint(target),candidate['kind'],_normalized_package_name(candidate['name']),
            candidate['version'],candidate['filename'],_candidate_artifact_identity(candidate),bool(no_deps))


def _candidate_release_metadata(pool,candidate,key,target,probe_cache,artifact_cache,*,no_deps=False):
    """Use only artifact-specific metadata as evidence for dependency decisions.

    Release JSON may describe another wheel from the same release. It cannot
    prove that this candidate is SAT or UNSAT. A hash-bound sidecar is usable;
    otherwise inspecting the pinned archive is necessary, without installation.
    --no-deps controls graph expansion, never metadata integrity verification.
    """
    target=_coerce_target(target)
    identity=_candidate_probe_identity(candidate,target,no_deps)
    def probe():
        sha,url=_candidate_artifact_identity(candidate)
        core=_pep658_candidate_metadata(candidate,target)
        if core is None:
            return _materialize_candidate_metadata(pool,candidate,key,target,artifact_cache)
        requirements,extras=core
        return {'kind':candidate['kind'],'name':candidate['name'],'version':candidate['version'],
                'filename':candidate['filename'],'sha256':sha,'url':url,
                'requirements':[normalize_legacy_source_requirement(row) for row in requirements],
                'provides_extra':sorted(set(extras)),
                **_candidate_yank_provenance(candidate)}
    return _memo_get_or_compute(probe_cache,identity,probe)


def _materialize_solution(pool,records,key,target,artifact_cache,executor=None,source_probe=None):
    """Acquire winning artifacts concurrently and verify solve-time metadata exactly."""
    def materialize(expected):
        candidate={'kind':expected['kind'],'name':expected['name'],'version':expected['version'],
                   'filename':expected['filename'],'item':{'url':expected['url'],
                   'digests':{'sha256':expected['sha256']},
                   'yanked':expected.get('yanked',False),
                   'yanked_reason':expected.get('yanked_reason')}}
        if expected['kind']=='sdist' and source_probe is not None:
            # One verified source/target result is reused across solver probes
            # and checkpoint materialization, without re-running build hooks.
            identity=('native-source-artifact',_target_fingerprint(target),
                      expected['sha256'],expected['filename'])
            actual=_memo_get_or_compute(artifact_cache,identity,
                lambda:source_probe(pool,candidate,key,target))
            size=pool.verify_object(actual['sha256'])
            pool.reference(actual['sha256'],'python-source',key,size)
        else:
            actual=_materialize_candidate_metadata(pool,candidate,key,target,artifact_cache)
        if (sorted(actual['requirements'])!=sorted(expected['requirements'])
                or sorted(actual['provides_extra'])!=sorted(expected['provides_extra'])
                or (expected['kind']=='sdist' and source_probe is not None
                    and actual.get('build_requirements')!=expected.get('build_requirements'))
                or _candidate_yank_provenance(candidate)!={
                    key:expected[key] for key in ('yanked','yanked_reason') if key in expected}):
            raise RuntimeError('PyPI release metadata differs from selected artifact metadata: '
                               +expected['name']+'=='+expected['version'])
        return actual
    if executor is None or len(records)<2:
        return [materialize(expected) for expected in records]
    futures=[executor.submit(materialize,expected) for expected in records]
    try:
        return [future.result() for future in futures]
    except BaseException:
        for future in futures:future.cancel()
        raise


def _candidate_satisfies(candidate,requirements,constraints):
    _,_,Version,_,_=_packaging_symbols();version=Version(candidate['version'])
    return all(not req.specifier or req.specifier.contains(version,prereleases=True)
               for req in [*requirements,*constraints])


def _resolve_registry_plan(pool,target,reqs,constraints,key,*,no_deps=False,resolver_cache=None,materialize=True,preferred_versions=None):
    """Mandatory production Rust graph search; no Python search path exists.

    Python retains the exact wheel/PEP-440/PEP-508/PEP-517 evidence oracle.
    Every decision, backjump, state and nogood is owned by the Rust binary.
    """
    bridge = Path(__file__).resolve().with_name('verified_resolver_bridge.py')
    if bridge.is_symlink() or not bridge.is_file():
        raise RuntimeError('missing sealed native Rust solver bridge')
    spec = importlib.util.spec_from_file_location('verified_resolver_bridge', bridge)
    if spec is None or spec.loader is None:
        raise RuntimeError('cannot load mandatory native resolver bridge')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.solve(globals(),pool,target,reqs,constraints,key,no_deps=no_deps,
                        resolver_cache=resolver_cache,materialize=materialize,
                        preferred_versions=preferred_versions)


def _pip_plan_path(stage, key):
    if not isinstance(key, str) or re.fullmatch(r'[A-Za-z0-9_-]+', key) is None:
        raise ValueError('unsafe pip plan identity')
    return Path(stage)/'metadata'/('pip-plan-'+key+'.json')


def _read_pip_plan_tree(stage, key):
    """Verify the graph of immutable completion records, not only its root."""
    records = {}
    active = set()
    def visit(identity, expected_sha=None, expected_target=None):
        if identity in active:
            raise ValueError('cyclic pip build closure')
        path = _pip_plan_path(stage, identity)
        if path.is_symlink() or not path.is_file():
            raise ValueError('missing or unsafe pip build checkpoint: '+identity)
        raw = path.read_bytes()
        if expected_sha is not None and hashlib.sha256(raw).hexdigest() != expected_sha:
            raise ValueError('pip build checkpoint integrity differs: '+identity)
        plan = json.loads(raw)
        if (plan.get('artifact_model') != PIP_ARTIFACT_MODEL or
                plan.get('plan_schema') != PIP_PLAN_SCHEMA or plan.get('optional_failed')):
            raise ValueError('incomplete or incompatible pip build checkpoint')
        _pip_plan_artifact_shas(plan)
        if expected_target is not None and plan['target'] != expected_target:
            raise ValueError('pip build dependency target differs')
        if expected_target is not None and identity != pip_group_key(
                plan['target'], plan['requested'], plan['constraints'], plan['no_deps'],
                preferred_versions=plan.get('preferred_versions', {})):
            raise ValueError('pip build checkpoint input identity differs')
        children = plan.get('build_plans', {})
        if not isinstance(children, dict) or any(not isinstance(sha, str) or not SHA.fullmatch(sha)
                                                  for sha in children.values()):
            raise ValueError('invalid pip build checkpoint references')
        if identity in records:
            return
        active.add(identity)
        for child, sha in sorted(children.items()):
            visit(child, sha, plan['target'])
        active.remove(identity)
        records[identity] = plan
    visit(key)
    return records


def reuse_pip_plan(pool,target,reqs,key,*,constraints=(),no_deps=False,preferred_versions=None):
    """Reuse a verified completed logical plan without network or resolver work."""
    target=_coerce_target(target)
    path=pool.stage/'metadata'/('pip-plan-'+key+'.json')
    if not path.is_file() or path.is_symlink():return False
    try:
        plan=json.loads(path.read_bytes())
        if (plan.get('artifact_model')!=PIP_ARTIFACT_MODEL or plan.get('plan_schema')!=PIP_PLAN_SCHEMA
                or plan.get('target')!=target.as_dict() or plan.get('requested')!=sorted(set(reqs))
                or plan.get('constraints')!=sorted(set(constraints))
                or plan.get('preferred_versions',{})!=_canonical_pip_preferences(preferred_versions)
                or plan.get('no_deps') is not bool(no_deps)):
            return False
        plans = _read_pip_plan_tree(pool.stage, key)
        for dependency, completed in plans.items():
            for row in completed['packages']:
                sha = row['sha256']
                size = pool.verify_object(sha)
                category='python-source' if row['kind']=='sdist' else 'python'
                pool.reference(sha,category,dependency,size)
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        raise RuntimeError('invalid retained pip checkpoint: '+str(exc)) from exc
    if _POOL_PROGRESS is None: print('[pool] reused verified pip closure '+key,flush=True)
    return True


def _write_pip_plan(pool,target,reqs,key,packages,*,constraints=(),no_deps=False,build_plans=None,preferred_versions=None):
    target=_coerce_target(target);stage=pool.stage
    files=[{'filename':row['filename'],'sha256':row['sha256']} for row in packages if row['kind']=='wheel']
    sources=[{key_:row[key_] for key_ in ('name','version','filename','url','sha256','requirements','provides_extra')}
             for row in packages if row['kind']=='sdist']
    plan={'artifact_model':PIP_ARTIFACT_MODEL,'plan_schema':PIP_PLAN_SCHEMA,
          'resolver_policy':{'schema':PIP_PLAN_SCHEMA,'name':PIP_RESOLVER_POLICY,'target_fingerprint':_target_fingerprint(target),
                             'runtime':_resolver_runtime_identity()},
          'target':target.as_dict(),'python':target.python_full_version,
          'requested':sorted(set(reqs)),'constraints':sorted(set(constraints)),
          'preferred_versions':_canonical_pip_preferences(preferred_versions),
          'no_deps':bool(no_deps),'packages':packages,'files':files,'source_archives':sources,
          'build_plans':dict(sorted((build_plans or {}).items()))}
    try:_pip_plan_artifact_shas(plan)
    except (ValueError,KeyError,TypeError) as exc:raise RuntimeError('invalid pip closure: '+str(exc)) from exc
    for child, expected_sha in plan['build_plans'].items():
        _read_pip_plan_tree(stage, child)
        if digest(_pip_plan_path(stage, child)) != expected_sha:
            raise RuntimeError('build checkpoint changed before parent publication')
    # A completed checkpoint is durable only after its CAS links and metadata
    # directory entries have been synchronized, not merely their file contents.
    for row in packages:
        sha = row['sha256']
        pool.verify_object(sha)
        with (pool.objects/sha[:2]/sha).open('rb') as artifact:
            os.fsync(artifact.fileno())
    for directory in sorted({(pool.objects/row['sha256'][:2]) for row in packages}):
        _sync_directory(directory)
    _sync_directory(pool.objects)
    write_new(stage/'metadata'/('pip-plan-'+key+'.json'),json.dumps(plan,sort_keys=True,separators=(',',':')))
    fd=os.open(stage/'metadata',os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def pip_closure(pool,target,reqs,key,*,constraints=(),no_deps=False,resolver_cache=None):
    if not reqs:return
    target=_coerce_target(target);stage=pool.stage
    write_new(stage/'metadata'/('pip-'+key+'.txt'),'\n'.join(sorted(set(reqs)))+'\n')
    packages=_resolve_registry_plan(pool,target,reqs,constraints,key,no_deps=no_deps,
                                    resolver_cache=resolver_cache)
    _write_pip_plan(pool,target,reqs,key,packages,constraints=constraints,no_deps=no_deps)


def _historical_exact_pip_pins(requirements, target):
    """Extract exact active direct installs; no PyPI version substitution.

    Pins from preceding successful, required recipe commands are part of the
    task-local installed environment, even if the next requirements file names
    the same distribution without a version.  Keep this per task and target.
    """
    Requirement, _SpecifierSet, _Version, _InvalidVersion, _env = _packaging_symbols()
    markers = _target_marker_environment(target)
    result = {}
    for raw in sorted(set(requirements)):
        requirement = Requirement(normalize_legacy_source_requirement(raw))
        if requirement.url is not None:
            continue
        if requirement.marker is not None and not requirement.marker.evaluate(markers):
            continue
        specifications = tuple(requirement.specifier)
        if (len(specifications) != 1 or specifications[0].operator != '=='
                or '*' in specifications[0].version):
            continue
        name = _normalized_package_name(requirement.name)
        exact = requirement.name + '==' + specifications[0].version
        if name in result and result[name] != exact:
            raise RuntimeError('conflicting exact pins within a pip recipe step: ' + name)
        result[name] = exact
    return result


def _historical_pip_preferences(prior, requirements, constraints, target, *, upgrade=False):
    """Prefer earlier successful installs without forbidding needed changes.

    A previous exact installation does not constrain the next Pip transaction.
    Preserve its version as a verified, task-specific ordering preference.
    Explicit subsequent requirements and constraints always take precedence.
    """
    Requirement, _SpecifierSet, Version, InvalidVersion, _env = _packaging_symbols()
    current_pins = _historical_exact_pip_pins(requirements, target)
    requested = {}
    for raw in sorted(set(requirements)):
        requirement = Requirement(normalize_legacy_source_requirement(raw))
        if requirement.marker is not None and not requirement.marker.evaluate(_target_marker_environment(target)):
            continue
        requested[_normalized_package_name(requirement.name)] = requirement
    explicit_constraints = {}
    for raw in sorted(set(constraints)):
        requirement = Requirement(normalize_legacy_source_requirement(raw))
        if requirement.marker is not None and not requirement.marker.evaluate(_target_marker_environment(target)):
            continue
        explicit_constraints.setdefault(_normalized_package_name(requirement.name), []).append(requirement)
    inherited = {}
    for name, original in sorted(prior.items()):
        if name in current_pins:
            continue
        if upgrade and name in requested:
            continue
        installed = Requirement(original)
        try:
            version = Version(next(iter(installed.specifier)).version)
        except (InvalidVersion, ValueError, StopIteration) as exc:
            raise RuntimeError('invalid retained pip recipe pin') from exc
        if (name in requested and requested[name].specifier
                and not requested[name].specifier.contains(version, prereleases=True)):
            continue
        if any(req.specifier and not req.specifier.contains(version, prereleases=True)
               for req in explicit_constraints.get(name, ())):
            continue
        inherited[name] = original
    return inherited


def acquire_pip_group(pool,key,group,*,resolver_cache=None):
    """Deduplicate concurrent build/runtime closures by exact plan identity."""
    with pool._state_lock:
        locks=getattr(pool,'_native_group_locks',None)
        if locks is None:
            locks={};pool._native_group_locks=locks
        lock=locks.setdefault(key,threading.RLock())
        if not hasattr(pool, '_native_group_context'):
            pool._native_group_context = threading.local()
            pool._native_group_edges = defaultdict(set)
        stack = getattr(pool._native_group_context, 'stack', ())
        if key in stack:
            raise RuntimeError('cyclic native pip build requirements')
        if stack:
            parent = stack[-1]
            pending = [key]; seen = set()
            while pending:
                current = pending.pop()
                if current == parent:
                    raise RuntimeError('cyclic concurrent pip build requirements')
                if current not in seen:
                    seen.add(current)
                    pending.extend(pool._native_group_edges[current])
            pool._native_group_edges[parent].add(key)
    try:
        with lock:
            pool._native_group_context.stack = (*stack, key)
            try:
                return _native_pip_group_locked(pool,key,group)
            finally:
                pool._native_group_context.stack = stack
    finally:
        if stack:
            with pool._state_lock:
                pool._native_group_edges[stack[-1]].discard(key)


def _native_pip_group_locked(pool,key,group):
    """Checkpoint a real pip solution, keeping optional groups explicit."""
    target=_coerce_target(group['target'])
    path = _pip_plan_path(pool.stage, key)
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise RuntimeError('unsafe native pip checkpoint')
        previous = json.loads(path.read_bytes())
        if previous.get('optional_failed'):
            if (previous.get('target') != target.as_dict() or
                    previous.get('requested') != sorted(set(group['requirements'])) or
                    previous.get('constraints') != sorted(set(group['constraints'])) or
                    previous.get('preferred_versions',{}) != _canonical_pip_preferences(group.get('preferred_versions')) or
                    previous.get('no_deps') is not group['no_deps']):
                raise RuntimeError('optional pip outcome identity differs')
            if group['required']:
                raise RuntimeError('required pip closure has only a recorded optional failure: '+key)
            return 'optional-failed'
    if reuse_pip_plan(pool,target,group['requirements'],key,
                      constraints=group['constraints'],no_deps=group['no_deps'],
                      preferred_versions=group.get('preferred_versions')):
        return 'reused'
    try:
        packages=_native_resolve_registry(pool,target,group['requirements'],
            group['constraints'],key,no_deps=group['no_deps'],
            preferred_versions=group.get('preferred_versions'))
        build_plans = _native_acquire_build_dependencies(pool,target,packages)
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        detail = str(exc)
        if isinstance(exc, subprocess.TimeoutExpired) and exc.output:
            detail += '; last pip output: ' + exc.output[-5000:].decode(errors='replace')
        if group['required']:
            evidence={
                'closure':key,
                'requirements':sorted(set(group['requirements'])),
                'constraints':sorted(set(group['constraints'])),
                'preferred_versions':_canonical_pip_preferences(group.get('preferred_versions')),
                'no_deps':group['no_deps'],
                'tasks':sorted(set(group['tasks'])),
                'target':target.as_dict(),
            }
            print('[pool] required pip closure input evidence: '
                  +json.dumps(evidence,sort_keys=True,ensure_ascii=False),
                  file=sys.stderr,flush=True)
            raise RuntimeError('required native pip closure '+key+' failed: '+detail) from exc
        write_new(pool.stage/'metadata'/('pip-plan-'+key+'.json'),json.dumps({
            'artifact_model':PIP_ARTIFACT_MODEL,'plan_schema':PIP_PLAN_SCHEMA,
            'target':target.as_dict(),'python':target.python_full_version,
            'requested':sorted(set(group['requirements'])),'constraints':sorted(set(group['constraints'])),
            'preferred_versions':_canonical_pip_preferences(group.get('preferred_versions')),
            'no_deps':group['no_deps'],'optional_failed':str(exc),
            'packages':[],'files':[],'source_archives':[]},sort_keys=True))
        return 'optional-failed'
    # A checkpoint/publication failure is infrastructure failure, even for a
    # recipe that permits its installer to fail. Never overwrite a completed
    # record with an optional-failure marker.
    _write_pip_plan(pool,target,group['requirements'],key,packages,
                    constraints=group['constraints'],no_deps=group['no_deps'],build_plans=build_plans,
                    preferred_versions=group.get('preferred_versions'))
    return 'acquired'


def acquire_pip_groups(pool, groups):
    """Share bounded metadata I/O across concurrent verified closure solvers."""
    ordered=sorted(groups.items())
    if not ordered:
        return
    closure_workers, metadata_workers = _pip_worker_controls()
    if (type(closure_workers) is not int or closure_workers < 1
            or type(metadata_workers) is not int or metadata_workers < 1):
        raise RuntimeError('invalid configured pip solver concurrency')
    workers=min(closure_workers,len(ordered))
    if _POOL_PROGRESS is None:
        print('[pool] verified Pip graph solver: '+str(len(ordered))+
              ' closures, '+str(workers)+' closure workers, '+str(metadata_workers)+
              ' shared metadata workers; host-only', flush=True)
    _pool_progress('Pip closures',0,len(ordered),'closures',f'{workers} workers')
    cache=_native_solver_cache(pool)
    with concurrent.futures.ThreadPoolExecutor(max_workers=metadata_workers,
            thread_name_prefix='verified-pypi-metadata') as io_executor:
        with pool._state_lock:
            cache['metadata_executor']=io_executor
            cache['metadata_prefetch']=_metadata_prefetch_width(workers,metadata_workers)
            cache['prefetch_controller']=_ResolverActivity(metadata_workers)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers,
                    thread_name_prefix='verified-pip-closure') as executor:
                futures={executor.submit(acquire_pip_group,pool,key,group):key
                         for key,group in ordered}
                errors=[];done=0
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                        done+=1
                        _pool_progress('Pip closures',done,len(ordered),'closures',
                                       f'{workers} workers')
                    except BaseException as exc:
                        errors.append((futures[future],exc))
                        for other in futures:
                            if not other.done():other.cancel()
                if errors:
                    key,exc=min(errors,key=lambda row:row[0])
                    raise RuntimeError('verified pip closure '+key+' failed: '+str(exc)) from exc
        finally:
            with pool._state_lock:
                cache.pop('metadata_executor',None)
                cache.pop('metadata_prefetch',None)
                cache.pop('prefetch_controller',None)

def npm_lock_urls(lock, label, *, workspace_checker=None):
    """Extract trusted registry tarballs from npm lockfile v1/v2/v3."""
    urls={}
    packages=lock.get('packages')
    dependencies=lock.get('dependencies')
    if isinstance(packages,dict) and packages:
        records=list(packages.values())
    elif isinstance(dependencies,dict):
        records=[];pending=[dependencies];seen=set()
        while pending:
            nested=pending.pop()
            if id(nested) in seen:raise RuntimeError('cyclic npm dependency tree: '+label)
            seen.add(id(nested))
            if not isinstance(nested,dict):raise RuntimeError('invalid npm dependencies: '+label)
            for name in sorted(nested):
                record=nested[name]
                if not isinstance(record,dict):raise RuntimeError('invalid npm dependency record: '+label)
                records.append(record)
                if 'dependencies' in record:pending.append(record['dependencies'])
    else:
        raise RuntimeError('npm lockfile has no package records: '+label)
    for item in records:
        if not isinstance(item,dict) or not item.get('resolved'):
            continue
        url=item['resolved'];integ=item.get('integrity')
        if item.get('link') is True:
            if workspace_checker is None:
                raise RuntimeError('unexpected npm workspace link: '+label)
            workspace_checker(url)
            continue
        if (not isinstance(url,str) or not url.startswith('https://registry.npmjs.org/')
                or not isinstance(integ,str) or not integ):
            raise RuntimeError('npm package has no trusted registry source/SRI: '+label)
        if url in urls and urls[url] != integ:
            raise RuntimeError('conflicting npm lockfile integrity for '+url)
        urls[url]=integ
    return urls


def _npm_cli_metadata():
    """Fetch immutable-version npm registry metadata; never use the moving `latest` tag."""
    npm_version = _pinned_npm_version()
    metadata_url='https://registry.npmjs.org/npm/'+npm_version
    raw=_read_https(metadata_url,timeout=90,limit=4*1024*1024,
                    user_agent='gpt-trace-dependency-pool/3',expected_host='registry.npmjs.org')
    try:info=json.loads(raw)
    except ValueError as exc:raise RuntimeError('invalid npm CLI metadata') from exc
    if info.get('version')!=npm_version:
        raise RuntimeError('npm registry returned unexpected CLI version')
    engine=(info.get('engines') or {}).get('node')
    if not isinstance(engine,str) or not engine.strip():
        raise RuntimeError('pinned npm CLI has no Node engine compatibility metadata')
    dist=info.get('dist') or {};tarball,sri=dist.get('tarball'),dist.get('integrity')
    if (not isinstance(tarball,str) or
            not tarball.startswith('https://registry.npmjs.org/npm/-/npm-'+npm_version)):
        raise RuntimeError('untrusted npm CLI archive')
    if not isinstance(sri,str) or not sri:raise RuntimeError('npm CLI lacks SRI')
    return {'version':npm_version,'engine':engine,'url':tarball,'integrity':sri}


def npm_cli_artifact(pool, category, identity):
    """Acquire the one pinned npm CLI tarball and register per-use provenance."""
    metadata_path=pool.stage/'metadata'/'npm-cli.json'
    if metadata_path.exists():
        try:meta=json.loads(metadata_path.read_bytes())
        except ValueError as exc:raise RuntimeError('invalid retained npm CLI metadata') from exc
        if (meta.get('version')!=_pinned_npm_version() or not isinstance(meta.get('url'),str)
                or not isinstance(meta.get('integrity'),str)):
            raise RuntimeError('retained npm CLI metadata does not match pin')
    else:
        meta=_npm_cli_metadata()
    sha=pool.download(meta['url'],category,identity,sri=meta['integrity'])
    if metadata_path.exists():
        if meta.get('sha256')!=sha:raise RuntimeError('retained npm CLI CAS identity changed')
    else:
        meta={**meta,'sha256':sha}
        write_new(metadata_path,json.dumps(meta,sort_keys=True))
    return sha,meta


def _semver_tuple(value):
    match=re.fullmatch(r'v?(\d+)(?:\.(\d+))?(?:\.(\d+))?',str(value).strip())
    if not match:raise ValueError('invalid semantic version: '+str(value))
    return tuple(int(part or 0) for part in match.groups())


def _node_engine_allows(version, expression):
    """Evaluate the finite npm engine range forms used by immutable npm metadata."""
    current=_semver_tuple(version)
    def atom(token):
        token=token.strip()
        if not token:return True
        wildcard=re.fullmatch(r'(?:v)?(\d+)(?:\.(\d+))?(?:\.(x|X|\*))?',token)
        if wildcard and wildcard.group(3) in ('x','X','*'):
            prefix=tuple(int(part) for part in wildcard.groups()[:2] if part is not None)
            return current[:len(prefix)]==prefix
        if token in ('*','x','X'):return True
        caret=token.startswith('^');tilde=token.startswith('~') and not token.startswith('~=')
        if caret or tilde:
            base=_semver_tuple(token[1:]);lower=current>=base
            if caret:
                major,minor,patch=base
                upper=((major+1,0,0) if major else (0,minor+1,0) if minor else (0,0,patch+1))
            else:
                raw=token[1:].lstrip('v').split('.')
                upper=((base[0]+1,0,0) if len(raw)==1 else (base[0],base[1]+1,0))
            return lower and current<upper
        match=re.fullmatch(r'(>=|<=|>|<|==|=)?\s*(v?\d+(?:\.\d+){0,2})',token)
        if not match:raise ValueError('unsupported Node engine constraint: '+token)
        operator=match.group(1) or '=';expected=_semver_tuple(match.group(2))
        return {'>=':current>=expected,'<=':current<=expected,'>':current>expected,'<':current<expected,
                '=':current==expected,'==':current==expected}[operator]
    for disjunct in str(expression).split('||'):
        tokens=[token for token in re.split(r'\s+',disjunct.strip()) if token]
        try:
            if tokens and all(atom(token) for token in tokens):return True
        except ValueError:
            raise
    return False


def _run_pinned_npm(pool, args, *, cwd, env, timeout=1800):
    """Run the npm CLI recorded by verified Kali provenance."""
    import tarfile
    npm_version = _pinned_npm_version()
    sha,meta=npm_cli_artifact(pool,'npm-resolver-cli','npm-'+npm_version)
    archive_path=pool.objects/sha[:2]/sha
    node=shutil.which('node')
    if not node:raise RuntimeError('Node.js executable missing on fetch host')
    version_text=invoke([node,'--version'],capture=True).strip()
    try: compatible=_node_engine_allows(version_text,meta.get('engine'))
    except ValueError as exc:raise RuntimeError('unsupported pinned npm Node engine metadata') from exc
    if not compatible:
        raise RuntimeError('fetch-host Node.js does not satisfy pinned npm engine '+str(meta.get('engine')))
    with tempfile.TemporaryDirectory(prefix='swegym-npm-cli-') as temp:
        root=Path(temp)
        total=0
        with tarfile.open(archive_path,'r:*') as archive:
            for member in archive:
                rel=Path(member.name)
                if (rel.is_absolute() or '..' in rel.parts or '\\' in member.name
                        or member.issym() or member.islnk() or member.isdev()):
                    raise RuntimeError('unsafe entry in pinned npm CLI archive')
                if member.isfile():
                    total+=member.size
                    if member.size>16*1024*1024 or total>128*1024*1024:
                        raise RuntimeError('oversized pinned npm CLI archive')
            archive.extractall(root)
        cli=root/'package'/'bin'/'npm-cli.js'
        if cli.is_symlink() or not cli.is_file():raise RuntimeError('npm CLI archive lacks npm-cli.js')
        # npm rejects loading the same config path in two scopes, even when
        # that path is /dev/null. Distinct empty files also exclude host tokens.
        isolated = {key: value for key, value in env.items()
                    if key.lower() not in {'npm_config_userconfig', 'npm_config_globalconfig'}}
        for scope in ('user', 'global'):
            config = root / (scope + '.npmrc')
            write_new(config, b'')
            isolated['NPM_CONFIG_' + scope.upper() + 'CONFIG'] = str(config)
        return invoke([node,str(cli),*args],cwd=cwd,env=isolated,timeout=timeout)


def _download_sri_closure(pool, urls, category, identity=None):
    """Acquire one immutable SRI URL set concurrently within the global I/O budget."""
    ordered=sorted(urls.items())
    if not ordered:return {}
    workers=min(_acquisition_workers(),len(ordered))
    phase = category.upper() + ' archives'
    if _POOL_PROGRESS is None:
        print(f'[pool] {category} closure: {len(ordered)} unique archives with {workers} workers',flush=True)
    _pool_progress(phase,0,len(ordered),'archives',f'{workers} workers')
    def transfer(url,sri):
        return url,pool.download(url,category,url if identity is None else identity,sri=sri)
    results={}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers,
                                               thread_name_prefix=category) as executor:
        futures=[executor.submit(transfer,url,sri) for url,sri in ordered]
        try:
            for future in concurrent.futures.as_completed(futures):
                url,sha=future.result();results[url]=sha
                _pool_progress(phase,len(results),len(ordered),'archives',f'{workers} workers')
        except BaseException:
            for future in futures:future.cancel()
            raise
    return results


def npm_package_json_closure(pool, mirror, commit, repo_ref, identity):
    """Resolve pinned VCS package metadata with pinned npm; never run package scripts."""
    candidates=[]
    for package_path in git_files_named(mirror,commit,'package.json'):
        text=git_file(mirror,commit,package_path,required=True)
        try:value=json.loads(text)
        except ValueError as exc:raise RuntimeError('invalid VCS package.json: '+repo_ref+':'+package_path) from exc
        if any(value.get(table) for table in ('dependencies','devDependencies')):
            candidates.append((package_path,text,value))
    if len(candidates)!=1:
        raise RuntimeError('npm-backed VCS source must identify exactly one dependency package.json: '+repo_ref)
    package_path,package_text,package=candidates[0]
    for table in ('dependencies','devDependencies'):
        value=package.get(table,{})
        if value is not None and not isinstance(value,dict):
            raise RuntimeError('invalid npm dependency table in '+repo_ref)
        for name,spec in (value or {}).items():
            if not isinstance(name,str) or not isinstance(spec,str):
                raise RuntimeError('non-string npm dependency in '+repo_ref)
            if spec.startswith(('git','http:','https:','file:','link:','workspace:')):
                raise RuntimeError('non-registry npm dependency requires explicit pin: '+name)
    key=hashlib.sha256((repo_ref+'\0'+commit+'\0'+identity).encode()).hexdigest()[:20]
    work=pool.stage/'npm'/('resolve-'+key);work.mkdir()
    write_new(work/'package.json',json.dumps(package,sort_keys=True,indent=2)+'\n')
    cache=work/'cache';env=dict(os.environ)
    env.update({'npm_config_cache':str(cache),'npm_config_registry':'https://registry.npmjs.org/',
                'npm_config_audit':'false','npm_config_fund':'false','npm_config_ignore_scripts':'true'})
    _run_pinned_npm(pool,['install','--package-lock-only','--ignore-scripts','--no-audit','--no-fund',
                          '--registry=https://registry.npmjs.org/'],cwd=work,env=env,timeout=1800)
    if (work/'node_modules').exists():raise RuntimeError('npm resolver unexpectedly installed node_modules')
    lock_path=work/'package-lock.json'
    if lock_path.is_symlink() or not lock_path.is_file():raise RuntimeError('npm resolver produced no lockfile')
    lock=json.loads(lock_path.read_bytes());urls=npm_lock_urls(lock,repo_ref)
    if not urls:raise RuntimeError('npm resolver produced empty archive closure: '+repo_ref)
    downloaded=_download_sri_closure(pool,urls,'npm-vcs',identity)
    artifacts=[{'url':url,'integrity':sri,'sha256':downloaded[url]}
               for url,sri in sorted(urls.items())]
    write_new(pool.stage/'metadata'/('npm-vcs-'+key+'.json'),json.dumps({
        'repo':repo_ref,'commit':commit,'identity':identity,
        'resolver_npm':_pinned_npm_version(),
        'package_path':package_path,'package_sha256':hashlib.sha256(package_text.encode()).hexdigest(),
        'lockfile':lock,'artifacts':artifacts},sort_keys=True))
    shutil.rmtree(work)
    return artifacts


def npm_global_bootstrap(pool):
    """Freeze the exact npm CLI used by the benchmark's global npm upgrade."""
    sha,meta=npm_cli_artifact(pool,'npm-global-cli','npm')
    path=pool.stage/'metadata'/'npm-global.json'
    if not path.exists():
        write_new(path,json.dumps({'version':meta['version'],'url':meta['url'],
                                   'sha256':sha,'integrity':meta['integrity']},sort_keys=True))

def audit_inventory(pool,task_plan,envplan,gitplan,operation_id, *, contract_tasks=None,
                    conda_transactions=None,conda_lock_sha256=None):
    stage=pool.stage
    files=[];seen_inodes={}
    for path in sorted(stage.rglob('*')):
        if path.is_symlink():
            raise RuntimeError('symlink in dependency pool: '+str(path))
        if not path.is_file():continue
        rel=path.relative_to(stage).as_posix()
        info=path.stat();identity=(info.st_dev,info.st_ino)
        if identity in seen_inodes:
            row={'path':rel,'size':info.st_size,'sha256':seen_inodes[identity]}
        else:
            row={'path':rel,'size':info.st_size,'sha256':digest(path)}
            seen_inodes[identity]=row['sha256']
        files.append(row)

    file_digests={entry['path']:entry['sha256'] for entry in files}

    def reject(label,detail):
        pool.issue('inventory:'+label,detail)

    if not pool.links:reject('CAS','no acquired content-addressed objects')
    expected_tasks=len(contract_tasks) if contract_tasks is not None else len(task_plan)
    expected_envs=(len({task.get('env_hash') for task in contract_tasks.values()})
                   if contract_tasks is not None else len(envplan))
    expected_repos=(len({task.get('repo') for task in contract_tasks.values()})
                    if contract_tasks is not None else len(gitplan))
    if len(task_plan)!=expected_tasks or len(envplan)!=expected_envs or len(gitplan)!=expected_repos:
        reject('contract','dependency coverage does not match the pinned contract')
    for kind in ('conda','git','apt'):
        if not pool.provenance.get(kind):
            reject('provenance','no acquired '+kind+' artifacts')
    for sha,row in pool.links.items():
        if not SHA.fullmatch(sha) or row.get('sha256')!=sha:
            reject('CAS','invalid object identity '+str(sha));continue
        expected='objects/sha256/'+sha[:2]+'/'+sha
        target=stage/expected
        if (row.get('path')!=expected or not target.is_file() or target.is_symlink()
                or type(row.get('size')) is not int or target.stat().st_size!=row['size']
                or file_digests.get(expected)!=sha):
            reject('CAS','missing/bad object '+sha)
    for category,groups_ in pool.provenance.items():
        for identity,digests in groups_.items():
            if not isinstance(digests,list) or not digests:
                reject(category,'empty artifact provenance '+identity);continue
            for sha in digests:
                if sha not in pool.links:reject(category,'unregistered artifact '+sha)

    if contract_tasks is not None and set(task_plan)!=set(contract_tasks):
        reject('tasks','missing or extra task identity')

    validated_pip = set()
    def validate_pip(logical,key,*,optional):
        try:
            metadata = _pip_plan_path(stage, key)
            if metadata.is_symlink() or not metadata.is_file():
                raise ValueError('missing or unsafe pip closure')
            closure=json.loads(metadata.read_bytes())
            if closure.get('artifact_model')!=PIP_ARTIFACT_MODEL:
                raise ValueError('pip closure does not use the global content-addressed artifact model')
            if closure.get('plan_schema') != PIP_PLAN_SCHEMA or not isinstance(closure.get('target'), dict):
                raise ValueError('pip closure lacks target-environment resolution identity')
            failed=closure.get('optional_failed')
            if failed:
                if not optional or not isinstance(failed,str):
                    raise ValueError('failure marker on required closure')
                return
            dependencies = _read_pip_plan_tree(stage, key)
            for completed in dependencies.values():
                for sha in _pip_plan_artifact_shas(completed):
                    if sha not in pool.links:
                        raise ValueError('unregistered build/runtime artifact '+sha)
            validated_pip.update(dependencies)
            for artifact in closure.get('files',[]):
                if artifact.get('sha256') not in pool.links:
                    raise ValueError('unregistered wheel '+str(artifact))
            for artifact in closure.get('source_archives',[]):
                if artifact.get('sha256') not in pool.links:
                    raise ValueError('unregistered source '+str(artifact))
        except (OSError,ValueError,TypeError,KeyError) as exc:
            reject(logical,'invalid pip closure '+key+': '+str(exc))

    for logical,plan in task_plan.items():
        if contract_tasks is not None and logical in contract_tasks:
            expected=contract_tasks[logical]
            if (plan.get('repo')!=expected['repo'] or plan.get('base_commit')!=expected['base_commit']
                    or plan.get('env_hash')!=expected['env_hash']):
                reject(logical,'task identity diverges from pinned contract')
        repo,commit,env=plan.get('repo'),plan.get('base_commit'),plan.get('env_hash')
        if (repo not in gitplan or commit not in gitplan[repo].get('commits',[])
                or env not in envplan or plan.get('python')!=envplan[env]):
            reject(logical,'unresolved repo/commit/Conda environment')
        primary=plan.get('pip_plan')
        if primary is not None and primary not in plan.get('pip_steps',[]):
            reject(logical,'primary pip closure is not referenced by pip_steps')
        for key in plan.get('pip_steps',[]):validate_pip(logical,key,optional=False)
        for key in plan.get('environment_pip_steps',[]):validate_pip(logical,key,optional=False)
        for key in plan.get('pip_optional_steps',[]):validate_pip(logical,key,optional=True)

    # The template builder consumes every retained plan, including closures
    # discovered by local/VCS build hooks that have no direct task pip step.
    for metadata in sorted((stage/'metadata').glob('pip-plan-*.json')):
        key = metadata.name[len('pip-plan-'):-len('.json')]
        if key not in validated_pip:
            validate_pip('retained-plan', key, optional=True)

    if conda_transactions is None:
        conda_transactions={env:['env-'+env] for env in envplan}
    if set(conda_transactions)!=set(envplan):
        reject('Conda','transaction plan does not cover all environments')
    conda_keys=[]
    for env in envplan:
        keys=conda_transactions.get(env)
        if not isinstance(keys,list) or not keys or keys[-1]!='env-'+env:
            reject(env,'invalid Conda transaction sequence');continue
        conda_keys.extend(keys)
    for key in dict.fromkeys(conda_keys):
        metadata=stage/'metadata'/('conda-'+key+'.json')
        if not metadata.is_file():
            reject(key,'missing Conda solution');continue
        try:
            solution=json.loads(metadata.read_bytes())
            if not isinstance(solution,list) or not solution:
                raise ValueError('empty Conda package list')
            for artifact in solution:
                if artifact.get('sha256') not in pool.links or not artifact.get('url'):
                    raise ValueError('Conda archive not acquired')
        except (ValueError,TypeError,AttributeError) as exc:
            reject(key,'invalid Conda solution: '+str(exc))
    for logical,plan in task_plan.items():
        if not plan.get('environment_pip_steps'):continue
        env=plan.get('env_hash');keys=conda_transactions.get(env) or []
        if not keys:
            reject(logical,'environment pip phase has no base Conda transaction');continue
        try:
            base=json.loads((stage/'metadata'/('conda-'+keys[0]+'.json')).read_bytes())
            actual=conda_solution_full_python(base)
            expected_target=_locked_target(
                {'artifacts':{row['sha256']:row for row in base},
                 'environments':{env:{'transactions':[{'key':keys[0],'python':'.'.join(actual.split('.')[:2]),
                                                       'packages':[row['sha256'] for row in base]}]}}},
                env,keys[0])
            if (plan.get('environment_pip_python')!=actual
                    or plan.get('environment_pip_target')!=expected_target.as_dict()):
                raise ValueError('environment pip target does not match base Conda transaction')
        except (OSError,ValueError,TypeError,RuntimeError) as exc:
            reject(logical,'invalid environment pip phase: '+str(exc))

    apt_path=stage/'metadata'/'apt-closure.json'
    try:
        apt=json.loads(apt_path.read_bytes())
        if not apt.get('requested') or not apt.get('resolved'):
            raise ValueError('empty APT package resolution')
        for item in apt['resolved']:
            if (item.get('sha256') not in pool.links or not item.get('package')
                    or not item.get('version') or item.get('architecture') not in ('all',_target_debian_architecture())):
                raise ValueError('incomplete/bad APT archive metadata')
    except (OSError,ValueError,TypeError,AttributeError) as exc:
        reject('APT','missing/bad signed Kali closure: '+str(exc))

    # `apt-get upgrade` in upstream setup is deliberately not replayed against
    # the immutable Golden. Make the suppression explicit and contract-checked
    # rather than silently pretending an empty-status APT solve covers upgrades.
    try:
        policy=json.loads((stage/'metadata'/'apt-policy.json').read_bytes())
        flagged={logical for logical,plan in task_plan.items() if plan.get('apt_upgrade_suppressed') is True}
        expected=set()
        if contract_tasks is not None:
            for logical,task in contract_tasks.items():
                _,upgrades=apt_recipe_operations(task.get('repo_script_list',[]))
                if upgrades:expected.add(logical)
        if (policy.get('schema')!=1 or policy.get('upgrade_policy')!='suppress-on-frozen-golden'
                or set(policy.get('suppressed_tasks',[]))!=flagged
                or (contract_tasks is not None and flagged!=expected)):
            raise ValueError('APT upgrade suppression does not match pinned recipes')
    except (OSError,ValueError,TypeError) as exc:
        reject('APT-policy','missing/bad frozen-Golden upgrade policy: '+str(exc))

    frozen_path=stage/'metadata'/'vcs-frozen.json'
    try:
        frozen=json.loads(frozen_path.read_bytes())
        if not isinstance(frozen,dict):
            raise ValueError('VCS manifest is not a mapping')
        for ref,commit in frozen.items():
            if not isinstance(ref,str) or not isinstance(commit,str) or not COMMIT.fullmatch(commit):
                raise ValueError('invalid frozen VCS entry')
        for logical,plan in task_plan.items():
            for ref in plan.get('vcs',[]):
                if ref not in frozen:
                    reject(logical,'VCS source not frozen: '+ref)
    except (OSError,ValueError,TypeError) as exc:
        reject('VCS','missing/bad VCS pin manifest: '+str(exc))

    try:
        optional_failures=json.loads((stage/'metadata'/'vcs-optional-failures.json').read_bytes())
        required_refs={ref for plan in task_plan.values() for ref in plan.get('vcs',[])}
        optional_refs={ref for plan in task_plan.values() for ref in plan.get('optional_vcs',[])}
        if not isinstance(optional_failures,dict):
            raise ValueError('optional VCS failures are not a mapping')
        if any(ref in required_refs or ref not in optional_refs for ref in optional_failures):
            raise ValueError('required/unknown VCS source marked optional')
    except (OSError,ValueError,TypeError) as exc:
        reject('VCS-optional','bad optional VCS failure manifest: '+str(exc))

    try:
        npm_required=json.loads((stage/'metadata'/'vcs-npm-required.json').read_bytes())
        if not isinstance(npm_required,list) or not all(isinstance(ref,str) for ref in npm_required):
            raise ValueError('VCS npm requirement manifest is invalid')
        acquired=set((pool.provenance.get('npm-vcs') or {}).keys())
        for ref in npm_required:
            if ref not in acquired:reject('npm-vcs','JavaScript build closure missing for '+ref)
    except (OSError,ValueError,TypeError) as exc:
        reject('npm-vcs','missing/bad VCS npm requirement manifest: '+str(exc))

    issues=sorted(set(pool.issues))
    for url, sha in pool.by_url.items():
        if not isinstance(url,str) or not SHA.fullmatch(sha) or sha not in pool.links:
            reject('URL-index','unregistered URL-to-CAS artifact')
    issues=sorted(set(pool.issues))
    summary={'schema':2,'kind':'download-only-pool','complete':not issues,
             'operation_id':operation_id,'tasks':len(task_plan),'repos':len(gitplan),
             'conda_recipes':len(envplan),'python_versions':list(PYTHONS),
             'files':files,'issues':issues,'objects':pool.links,
             'url_index':dict(sorted(pool.by_url.items())),
             'provenance':pool.provenance,'task_plan':task_plan,
             'environment_plan':envplan,'conda_transactions':conda_transactions,
             'conda_lock_sha256':conda_lock_sha256,'git_plan':gitplan}
    write_new(stage/'inventory.json',json.dumps(summary,sort_keys=True,indent=2)+'\n')
    print('[pool] objects=',len(pool.links),'files=',len(files),'issues=',len(issues),flush=True)
    if issues:raise RuntimeError('incomplete dependency closure: '+issues[0]+
                                 '; inspect inventory.json; a later explicit fetch can reuse verified artifacts')
    return summary


def main(argv=None):
    global _POOL_PROGRESS
    p=argparse.ArgumentParser()
    p.add_argument('--repo-root',required=True,type=Path)
    p.add_argument('--stage',required=True,type=Path)
    p.add_argument('--operation-id',required=True)
    p.add_argument('--reuse-from',type=Path)
    args=p.parse_args(argv)
    if os.geteuid()==0:raise RuntimeError('refusing privileged fetch account')
    if not SHA.fullmatch(args.operation_id):raise RuntimeError('invalid operation ID')
    if args.stage.exists() or args.stage.is_symlink():raise RuntimeError('candidate stage already exists; refusing overwrite')
    repo_root=args.repo_root.resolve(strict=True)
    adapter=repo_root/'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym'
    pins=json.loads((adapter/'pins.json').read_bytes())
    if digest(adapter/'contract.json')!=pins['contract_sha256']:
        raise RuntimeError('pinned SWE-Gym Lite contract changed')
    contract=json.loads((adapter/'contract.json').read_bytes())
    conda_lock,conda_lock_sha256=load_conda_lock(adapter,pins,contract)
    # Validate the sealed execution-host target identity before creating a stage
    # or issuing any network request. Missing provenance can never waste a full
    # Conda/Git acquisition again.
    golden_target=_golden_target()
    _pinned_npm_version()
    tasks=contract['tasks'];environments=contract['environments']
    if not tasks or not environments or not {r['repo'] for r in tasks.values()}:
        raise RuntimeError('unexpected SWE-Gym Lite coverage')
    stage=args.stage
    stage.mkdir(mode=0o700)
    for name in ('git','git-extra','conda','wheels','metadata','downloads','npm','apt','objects'):
        (stage/name).mkdir(exist_ok=True)
    write_new(stage/'STAGING','Uncommitted, verified-resumable dependency acquisition.\n')
    _POOL_PROGRESS = _PoolProgress()
    _pool_progress('Verified recovery')
    verified=set()
    if args.reuse_from is not None:
        verified=salvage_verified_stage(args.reuse_from,stage,conda_artifacts=conda_lock['artifacts'])
    pool=Pool(stage)
    pool.conda_lock=conda_lock
    pool.verified_objects.update(verified)
    grouped=defaultdict(set)
    for task in tasks.values():grouped[task['repo']].add(task['base_commit'])
    mirrors,version_refs=_acquire_git_mirrors(
        stage,grouped,label='git',freeze_version_refs=True)
    gitplan={repo:{'commits':sorted(commits),'submodules':{},
                   'version_refs':version_refs[repo]}
             for repo,commits in sorted(grouped.items())}
    submodule_commits=defaultdict(set)
    inspected=0
    total_commits=sum(len(commits) for commits in grouped.values())
    _pool_progress('Inspecting Git submodules',0,total_commits,'commits')
    for repo,commits in sorted(grouped.items()):
        for commit in sorted(commits):
            # Preserve exact gitlinks generically. Scan locally first, then fetch
            # each independent submodule repository once with all pinned commits.
            for path,subrepo,sha in read_submodules(mirrors[repo],commit):
                previous=gitplan[repo]['submodules'].setdefault(path,{'repo':subrepo,'commits':[]})
                if previous.get('repo')!=subrepo:
                    raise RuntimeError('submodule path changes repository identity: '+repo+':'+path)
                if sha not in previous['commits']:previous['commits'].append(sha)
                submodule_commits[subrepo].add(sha)
            inspected+=1
            _pool_progress('Inspecting Git submodules',inspected,total_commits,'commits')
    _acquire_git_mirrors(stage,submodule_commits,label='git-extra')
    _acquire_nested_submodules(stage, gitplan)
    # Git files must not be linked to CAS while Git may still mutate refs.
    envplan={};requirements_by_env=defaultdict(set);vcs=set()
    vcs_by_env=defaultdict(set);environment_pip_target={}
    # Lock validation supplies transaction identities without downloading its
    # archive corpus. Static recipes and Python closures must be inspected first.
    conda_transaction_plan={env:[item['key'] for item in row['transactions']]
                            for env,row in conda_lock['environments'].items()}
    target_model=_target_environment_module()
    transaction_targets=target_model.locked_conda_targets(conda_lock,base_target=golden_target)
    base_target_by_env={};final_target_by_env={}
    for env,row in conda_lock['environments'].items():
        base_target_by_env[env]=transaction_targets[row['transactions'][0]['key']]
        final_target_by_env[env]=transaction_targets[row['transactions'][-1]['key']]
    _pool_progress('Conda recipe analysis',0,len(environments),'environments')
    for i,(env,entry) in enumerate(sorted(environments.items()),1):
        script=entry['original_script']
        version=python_version(script);envplan[env]=version
        locked=conda_lock['environments'][env]
        if locked['transactions'][-1]['python']!=version:
            raise RuntimeError('locked final Python differs from environment recipe: '+env)
        content=conda_yaml(script)
        pips=[]
        _pool_progress('Conda recipe analysis',i,len(environments),'environments')
        if content:
            _,pips=conda_pip_split(content)
            # The official upstream Dask recipe removes the pip section before
            # Conda sees it. Do not fetch packages from instructions it deletes.
            if any("sed -i '/- pip:/,/^ *-/d' environment.yml" in command
                   for command in script):
                pips=[]
            if conda_expected_transaction_keys(env,script)!=conda_transaction_plan[env]:
                raise RuntimeError('locked Conda transaction shape differs: '+env)
            if pips:
                environment_pip_target[env]=base_target_by_env[env]
        else:
            direct=conda_direct_specs(script)
            if not direct:
                raise RuntimeError('environment has neither YAML nor direct Conda create: '+env)
            if conda_transaction_plan[env]!=['env-'+env]:
                raise RuntimeError('direct Conda environment has unexpected locked transactions: '+env)
        for dep in pips:
            if not dep or dep.startswith('#'):continue
            if vcs_reference(dep):
                canonical=vcs_reference(dep)
                vcs.add(canonical)
                vcs_by_env[env].add(canonical)
            else:requirements_by_env[env].add(dep)
    # Trusted, pinned upstream spec table contains the evaluator prelude only.
    constants_file=adapter/'upstream'/'constants.py'
    if digest(constants_file)!=pins['upstream_files']['constants.py']:
        raise RuntimeError('untrusted evaluator setup constants')
    import importlib.util
    spec=importlib.util.spec_from_file_location('swe_gym_fetch_specs',constants_file)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    specs_table=module.MAP_REPO_VERSION_TO_SPECS
    task_plan={};groups={};apt_requested=set();apt_upgrade_tasks=set()
    # One immutable Git read cache for this acquisition attempt; results from
    # independent tasks are merged only by the main thread in logical task order.
    ordered_tasks=sorted(tasks.items())
    static_workers=min(_acquisition_workers(),len(ordered_tasks))
    source_cache=_StaticGitReadCache(static_workers)
    _pool_progress('Static task analysis',0,len(ordered_tasks),'recipes')

    def analyze_static_task(item):
        logical,task=item
        # The existing recipe evaluator below is preserved verbatim except for
        # isolated mutable accumulators, Git cache access and native isolation.
        task_plan={};groups={};apt_requested=set();apt_upgrade_tasks=set();vcs=set()
        own_issues=[]
        def issue(where,description):
            own_issues.append(f'{where}: {description}')
        repo=task['repo'];commit=task['base_commit'];mirror=mirrors[repo]
        version=envplan[task['env_hash']]
        commands=list(task['repo_script_list'])
        spec=specs_table[repo.lower()][task['version']]
        # Installation-relevant evaluator commands are public pinned spec data;
        # no patch, oracle, test command or private evaluator material is exported.
        commands.extend(spec.get('eval_commands',[]))
        for package in spec.get('pip_packages',[]):commands.append('pip install '+shlex.quote(package))
        get_file = lambda path,required=False: transformed_source(
            repo, path, source_cache.read(mirror,commit,path,required=required), commands)
        for command in list(commands):
            for match in re.finditer(r'(?<![\w-])make\s+(init|install)\b',command):
                try:
                    makefile=get_file('Makefile',required=True)
                    commands.extend(make_commands(makefile,match.group(1)))
                except (ValueError,RuntimeError) as exc:issue(logical,str(exc))
        env_hash=task['env_hash'];task_target=final_target_by_env[env_hash]
        env_pip_target=environment_pip_target.get(env_hash,task_target)
        env_requirements=set(requirements_by_env[env_hash]);env_vcs=set(vcs_by_env[env_hash])
        reqs=set();vcs_task=set();vcs_optional=set()
        explicit,reqfiles,_external,problems,extras,constraint_files,steps=pip_commands(commands)
        inline_constraints = set()
        for command in commands:
            if 'PIP_CONSTRAINT' in command:
                inline_constraints.update(re.findall(
                    r"echo\s+['\"]([A-Za-z0-9_.-]+[<>=!~][^'\"]+)['\"]\s*>", command))
        for problem in problems:issue(logical,problem)
        # Project metadata is read at the pinned commit and after the recipe's
        # explicitly supported textual transformations.
        # Native metadata is authoritative for actual local installations,
        # including static projects and --no-deps build-time requirements.
        if any(step['local_project'] for step in steps):
            reqs, vcs_task = _static_native_local_metadata(
                pool, task_target, mirror, commit, commands, extras)
        else:
            raw=get_file('pyproject.toml')
            if raw:
                try:
                    dep,git,problem=static_project(raw,extra_groups=extras)
                    reqs.update(dep);vcs_task.update(git)
                    dynamic={issue for issue in problem if issue.startswith('dynamic PEP621 ')}
                    if dynamic:
                        native_deps,native_vcs=_static_native_local_metadata(
                            pool,task_target,mirror,commit,commands,extras)
                        reqs.update(native_deps);vcs_task.update(native_vcs)
                    for ptext in problem:
                        if ptext not in dynamic:issue(logical,ptext)
                except (ValueError,TypeError) as exc:issue(logical,'invalid pyproject.toml: '+str(exc))
            cfg_deps,cfg_problems=setup_cfg_static(get_file('setup.cfg'),extras=extras)
            reqs.update(cfg_deps)
            for ptext in cfg_problems:issue(logical,ptext)
            setup=get_file('setup.py')
            setup_deps=set();setup_remote=set();setup_problems=[]
            for setup_argv in setup_script_invocations(commands):
                deps,remote,problems=setup_requirements_from_sources(
                    setup,get_file,extras=extras,python_version=task_target.python_full_version,
                    setup_argv=setup_argv)
                setup_deps.update(deps);setup_remote.update(remote);setup_problems.extend(problems)
            reqs.update(setup_deps);vcs_task.update(setup_remote)
            if setup_problems:
                native_deps,native_vcs=_static_native_local_metadata(
                    pool,task_target,mirror,commit,commands,extras)
                reqs.update(native_deps)
                vcs_task.update(native_vcs)

        task_steps=[];environment_steps=[];optional_steps=[];optional_skips=[]
        def register(req, constraints, name, *, no_deps=False, optional=False,
                     resolver_target=None, bucket='task', preferred_versions=None):
            if not req:return None
            selected_target=_coerce_target(resolver_target or task_target)
            preferred=_canonical_pip_preferences(preferred_versions)
            key=pip_group_key(selected_target,req,constraints,no_deps,preferred_versions=preferred)
            group=groups.setdefault(key,{'target':selected_target.as_dict(),'requirements':sorted(req),
                                          'constraints':sorted(constraints),'preferred_versions':preferred,'no_deps':no_deps,
                                          'required':not optional,'tasks':[],'steps':[]})
            if not optional:group['required']=True
            if logical not in group['tasks']:group['tasks'].append(logical)
            group['steps'].append(name)
            if optional:optional_steps.append(key)
            elif bucket=='environment':environment_steps.append(key)
            else:task_steps.append(key)
            return key

        # `pip:` entries embedded in environment.yml execute during the base
        # Conda transaction, not after a later Python override.
        register(env_requirements,set(),'conda-environment-pip',
                 resolver_target=env_pip_target,bucket='environment')

        # Sequential commands can replace earlier installed versions.
        # Retain earlier exact installs only as task-local ordering preferences;
        # imposing them as constraints produces false UNSAT on transitive deps.
        historical_pins = {}
        for step in steps:
            dependencies=set(step['requirements']);step_constraints=set(inline_constraints)
            step_vcs=set(step['vcs']);skip=False
            for filename in sorted(step['files']):
                try:
                    source=get_file(filename,required=not step['optional'])
                    if source is None and step['optional']:
                        optional_skips.append(step['command']+' [missing '+filename+']')
                        skip=True;break
                    a,b,c=parse_requirements(source,filename,get_file)
                    dependencies.update(a);step_vcs.update(b);step_constraints.update(c)
                except (ValueError,RuntimeError) as exc:
                    if step['optional']:
                        optional_skips.append(step['command']+' ['+str(exc)+']')
                        skip=True;break
                    issue(logical,str(exc))
            if skip: continue
            for filename in sorted(step['constraints']):
                try:
                    source=get_file(filename,required=not step['optional'])
                    if source is None and step['optional']:
                        optional_skips.append(step['command']+' [missing '+filename+']')
                        skip=True;break
                    a,b,c=parse_requirements(source,filename,get_file,constraint=True)
                    if a or b:raise RuntimeError('constraints incorrectly contain install targets')
                    step_constraints.update(c)
                except (ValueError,RuntimeError) as exc:
                    if step['optional']:
                        optional_skips.append(step['command']+' ['+str(exc)+']')
                        skip=True;break
                    issue(logical,str(exc))
            if skip: continue
            (vcs_optional if step['optional'] else vcs_task).update(step_vcs)
            # Local editable/develop is a separate installation against the
            # static package metadata. Remote VCS input is fetched separately.
            if step['local_project']:
                if not step['no_deps']:
                    dependencies.update(reqs)
            # The actual task installs these sequentially. Resolve an identical
            # Python target with only task-local previously pinned distributions.
            upgrade = any(token in ('-U', '--upgrade')
                          for token in shlex.split(step['command']))
            inherited = _historical_pip_preferences(
                historical_pins, dependencies, step_constraints, task_target,
                upgrade=upgrade)
            preferred = {}
            for package, pinned in sorted(inherited.items()):
                specifiers = tuple(_packaging_symbols()[0](pinned).specifier)
                if len(specifiers) != 1 or specifiers[0].operator != '==':
                    raise RuntimeError('invalid historical pip preference')
                preferred[package] = [specifiers[0].version]
            register(dependencies,step_constraints,step['command'],
                     no_deps=step['no_deps'],optional=step['optional'],preferred_versions=preferred)
            if not step['optional']:
                # The explicit new installation overrides any previous exact
                # pin for the same project; optional failures cannot establish
                # installed state for subsequent required steps.
                present = _historical_exact_pip_pins(dependencies,task_target)
                if upgrade:
                    names={_normalized_package_name(
                        _packaging_symbols()[0](normalize_legacy_source_requirement(row)).name)
                        for row in dependencies}
                    for name in names:historical_pins.pop(name,None)
                historical_pins.update(present)

        try:
            packages,upgrades=apt_recipe_operations(commands)
            apt_requested.update(packages)
            if upgrades:apt_upgrade_tasks.add(logical)
        except RuntimeError as exc:
            issue(logical,str(exc))
        for command in commands:
            for match in re.finditer(r'\bpipx\s+install\s+([\w.-]+)',command):
                # pipx creates its application venv from Kali's system Python,
                # not from the active historical Conda testbed interpreter.
                register({match.group(1)},set(),'pipx-application',
                         resolver_target=golden_target)
            if re.search(r'\bpdm\s+add\s+pre-commit',command):
                register({'pre-commit'},set(),'pdm-add')
            if re.search(r'\b(?:curl|wget)\b\s+https?://',command):
                issue(logical,'shell download needs explicit pinned hash: '+command[:90])

        primary=register(reqs,set(),'declarative-project-metadata')
        normalized_vcs={vcs_reference(item) or item for item in vcs_task}
        normalized_env_vcs={vcs_reference(item) or item for item in env_vcs}
        normalized_optional={vcs_reference(item) or item for item in vcs_optional}
        required_vcs=normalized_vcs|normalized_env_vcs
        vcs_targets={}
        def add_vcs_target(ref,target):
            serialized=_coerce_target(target).as_dict();fingerprint=_target_fingerprint(target)
            vcs_targets.setdefault(ref,{})[fingerprint]=serialized
        for ref in sorted(normalized_vcs):add_vcs_target(ref,task_target)
        for ref in sorted(normalized_env_vcs):add_vcs_target(ref,env_pip_target)
        for ref in sorted(normalized_optional):add_vcs_target(ref,task_target)
        task_plan[logical]={'repo':repo,'base_commit':commit,'env_hash':task['env_hash'],
                            'python':version,'target':task_target.as_dict(),
                            'environment_pip_python':env_pip_target.python_full_version,
                            'environment_pip_target':env_pip_target.as_dict(),
                            'pip_plan':primary,'pip_steps':task_steps,
                            'environment_pip_steps':environment_steps,
                            'pip_optional_steps':optional_steps,
                            'pip_optional_skips':optional_skips,
                            'vcs':sorted(required_vcs),
                            'optional_vcs':sorted(normalized_optional),
                            'vcs_targets':{ref:[values[key] for key in sorted(values)] for ref,values in sorted(vcs_targets.items())},
                            # Frozen Golden policy: official blanket upgrades are
                            # suppressed during eventual offline replay. Explicit
                            # apt-get install packages are still acquired below.
                            'apt_upgrade_suppressed':logical in apt_upgrade_tasks}
        vcs.update(required_vcs);vcs.update(normalized_optional)
        return (logical,task_plan[logical],groups,apt_requested,
                apt_upgrade_tasks,vcs,own_issues)

    with concurrent.futures.ThreadPoolExecutor(max_workers=static_workers,
            thread_name_prefix='static-task-analysis') as executor:
        for index,result in enumerate(executor.map(analyze_static_task,ordered_tasks),1):
            _merge_static_task_result(result,task_plan,groups,apt_requested,
                                      apt_upgrade_tasks,vcs,pool.issues)
            _pool_progress('Static task analysis',index,len(ordered_tasks),'recipes')

    write_new(stage/'metadata'/'apt-policy.json',json.dumps({
        'schema':1,'upgrade_policy':'suppress-on-frozen-golden',
        'suppressed_tasks':sorted(apt_upgrade_tasks),
        'requested_install_packages':sorted(apt_requested)},sort_keys=True,indent=2)+'\n')

    # Reject known-invalid pinned metadata BEFORE costly pip / VCS / npm / APT downloads.
    if pool.issues:
        static_issues=sorted(set(pool.issues))
        write_new(stage/'metadata'/'static-errors.json', json.dumps(static_issues, indent=2))
        for issue in static_issues:
            print('[pool] static issue: '+issue,file=sys.stderr,flush=True)
        raise RuntimeError('static dependency closure rejected before network resolution: '
                           +str(len(static_issues))+' issue(s); first: '+static_issues[0])
    acquire_pip_groups(pool,groups)
    # Pin VCS inputs, resolve metadata from pyproject/setup.cfg/setup.py, and
    # propagate nested VCS references only to tasks that depend on them.
    vcs_frozen={};vcs_optional_failures={};vcs_npm_required=set()
    vcs_required_tasks=defaultdict(set);vcs_optional_tasks=defaultdict(set)
    for logical,plan in task_plan.items():
        for value in plan['vcs']:vcs_required_tasks[value].add(logical)
        for value in plan.get('optional_vcs',[]):vcs_optional_tasks[value].add(logical)
    pending=set(vcs)
    visited_vcs=0
    _pool_progress('VCS dependency resolution',0,None,'sources visited',
                   f'{len(pending)} initially queued')
    while pending:
        if len(vcs_frozen) + len(pending) > MAX_VCS_CLOSURE:
            raise RuntimeError('VCS closure exceeds the audited finite bound')
        value=sorted(pending)[0];pending.remove(value)
        visited_vcs+=1
        _pool_progress('VCS dependency resolution',visited_vcs,None,'sources visited',
                       f'{len(pending)} queued')
        if value in vcs_frozen:continue
        required=bool(vcs_required_tasks[value])
        def vcs_failure(detail):
            if required:
                raise RuntimeError('required VCS closure failed for '+value+': '+detail)
            vcs_optional_failures[value]=detail
        canonical=vcs_reference(value)
        if canonical is None:
            vcs_failure('unrecognized Git reference');continue
        raw=canonical.removeprefix('git+').split('#',1)[0]
        parsed=urllib.parse.urlsplit(raw)
        repo_ref=parsed.path.strip('/')
        pinned=None
        if '@' in repo_ref:repo_ref,pinned=repo_ref.rsplit('@',1)
        repo_ref=repo_ref.removesuffix('.git')
        if parsed.scheme!='https' or parsed.hostname!='github.com' or not REPO.fullmatch(repo_ref):
            vcs_failure('unsupported source');continue
        if pinned and not COMMIT.fullmatch(pinned):
            if not re.fullmatch(r'[a-f0-9]{7,39}',pinned):
                vcs_failure('unresolved Git ref');continue
            api='https://api.github.com/repos/'+repo_ref+'/commits/'+pinned
            try:
                response=json.loads(_read_https(api,timeout=60,limit=1048576,
                    user_agent='gpt-trace-dependency-pool/2',expected_host='api.github.com'))
                resolved=response.get('sha')
                if not isinstance(resolved,str) or not COMMIT.fullmatch(resolved) or not resolved.startswith(pinned):
                    raise ValueError('GitHub returned a different commit identity')
                pinned=resolved
            except (OSError,ValueError) as exc:
                vcs_failure('unable to freeze abbreviated Git reference: '+str(exc));continue
        if not pinned:
            try:
                ref=invoke(['git','ls-remote','https://github.com/'+repo_ref+'.git','HEAD'],capture=True)
            except (RuntimeError,subprocess.CalledProcessError) as exc:
                vcs_failure('HEAD lookup failed: '+str(exc));continue
            match=re.fullmatch(r'([a-f0-9]{40})\s+HEAD\s*',ref)
            if not match:
                vcs_failure('HEAD could not be frozen');continue
            pinned=match.group(1)
        try:
            folder=ensure_commit(stage,repo_ref,pinned,label='git-extra')
            required_dependants=set(vcs_required_tasks[value])
            optional_dependants=set(vcs_optional_tasks[value])
            def ref_targets(logical,ref):
                plan=task_plan[logical]
                rows=plan.get('vcs_targets',{}).get(ref) or [plan['target']]
                result={}
                for row in rows:
                    target=_coerce_target(row);result[_target_fingerprint(target)]=target
                return result
            relevant={}
            for logical in required_dependants|optional_dependants:
                relevant.update(ref_targets(logical,value))
            if not relevant:
                raise RuntimeError('VCS source has no target interpreter identity')
            deps_by_target={};nested_by_target={}
            for fingerprint,target in sorted(relevant.items()):
                deps,nested = _native_local_metadata(pool,target,folder,pinned,[],())
                deps_by_target[fingerprint]=(target,deps)
                nested_by_target[fingerprint]=(target,nested)
            vcs_frozen[value]=pinned
            for fingerprint,(target,nested) in nested_by_target.items():
                for remote in nested:
                    normalized=vcs_reference(remote)
                    if normalized is None:raise RuntimeError('invalid nested VCS reference: '+remote)
                    for logical in required_dependants:
                        if fingerprint not in ref_targets(logical,value):continue
                        vcs_required_tasks[normalized].add(logical)
                        plan=task_plan[logical]
                        if normalized not in plan['vcs']:plan['vcs']=sorted([*plan['vcs'],normalized])
                        rows=plan.setdefault('vcs_targets',{}).setdefault(normalized,[])
                        if target.as_dict() not in rows:rows.append(target.as_dict())
                        rows.sort(key=lambda row:_target_fingerprint(row))
                    for logical in optional_dependants:
                        if fingerprint not in ref_targets(logical,value):continue
                        vcs_optional_tasks[normalized].add(logical)
                        plan=task_plan[logical]
                        if normalized not in plan['vcs'] and normalized not in plan['optional_vcs']:
                            plan['optional_vcs']=sorted([*plan['optional_vcs'],normalized])
                        rows=plan.setdefault('vcs_targets',{}).setdefault(normalized,[])
                        if target.as_dict() not in rows:rows.append(target.as_dict())
                        rows.sort(key=lambda row:_target_fingerprint(row))
                    if normalized not in vcs_frozen:pending.add(normalized)
            for fingerprint,(target,deps) in sorted(deps_by_target.items()):
                if not deps:continue
                key=pip_group_key(target,deps)
                required_for_target=any(fingerprint in ref_targets(item,value)
                                        for item in required_dependants)
                outcome=acquire_pip_group(pool,key,{
                    'target':target.as_dict(),'requirements':sorted(deps),'constraints':[],
                    'no_deps':False,'required':required_for_target,
                    'tasks':sorted(required_dependants|optional_dependants),'steps':['VCS '+value]})
                if outcome=='optional-failed':
                    vcs_optional_failures[value]='optional VCS transitive solve unavailable'
            setup_source=git_file(folder,pinned,'setup.py') or ''
            if re.search(r'check_call\(\s*\[\s*["\']npm["\']\s*,\s*["\']install["\']',setup_source):
                vcs_npm_required.add(value)
                try:npm_package_json_closure(pool,folder,pinned,repo_ref,value)
                except (RuntimeError,subprocess.CalledProcessError,OSError,ValueError) as exc:
                    if required_dependants:
                        raise RuntimeError('VCS npm closure: '+str(exc)) from exc
                    vcs_optional_failures[value]='optional VCS npm closure unavailable: '+str(exc)
        except (RuntimeError,subprocess.CalledProcessError,OSError,ValueError) as exc:
            # Do not retain a freeze proof for a source whose required closure
            # could not be inspected. Optional `|| true` sources may fail exactly
            # as the upstream recipe permits.
            vcs_frozen.pop(value,None)
            vcs_failure('VCS fetch/closure failed: '+str(exc))
    write_new(stage/'metadata'/'vcs-optional-failures.json',
              json.dumps(vcs_optional_failures,sort_keys=True,indent=2)+'\n')
    write_new(stage/'metadata'/'vcs-npm-required.json',json.dumps(sorted(vcs_npm_required),indent=2)+'\n')
    write_new(stage/'metadata'/'vcs-frozen.json',json.dumps(vcs_frozen,sort_keys=True,indent=2))
    # Freeze Git metadata only after all commits/tags/refs have been fetched.
    # Git FETCH_HEAD and refs are mutable during acquisition and must never be
    # hardlinked into content-addressed objects before that point.
    for kind in ('git','git-extra'):
        for path in sorted((stage/kind).rglob('*')):
            if path.is_file() and not path.is_symlink():
                pool.put(path,kind,path.relative_to(stage/kind).parts[0])
    # NPM lockfiles pinned via Subresource Integrity; no package scripts execute.
    npm_urls={}
    npm_done=0
    npm_total=sum(map(len,grouped.values()))
    _pool_progress('NPM lock analysis',0,npm_total,'commits')
    for repo,commits in sorted(grouped.items()):
        for commit in sorted(commits):
            for filename in git_files_named(mirrors[repo],commit,'package-lock.json'):
                source=git_file(mirrors[repo],commit,filename,required=True)
                try:lock=json.loads(source)
                except ValueError as exc:raise RuntimeError('invalid npm lockfile for '+repo+': '+filename) from exc
                def workspace(url, *, _repo=repo, _commit=commit, _filename=filename):
                    if (not isinstance(url,str) or Path(url).is_absolute()
                            or '..' in Path(url).parts or '\\' in url):
                        raise RuntimeError('unsafe npm workspace reference')
                    directory=str(Path(_filename).parent/url)
                    row=invoke(['git','--git-dir',mirrors[_repo],'ls-tree','-d',
                                _commit,'--',directory],capture=True).strip()
                    if not re.fullmatch(r'040000 tree [a-f0-9]{40}\t.+',row):
                        raise RuntimeError('npm workspace missing from pinned Git source: '+directory)
                found=npm_lock_urls(lock,repo+':'+filename,workspace_checker=workspace)
                for url,integ in found.items():
                    if url in npm_urls and npm_urls[url]!=integ:
                        raise RuntimeError('conflicting npm lockfile integrity for '+url)
                    npm_urls[url]=integ
            npm_done+=1
            _pool_progress('NPM lock analysis',npm_done,npm_total,'commits')
    _download_sri_closure(pool,npm_urls,'npm')
    # A pinned recipe may request a global npm CLI update outside its lockfile.
    # Freeze that CLI as an immutable SRI-verified dependency as well.
    if any('npm install --location=global npm' in cmd
           for task in tasks.values() for cmd in task['repo_script_list']):
        try: npm_global_bootstrap(pool)
        except (RuntimeError,OSError,ValueError) as exc:
            raise RuntimeError('required npm CLI acquisition failed: '+str(exc)) from exc
    # Signed APT download-only resolution against Kali, never the Ubuntu host.
    os_source=adapter/'os_packages.py'
    import ast
    tree=ast.parse(os_source.read_text())
    rows=[node.value for node in tree.body if isinstance(node,ast.Assign) and any(
          isinstance(target,ast.Name) and target.id=='PACKAGES' for target in node.targets)]
    if len(rows)!=1:raise RuntimeError('missing pinned APT manifest')
    apt_requested.update(ast.literal_eval(rows[0]))
    _pool_progress('Signed Kali APT resolution',details=f'{len(apt_requested)} requested packages')
    try:apt_closure(pool,apt_requested)
    except (RuntimeError,subprocess.CalledProcessError,OSError) as exc:
        raise RuntimeError('required signed Kali closure unavailable: '+str(exc)) from exc
    _pool_progress('Conda archive acquisition')
    acquired_transactions,_locked_base_python=acquire_locked_conda(pool,conda_lock)
    if acquired_transactions!=conda_transaction_plan:
        raise RuntimeError('acquired Conda transaction identities differ from prevalidated lock')
    _native_close(pool)
    with (Path(__file__).resolve().parents[1] / 'config/preparation.toml').open('rb') as stream:
        bootstrap=tomllib.load(stream)['bootstrap']
    _pool_progress('Miniconda bootstrap archive')
    pool.download('https://repo.anaconda.com/miniconda/' + bootstrap['miniconda_archive'],
                  'bootstrap', 'miniconda-installer', sha=bootstrap['miniconda_sha256'])
    _pool_progress('Verifying final pool inventory')
    audit_inventory(pool,task_plan,envplan,gitplan,args.operation_id,contract_tasks=tasks,
                    conda_transactions=conda_transaction_plan,
                    conda_lock_sha256=conda_lock_sha256)
    _pool_progress('Dependency acquisition complete',force=True)


if __name__=='__main__':
    try:main()
    except BaseException as exc:
        if _POOL_PROGRESS is not None: _POOL_PROGRESS.finish()
        print('[pool] FAILED; data retained, no automatic cleanup:',str(exc),file=sys.stderr,flush=True)
        raise
