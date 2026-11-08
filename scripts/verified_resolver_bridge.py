"""Mandatory Rust graph search. Python is *only* the verified packaging/PEP-517 I/O oracle.

The wire format is private, strict, binary and scoped to one subprocess/closure.
No Python backtracking or alternative solver is available on any failure.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import importlib.util
import io
import json
import os
import struct
import subprocess
import tempfile
import threading
from pathlib import Path



def _uint(number, width):
    if type(number) is not int or number < 0 or number >= 1 << (width * 8):
        raise RuntimeError('invalid verified resolver IPC integer')
    return number.to_bytes(width, 'big')


class _Wire:
    def __init__(self, child, frame_limit):
        self.reader = child.stdout
        self.writer = child.stdin
        self.limit = frame_limit

    def exact(self, count):
        if count < 0 or count > self.limit:
            raise RuntimeError('verified resolver exceeded IPC frame limit')
        value = self.reader.read(count)
        if value is None or len(value) != count:
            raise RuntimeError('verified resolver terminated during IPC')
        return value

    def number(self, width=4):
        return int.from_bytes(self.exact(width), 'big')

    def string(self):
        length = self.number()
        return self.exact(length).decode('utf-8', 'strict')

    def strings(self):
        count = self.number()
        if count > self.limit:
            raise RuntimeError('verified resolver supplied excessive item count')
        return [self.string() for _ in range(count)]

    def send_int(self, value, width=4):
        self.writer.write(_uint(value, width))

    def send_string(self, value):
        if type(value) is not str:
            raise RuntimeError('invalid verified resolver IPC string')
        raw = value.encode('utf-8')
        if len(raw) > self.limit:
            raise RuntimeError('verified resolver IPC text exceeds versioned limit')
        self.send_int(len(raw))
        self.writer.write(raw)

    def send_strings(self, values):
        self.send_int(len(values))
        for value in values:
            self.send_string(value)

    def response(self, result):
        # Encode the entire successful result before publishing its success bit.
        # A failed metadata probe must never leave a partial success response.
        destination = self.writer
        output = io.BytesIO()
        try:
            self.writer = output
            result()
        finally:
            self.writer = destination
        destination.write(b'\x01')
        destination.write(output.getvalue())
        destination.flush()

    def error(self, exc):
        self.writer.write(b'\x00')
        self.send_string(type(exc).__name__ + ': ' + str(exc))
        self.writer.flush()



def _policy(root):
    import tomllib
    source = root / 'config/preparation.toml'
    if source.is_symlink() or not source.is_file():
        raise RuntimeError('missing sealed resolver policy')
    with source.open('rb') as stream:
        controls = tomllib.load(stream)['acquisition']
    fields = ('pip_solver_max_decisions', 'pip_solver_max_depth',
              'pip_solver_cache_max_bytes', 'pip_solver_max_frame_bytes',
              'pip_total_timeout_seconds')
    if any(type(controls.get(name)) is not int or controls[name] < 1 for name in fields):
        raise RuntimeError('invalid versioned Rust solver resource controls')
    if controls['pip_solver_max_frame_bytes'] >= 2 ** 32:
        raise RuntimeError('Rust IPC frame size exceeds protocol capacity')
    return {key: controls[key] for key in fields}


def _binary(root):
    # One source of truth: the sealed, versioned Cargo manifest and the common
    # Fossil/Acer build identity contract. Never infer a binary from an Acer path.
    module_path = root / 'shared/gpt_trace_transport/local_templates.py'
    if module_path.is_symlink() or not module_path.is_file():
        raise RuntimeError('missing sealed runtime identity contract')
    spec = importlib.util.spec_from_file_location('verified_resolver_local_identity', module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError('invalid sealed runtime identity contract')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.verify_fetch_runtime_build_identity(root)
    return root / module.fetch_runtime_executables(root)[0]



def _same_pep440_version(host, observed, expected):
    """Version spelling is not a release identity: compare PEP 440 values."""
    if not isinstance(observed, str) or not isinstance(expected, str):
        return False
    _, _, Version, InvalidVersion, _ = host['_packaging_symbols']()
    try:
        return Version(observed) == Version(expected)
    except InvalidVersion:
        return False


def _verify_solution(host, target, roots, constraints_by_name, records, *, no_deps):
    """Independent Python packaging audit of the Rust solution, no second solve."""
    names = [host['_normalized_package_name'](row['name']) for row in records]
    if names != sorted(set(names)):
        raise RuntimeError('native Rust solution has duplicate or unordered projects')
    selected = dict(zip(names, records))
    required = {}
    extras_by_name = {}
    for root in roots:
        name = host['_normalized_package_name'](root.name)
        required.setdefault(name, []).append(root)
        extras_by_name.setdefault(name, set()).update(root.extras)
    expanded = {}
    while True:
        for name, checks in required.items():
            record = selected.get(name)
            if record is None or not host['_candidate_satisfies'](
                    record, checks, constraints_by_name.get(name, [])):
                raise RuntimeError('Rust solution fails independent PEP 440 audit for ' + name)
        if no_deps:
            break
        grew = False
        for name in sorted(required):
            active = frozenset(extras_by_name.get(name, ()))
            if expanded.get(name) == active:
                continue
            record = selected[name]
            for raw in record['requirements']:
                dep = host['_parse_registry_requirement'](raw)
                if not host['_marker_active'](dep, target, active):
                    continue
                dep_name = host['_normalized_package_name'](dep.name)
                required.setdefault(dep_name, []).append(dep)
                extras_by_name.setdefault(dep_name, set()).update(dep.extras)
            expanded[name] = active
            grew = True
        if not grew:
            break
    if set(selected) != set(required):
        raise RuntimeError('Rust solution contains unreachable or undeclared distributions')


def solve(host, pool, target, reqs, constraints, key, *, no_deps=False,
          resolver_cache=None, materialize=True, preferred_versions=None):
    """One required Rust binary per independent closure; Python supplies exact PyPI evidence."""
    target = host['_coerce_target'](target)
    target_root = Path(host['__file__']).resolve().parents[1]
    program = _binary(target_root)
    policy = _policy(target_root)
    constraints_by_name = host['_constraint_map'](constraints, target)
    resolver_cache = {} if resolver_cache is None else resolver_cache
    probe_cache = resolver_cache.setdefault('release_metadata', host['_SingleFlightCache']())
    artifact_cache = resolver_cache.setdefault('artifact_metadata', host['_SingleFlightCache']())
    release_cache = resolver_cache.setdefault('releases', host['_SingleFlightCache']())
    source_probe = resolver_cache.get('native_source_probe')
    prefetch_controller = resolver_cache.get('prefetch_controller')
    executor = resolver_cache.get('metadata_executor')
    prefetch_width = (prefetch_controller.width() if prefetch_controller is not None
                      else resolver_cache.get('metadata_prefetch', 1))
    wheel_only = (resolver_cache.get('sources_require_locked_python') is True
                  and not target.python_artifact_sha256)
    preferred = (host['_canonical_pip_preferences'](preferred_versions)
                 if preferred_versions is not None else resolver_cache.get('preferred_versions'))

    roots = []
    for raw in sorted(set(reqs)):
        requirement = host['_parse_registry_requirement'](raw)
        if host['_marker_active'](requirement, target):
            roots.append(requirement)
    if not roots:
        return []

    candidate_by_id = {}
    id_by_identity = {}
    record_by_id = {}
    domain_cache = {}
    valid_cache = {}
    probe_lock = threading.Lock()
    candidate_lock = threading.Lock()
    observed_lock = threading.Lock()
    observed_metadata = set()
    prefetch_futures = {}

    def retain_prefetch(references):
        """Only the current Rust candidate window may keep queued metadata work.

        Completed probes remain in the validated single-flight/record caches,
        while unneeded pending futures are canceled, not silently waited for.
        """
        keep = set(references)
        if len(keep) != len(references):
            raise RuntimeError('duplicate native Rust prefetch candidate')
        for ref in tuple(prefetch_futures):
            if ref not in keep:
                prefetch_futures.pop(ref).cancel()

    def domain(name, requirements):
        raw = tuple(requirements)
        cache_key = name, raw
        if cache_key in domain_cache:
            return domain_cache[cache_key]
        parsed = [host['_parse_registry_requirement'](value) for value in raw]
        items = host['_candidate_versions'](
            pool, name, parsed, constraints_by_name.get(name, []), target,
            release_cache=release_cache, preferred_versions=preferred)
        if wheel_only:
            items = [candidate for candidate in items if candidate['kind'] == 'wheel']
        ids = []
        for candidate in items:
            identity = (candidate['name'], candidate['kind'], candidate['version'],
                        candidate['filename'], host['_candidate_artifact_identity'](candidate))
            with candidate_lock:
                ref = id_by_identity.get(identity)
                if ref is None:
                    ref = len(candidate_by_id) + 1
                    if ref >= 2 ** 32:
                        raise RuntimeError('native Rust candidate reference overflow')
                    id_by_identity[identity] = ref
                    candidate_by_id[ref] = candidate
            ids.append(ref)
        domain_cache[cache_key] = ids
        return ids

    def record(ref):
        if ref not in candidate_by_id:
            raise RuntimeError('Rust returned a candidate absent from the verified registry')
        with probe_lock:
            value = record_by_id.get(ref)
            if value is not None:
                with observed_lock:
                    observed_metadata.add(host['_normalized_package_name'](value['name']))
                return value
        candidate = candidate_by_id[ref]
        if candidate['kind'] == 'sdist' and source_probe is not None:
            identity = ('native-source', host['_candidate_probe_identity'](candidate, target, no_deps))
            artifact_id = ('native-source-artifact',host['_target_fingerprint'](target),
                           host['_candidate_artifact_identity'](candidate)[0], candidate['filename'])
            value = host['_memo_get_or_compute'](probe_cache, identity,
                lambda: host['_memo_get_or_compute'](artifact_cache, artifact_id,
                    lambda: source_probe(pool, candidate, key, target)))
        else:
            value = host['_candidate_release_metadata'](
                pool, candidate, key, target, probe_cache, artifact_cache, no_deps=no_deps)
        if (not isinstance(value, dict) or
                value.get('kind') != candidate['kind'] or
                host['_normalized_package_name'](value.get('name', '')) != host['_normalized_package_name'](candidate['name']) or
                not _same_pep440_version(host, value.get('version'), candidate['version']) or
                not isinstance(value.get('requirements'), list) or
                not all(isinstance(item, str) for item in value['requirements'])):
            raise RuntimeError('verified candidate metadata differs from chosen release')
        with probe_lock:
            record_by_id[ref] = value
        with observed_lock:
            observed_metadata.add(host['_normalized_package_name'](candidate['name']))
        return value

    def active_dependencies(ref, extras):
        result = []
        for raw in record(ref)['requirements']:
            req = host['_parse_registry_requirement'](raw)
            if not host['_marker_active'](req, target, extras):
                continue
            result.append(req)
        return result

    with tempfile.TemporaryFile(mode='w+b') as errors:
        child = subprocess.Popen([str(program)], cwd=target_root,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors,
                close_fds=True, start_new_session=True)
        wire = _Wire(child, policy['pip_solver_max_frame_bytes'])
        # A complete closure has no artificial wall-clock deadline. Native
        # metadata requests and isolated build hooks enforce their own limits.
        result = None
        outcome = None
        summary = None
        try:
            wire.send_int(wire.limit, 8)
            wire.send_int(policy['pip_solver_max_decisions'], 8)
            wire.send_int(policy['pip_solver_max_depth'], 8)
            wire.send_int(policy['pip_solver_cache_max_bytes'], 8)
            wire.send_int(0, 8)  # Rust protocol: no global deadline for a closure.
            wire.send_int(prefetch_width, 8)
            wire.send_int(int(bool(no_deps)), 1)
            wire.send_int(len(roots))
            for requirement in roots:
                name = host['_normalized_package_name'](requirement.name)
                wire.send_string(name)
                wire.send_string(str(requirement))
                wire.send_strings(sorted(requirement.extras))
            wire.writer.flush()
            while True:
                op = wire.exact(1)
                if op == b'D':
                    name, requirements = wire.string(), wire.strings()
                    def deliver_domain():
                        refs = domain(name, requirements)
                        wire.send_int(len(refs))
                        for ref in refs:
                            candidate = candidate_by_id[ref]
                            wire.send_int(ref)
                            for field in ('kind', 'version', 'filename'):
                                wire.send_string(candidate[field])
                    action = deliver_domain
                elif op == b'B':
                    # Mirror Python domain_futures: fetch every unresolved
                    # requirement domain concurrently, collect in sorted order.
                    count = wire.number()
                    if count > wire.limit:
                        raise RuntimeError('unbounded native domain batch')
                    requests = [(wire.string(), tuple(wire.strings())) for _ in range(count)]
                    def deliver_domains():
                        if executor is None:
                            results = [domain(name, rows) for name, rows in requests]
                        else:
                            pending = [executor.submit(domain, name, rows)
                                       for name, rows in requests]
                            try:
                                results = [future.result() for future in pending]
                            except BaseException:
                                for future in pending:
                                    future.cancel()
                                raise
                        wire.send_int(len(results))
                        for refs in results:
                            wire.send_int(len(refs))
                            for ref in refs:
                                candidate = candidate_by_id[ref]
                                wire.send_int(ref)
                                for field in ('kind', 'version', 'filename'):
                                    wire.send_string(candidate[field])
                    action = deliver_domains
                elif op == b'K':
                    # Match Python cached_compatible: only inspected,
                    # immutable metadata may justify forward pruning.
                    count = wire.number()
                    if count > wire.limit:
                        raise RuntimeError('unbounded native cache-inspection batch')
                    references = [wire.number() for _ in range(count)]
                    def deliver_known():
                        for ref in references:
                            candidate = candidate_by_id.get(ref)
                            if candidate is None:
                                raise RuntimeError('unknown Rust metadata-cache candidate')
                            name = host['_normalized_package_name'](candidate['name'])
                            with observed_lock:
                                observed = name in observed_metadata
                            if no_deps or not observed:
                                known = False
                            else:
                                identity = host['_candidate_probe_identity'](
                                    candidate, target, no_deps)
                                entry = (probe_cache.peek(identity)
                                         if isinstance(probe_cache, host['_SingleFlightCache'])
                                         else probe_cache.get(identity))
                                known = entry is not None
                            wire.send_int(int(known), 1)
                    action = deliver_known
                elif op == b'W':
                    # The fairness controller is re-evaluated for each
                    # candidate, as in Python schedule_metadata(position).
                    def deliver_width():
                        width = (prefetch_controller.width()
                                 if prefetch_controller is not None
                                 else prefetch_width)
                        wire.send_int(width)
                    action = deliver_width
                elif op == b'A':
                    count = wire.number()
                    if count > wire.limit:
                        raise RuntimeError('unbounded Rust metadata prefetch')
                    references = [wire.number() for _ in range(count)]
                    def deliver_prefetch():
                        # Validate the whole window before touching existing work.
                        for ref in references:
                            if ref not in candidate_by_id:
                                raise RuntimeError('unknown Rust metadata prefetch candidate')
                        retain_prefetch(references)
                        if executor is not None:
                            for ref in references:
                                if ref not in prefetch_futures and ref not in record_by_id:
                                    prefetch_futures[ref] = executor.submit(record, ref)
                    action = deliver_prefetch
                elif op == b'X':
                    # Entering another search branch abandons speculative work
                    # from the previous branch, not its completed verified cache.
                    def deliver_prefetch_clear():
                        retain_prefetch(())
                    action = deliver_prefetch_clear
                elif op == b'C':
                    ref, requirements = wire.number(), wire.strings()
                    def deliver_check():
                        if ref not in candidate_by_id:
                            raise RuntimeError('unknown Rust compatibility candidate')
                        candidate = candidate_by_id[ref]
                        name = host['_normalized_package_name'](candidate['name'])
                        cache_key = (ref, tuple(requirements))
                        matches = valid_cache.get(cache_key)
                        if matches is None:
                            parsed = [host['_parse_registry_requirement'](value) for value in requirements]
                            matches = host['_candidate_satisfies'](
                                candidate, parsed, constraints_by_name.get(name, []))
                            valid_cache[cache_key] = matches
                        wire.send_int(int(matches), 1)
                    action = deliver_check
                elif op == b'M':
                    count = wire.number()
                    if count > wire.limit:
                        raise RuntimeError('unbounded native metadata request')
                    references = [wire.number() for _ in range(count)]
                    def deliver_metadata():
                        for ref in references:
                            future = prefetch_futures.pop(ref, None)
                            if future is None:
                                record(ref)
                            else:
                                future.result()
                    action = deliver_metadata
                elif op == b'P':
                    ref, extras = wire.number(), wire.strings()
                    def deliver_expansion():
                        dependencies = [] if no_deps else active_dependencies(ref, set(extras))
                        wire.send_int(len(dependencies))
                        for req in dependencies:
                            wire.send_string(host['_normalized_package_name'](req.name))
                            wire.send_string(str(req))
                            wire.send_strings(sorted(req.extras))
                    action = deliver_expansion
                elif op == b'S':
                    count = wire.number()
                    if count > wire.limit:
                        raise RuntimeError('unbounded native solution')
                    selected = [wire.number() for _ in range(count)]
                    summary = wire.string()
                    if len(selected) != len(set(selected)):
                        raise RuntimeError('duplicate Rust solution candidate')
                    result = [record(ref) for ref in selected]
                    outcome = 'success'
                    break
                elif op in (b'U', b'F'):
                    detail = wire.string()
                    summary = wire.string() if op == b'U' else None
                    outcome = 'error'
                    result = (detail, summary)
                    break
                else:
                    raise RuntimeError('invalid mandatory Rust solver IPC opcode')
                try:
                    wire.response(action)
                except BaseException as exc:
                    wire.error(exc)
                    # The Rust solver receives the exact failure and exits; it
                    # cannot reinterpret missing PyPI evidence as UNSAT.
            wire.writer.close()
            status = child.wait(timeout=30)
            if status != 0 and outcome == 'success':
                raise RuntimeError('Rust solver exited with nonzero status after reporting success')
            if outcome == 'error':
                detail, stats = result
                raise RuntimeError(('deterministic registry dependency resolution is unsatisfiable; '
                                    if stats is not None else 'native Rust resolver failed: ')
                                   + detail + ('; ' + stats if stats else ''))
            if outcome != 'success':
                raise RuntimeError('native Rust resolver provided no solution')
            _verify_solution(host, target, roots, constraints_by_name, result, no_deps=no_deps)
            if host.get('_POOL_PROGRESS') is None:
                print('[pool] Rust resolver ' + key + ': solved ' + str(len(result)) + ' packages; '
                      + summary, flush=True)
            return (host['_materialize_solution'](
                        pool, result, key, target, artifact_cache, executor=executor,
                        source_probe=source_probe) if materialize else result)
        except BaseException as exc:
            if child.poll() is None:
                child.kill()
            child.wait()
            errors.seek(max(0, errors.tell() - 8192))
            text = errors.read().decode(errors='replace')
            if text:
                raise RuntimeError(str(exc) + '; Rust stderr: ' + text) from exc
            raise
        finally:
            for future in prefetch_futures.values():
                future.cancel()
            if child.stdin is not None and not child.stdin.closed:
                child.stdin.close()
            if child.stdout is not None and not child.stdout.closed:
                child.stdout.close()
