"""Expose independent native Conda package actions to preparation supervisors."""
from __future__ import annotations

import functools
import inspect
import itertools
import re
import runpy
import sys
import threading
from pathlib import Path


def run_conda_actions(arguments, emit):
    events = itertools.count(1)
    thread_scope = threading.local()
    from conda.core import link, package_cache_data, path_actions

    def wrap(function, label):
        @functools.wraps(function)
        def observed(*args, **kwargs):
            ident = next(events)
            description = label
            if args:
                subject = args[0]
                attributes = vars(subject) if hasattr(subject, '__dict__') else {}
                detail = attributes.get('target_short_path')
                if detail is None:
                    detail = attributes.get('source_short_path')
                if detail is not None:
                    description += ':' + str(detail)[:200]
            stack = getattr(thread_scope, 'stack', None)
            if stack is None:
                stack = []
                thread_scope.stack = stack
            if stack:
                emit('pause', stack[-1][0], stack[-1][1])
            emit('begin', ident, description)
            stack.append((ident, description))
            try:
                return function(*args, **kwargs)
            finally:
                stack.pop()
                emit('end', ident, description)
                if stack:
                    emit('resume', stack[-1][0], stack[-1][1])
        return observed

    def descendants(parent):
        for subtype in parent.__subclasses__():
            yield subtype
            yield from descendants(subtype)

    classes = list(dict.fromkeys((path_actions._Action, *descendants(path_actions._Action))))
    instrumented = 0
    for cls in classes:
        for name in ('execute', 'verify'):
            function = cls.__dict__.get(name)
            if inspect.isfunction(function) and not getattr(function, '__isabstractmethod__', False):
                setattr(cls, name, wrap(function, 'conda:' + cls.__name__ + '.' + name))
                instrumented += 1
    if instrumented < 2:
        raise RuntimeError('Conda elementary action instrumentation is unavailable')

    # Each explicit archive gets its own preparation budget. This is not the
    # deadline for ProgressiveFetchExtract.execute, which handles many archives.
    original_record = package_cache_data.ProgressiveFetchExtract.make_actions_for_record
    package_cache_data.ProgressiveFetchExtract.make_actions_for_record = staticmethod(
        wrap(original_record, 'conda:prepare_package'))
    link.run_script = wrap(link.run_script, 'conda:package_script')
    package_cache_data.do_extract_action = wrap(
        package_cache_data.do_extract_action, 'conda:extract_package')
    package_cache_data.do_cache_action = wrap(
        package_cache_data.do_cache_action, 'conda:cache_package')
    emit('ready', 0, 'conda:instrumented')
    sys.argv = ['conda', *arguments]
    try:
        runpy.run_module('conda', run_name='__main__', alter_sys=True)
    except SystemExit as exc:
        if exc.code is None or exc.code == 0:
            emit('complete', 0, 'conda:complete')
        raise
    else:
        emit('complete', 0, 'conda:complete')


def template_main():
    arguments = sys.argv[1:]
    if not ((arguments[:1] == ["create"] and ("--offline" in arguments or "--clone" in arguments))
            or arguments[:2] == ["env", "remove"]):
        raise ValueError("unsupported supervised Conda template operation")

    with Path("/dev/ttyS0").open("wb", buffering=0) as serial:
        writer = threading.Lock()

        def emit(event, identity, description):
            if event in {"ready", "complete"}:
                return
            label = f"conda-{identity}-" + re.sub(r"[^a-zA-Z0-9._+-]", "-", description)
            payload = f"GPTTRACE_TEMPLATE {event} {label[:128]}\n".encode("ascii")
            with writer:
                if serial.write(payload) != len(payload):
                    raise OSError("short Conda serial record")

        run_conda_actions(arguments, emit)


if __name__ == "__main__":
    template_main()
