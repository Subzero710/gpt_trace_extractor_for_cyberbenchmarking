from __future__ import annotations

import importlib.util
import itertools
from collections import namedtuple
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


trace = load('template_conda_package_trace', 'infra/workstation/image/template_conda_trace.py')
watch_module = load('template_conda_package_watch', 'shared/gpt_trace_transport/operation_watch.py')


@pytest.fixture
def native():
    calls = []
    events = []
    group = namedtuple('ActionGroup', 'type pkg_data actions target_prefix')

    class Action:
        verified = False

        def __init__(self, name, error=None):
            self.name = name
            self.error = error

        def verify(self):
            calls.append(('verify', self.name))
            self.verified = True
            return self.error

        def execute(self):
            calls.append(('execute', self.name))
            if self.error:
                raise self.error

        def reverse(self):
            calls.append(('reverse', self.name))

    class Record(Action):
        def __init__(self, package):
            super().__init__(package.name)
            self.package_info = package

        def execute(self):
            return super().execute()

        def reverse(self):
            return super().reverse()

    class Transaction:
        @staticmethod
        def _verify_individual_level(groups):
            errors = []
            for action in itertools.chain.from_iterable(g.actions for batch in groups for g in batch):
                if not action.verified:
                    error = action.verify()
                    if error:
                        errors.append(error)
            return errors

        @staticmethod
        def _execute_actions(group):
            try:
                for action in group.actions:
                    action.execute()
            except Exception as exc:
                Transaction._reverse_actions(group)
                return exc

        @staticmethod
        def _reverse_actions(group, reverse_from_idx=-1):
            actions = group.actions if reverse_from_idx < 0 else group.actions[:reverse_from_idx + 1]
            for action in reversed(actions):
                action.reverse()
            return []

        @staticmethod
        def _verify_prefix_level(argument):
            return argument

        @staticmethod
        def _make_link_actions(context, package_info, *args):
            return package_info

        _make_entry_point_actions = _make_link_actions
        _make_compile_actions = _make_link_actions

    class FetchExtract:
        @staticmethod
        def make_actions_for_record(record):
            return record

    link = SimpleNamespace(UnlinkLinkTransaction=Transaction,
                           make_unlink_actions=lambda context, prefix, record: record,
                           read_package_info=lambda record, cache_record: record,
                           run_script=lambda prefix, prec, action='post-link', *args, **kwargs: True)
    cache = SimpleNamespace(ProgressiveFetchExtract=FetchExtract,
                            do_cache_action=lambda prec, *args, **kwargs: prec,
                            do_extract_action=lambda prec, *args, **kwargs: prec,
                            do_cleanup=lambda actions: None, do_reverse=lambda actions: None)
    action_method = Action.verify
    trace.instrument_package_actions(link, cache, SimpleNamespace(CreatePrefixRecordAction=Record),
                                     lambda *event: events.append(event))
    assert Action.verify is action_method
    return SimpleNamespace(Action=Action, Record=Record, Group=group, Transaction=Transaction,
                           link=link, cache=cache, calls=calls, events=events)


def test_verification_groups_preserve_native_order_and_errors(native):
    a, b = (SimpleNamespace(name=name) for name in ('alpha', 'beta'))
    first, second = ValueError('first'), ValueError('second')
    files = [native.Action(str(i)) for i in range(1000)]
    files[123].error = first
    files[567].verified = True
    other = native.Action('other', second)
    records = tuple(native.Record(package) for package in (a, b))
    groups = ((native.Group('link', a, files, '/prefix'), native.Group('link', b, (other,), '/prefix')),
              (native.Group('record', None, records, '/prefix'),))
    assert native.Transaction._verify_individual_level(groups) == [first, second]
    assert native.calls == [('verify', action.name) for action in (*files[:567], *files[568:], other, *records)]
    assert len(native.events) == 8
    assert [label for kind, _, label in native.events if kind == 'begin'] == [
        'conda:verify:link:alpha', 'conda:verify:link:beta',
        'conda:verify:record:alpha', 'conda:verify:record:beta']


def test_execute_native_group_and_rollback_without_per_file_events(native):
    pkg = SimpleNamespace(name='alpha')
    actions = [native.Action(str(i)) for i in range(1000)]
    error = ValueError('link failed')
    actions[-1].error = error
    group = native.Group('link', pkg, actions, '/prefix')
    assert native.Transaction._execute_actions(group) is error
    assert native.calls == [('execute', action.name) for action in actions] + [
        ('reverse', action.name) for action in reversed(actions)]
    assert [(kind, label) for kind, _, label in native.events] == [
        ('begin', 'conda:execute:link:alpha'), ('begin', 'conda:reverse:link:alpha'),
        ('end', 'conda:reverse:link:alpha'), ('end', 'conda:execute:link:alpha')]


def test_record_group_has_one_deadline_per_package(native):
    records = tuple(native.Record(SimpleNamespace(name=name)) for name in ('alpha', 'beta'))
    group = native.Group('record', None, records, '/prefix')
    assert native.Transaction._execute_actions(group) is None
    assert native.Transaction._reverse_actions(group) == []
    assert native.calls == [('execute', 'alpha'), ('execute', 'beta'), ('reverse', 'beta'), ('reverse', 'alpha')]
    assert len(native.events) == 8
    assert [label for kind, _, label in native.events if kind == 'begin'] == [
        'conda:execute:record:alpha', 'conda:execute:record:beta',
        'conda:reverse:record:beta', 'conda:reverse:record:alpha']


def test_group_deadline_does_not_reset_on_nested_or_concurrent_events(native, monkeypatch):
    now = 0.0
    monkeypatch.setattr(watch_module.time, 'monotonic', lambda: now)
    watchdog = watch_module.OperationWatch(180, prefix=b'GPTTRACE_TEMPLATE ', description='template')

    def feed(kind, identity, label):
        watchdog.feed(f'GPTTRACE_TEMPLATE {kind} conda-{identity}-{label}\n'.encode())

    feed('begin', 1, 'execute-link-alpha')
    now = 100
    feed('begin', 2, 'execute-link-beta')
    now = 179
    feed('end', 2, 'execute-link-beta')
    assert watchdog.check() == 1
    now = 180
    with pytest.raises(TimeoutError, match='execute-link-alpha'):
        watchdog.check()


def test_package_hooks_keep_original_return_values(native):
    pkg = SimpleNamespace(name='alpha')
    assert native.Transaction._make_link_actions({}, pkg) is pkg
    assert native.cache.ProgressiveFetchExtract.make_actions_for_record(pkg) is pkg
    assert native.cache.do_extract_action(pkg, None, None) is pkg
    assert native.link.run_script('/prefix', pkg, 'post-link', activate=True)
    assert [label for kind, _, label in native.events if kind == 'begin'] == [
        'conda:_make_link_actions:alpha', 'conda:prepare-package:alpha',
        'conda:do_extract_action:alpha', 'conda:script:post-link:alpha']
