"""Observe Conda's native package groups during offline template provisioning."""
from __future__ import annotations

import functools
import itertools
import re
import runpy
import sys
import threading
from pathlib import Path


def instrument_package_actions(link, cache, path_actions, emit):
    transaction = link.UnlinkLinkTransaction
    events = itertools.count(1)

    def observe(function, describe):
        @functools.wraps(function)
        def observed(*args, **kwargs):
            identity = next(events)
            label = 'conda:' + describe(*args, **kwargs)
            emit('begin', identity, label)
            try:
                return function(*args, **kwargs)
            finally:
                emit('end', identity, label)
        return observed

    def package_label(stage, package):
        return stage + ':' + package.name

    def group_label(stage, group):
        phase = stage + ':' + group.type
        if group.pkg_data is None:
            return phase + ':transaction'
        return package_label(phase, group.pkg_data)

    def static_method(cls, name, describe):
        descriptor = vars(cls)[name]
        if not isinstance(descriptor, staticmethod):
            raise RuntimeError('unexpected Conda static method: ' + name)
        setattr(cls, name, staticmethod(observe(descriptor.__func__, describe)))

    def module_function(module, name, describe):
        setattr(module, name, observe(getattr(module, name), describe))

    # Conda flattens every package into one verification loop. Call the
    # original verifier on each native group, retaining order and all errors.
    descriptor = vars(transaction)['_verify_individual_level']
    if not isinstance(descriptor, staticmethod):
        raise RuntimeError('unexpected Conda package verifier')
    verify = descriptor.__func__
    verify_group = observe(verify, lambda groups: group_label('verify', groups[0][0]))

    @functools.wraps(verify)
    def verify_packages(prefix_action_group):
        errors = []
        for groups in prefix_action_group:
            for group in groups:
                if group.type == 'record':
                    # The native record group contains one action per package.
                    for action in group.actions:
                        package = group._replace(pkg_data=action.package_info, actions=(action,))
                        errors.extend(verify_group(((package,),)))
                else:
                    errors.extend(verify_group(((group,),)))
        return errors

    transaction._verify_individual_level = staticmethod(verify_packages)

    # Link/unlink/entry-point/menu and rollback groups keep their original
    # action order, exception handling and rollback semantics. Record creation
    # is the one multi-package group with individual native package actions.
    for name, phase in (('_execute_actions', 'execute'), ('_reverse_actions', 'reverse')):
        descriptor = vars(transaction)[name]
        if not isinstance(descriptor, staticmethod):
            raise RuntimeError('unexpected Conda group method: ' + name)
        original = descriptor.__func__
        grouped = observe(original, lambda group, *args, phase=phase, **kwargs: group_label(phase, group))

        def dispatch(group, *args, original=original, grouped=grouped, **kwargs):
            if group.type == 'record':
                return original(group, *args, **kwargs)
            return grouped(group, *args, **kwargs)

        setattr(transaction, name, staticmethod(functools.wraps(original)(dispatch)))

    for name in ('execute', 'reverse'):
        cls = path_actions.CreatePrefixRecordAction
        original = vars(cls)[name]
        setattr(cls, name, observe(original, lambda action, name=name: package_label(name + ':record', action.package_info)))

    # Package creation and native scripts are also independently bounded.
    for name in ('_make_link_actions', '_make_entry_point_actions', '_make_compile_actions'):
        static_method(transaction, name, lambda context, package_info, *args, name=name, **kwargs: package_label(name, package_info))
    module_function(link, 'make_unlink_actions', lambda context, prefix, prefix_record: package_label('prepare-unlink', prefix_record))
    module_function(link, 'read_package_info', lambda record, cache_record: package_label('read-package-info', record))
    module_function(link, 'run_script', lambda prefix, prec, action='post-link', *args, **kwargs: package_label('script:' + action, prec))
    static_method(transaction, '_verify_prefix_level', lambda argument: 'verify-prefix')

    static_method(cache.ProgressiveFetchExtract, 'make_actions_for_record',
                  lambda record: package_label('prepare-package', record))
    for name in ('do_cache_action', 'do_extract_action'):
        module_function(cache, name, lambda prec, *args, name=name, **kwargs: package_label(name, prec))
    for name in ('do_cleanup', 'do_reverse'):
        module_function(cache, name, lambda actions, name=name: name + ':package-cache')


def main():
    arguments = sys.argv[1:]
    if not ((arguments[:1] == ['create'] and ('--offline' in arguments or '--clone' in arguments))
            or arguments[:2] == ['env', 'remove']):
        raise ValueError('unsupported supervised Conda template operation')
    from conda.core import link, package_cache_data, path_actions

    with Path('/dev/ttyS0').open('wb', buffering=0) as serial:
        writer = threading.Lock()

        def emit(event, identity, description):
            label = f'conda-{identity}-' + re.sub(r'[^a-zA-Z0-9._+-]', '-', description)
            payload = f'GPTTRACE_TEMPLATE {event} {label[:128]}\n'.encode('ascii')
            with writer:
                if serial.write(payload) != len(payload):
                    raise OSError('short Conda serial record')

        instrument_package_actions(link, package_cache_data, path_actions, emit)
        sys.argv = ['conda', *arguments]
        runpy.run_module('conda', run_name='__main__', alter_sys=True)


if __name__ == '__main__':
    main()
