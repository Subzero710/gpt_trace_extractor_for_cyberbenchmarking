"""Historical multi-command pip recipe continuity contracts."""

import pytest
from packaging.markers import default_environment

import superbench_pool as pool


@pytest.fixture(autouse=True)
def target_markers(monkeypatch):
    env = default_environment()
    monkeypatch.setattr(pool, '_target_marker_environment', lambda _target: env)


def test_earlier_exact_pin_is_preferred_by_later_unpinned_requirement():
    command = 'python -m pip install types-pkg-resources==0.1.3 pytest; pip install -r requirements-dev.txt'
    steps = pool.pip_commands([command])[-1]
    assert len(steps) == 2
    installed = pool._historical_exact_pip_pins(steps[0]['requirements'], object())
    inherited = pool._historical_pip_preferences(
        installed, {'types-pkg_resources', 'pytest'}, set(), object())
    assert inherited == {'types-pkg-resources': 'types-pkg-resources==0.1.3'}


def test_does_not_override_later_explicit_pin():
    pinned = pool._historical_exact_pip_pins({'demo-package==1.2.3'}, object())
    assert pool._historical_pip_preferences(
        pinned, {'demo_package==4.5.6'}, [], object()) == {}


def test_does_not_override_incompatible_later_constraints():
    pinned = pool._historical_exact_pip_pins({'some-package==1.2.3'}, object())
    assert pool._historical_pip_preferences(
        pinned, {'some-package'}, {'some-package>=2'}, object()) == {}


def test_upgrade_can_release_prior_pin():
    pinned = pool._historical_exact_pip_pins({'some-package==1.2.3'}, object())
    assert pool._historical_pip_preferences(
        pinned, {'some-package'}, [], object(), upgrade=True) == {}


def test_exact_pins_ignore_inactive_markers():
    pins = pool._historical_exact_pip_pins(
        {'some-package==1.2.3; python_version < "2"'}, object())
    assert pins == {}


def test_unpinned_and_range_requirements_not_promoted_to_exact_pins():
    assert pool._historical_exact_pip_pins(
        {'demo-package>=1', 'other-package', 'third-package==1.*'}, object()) == {}


def test_conflicting_exact_pin_is_rejected():
    with pytest.raises(RuntimeError, match='conflicting exact pins'):
        pool._historical_exact_pip_pins(
            {'demo-package==1.2.3', 'demo_package==4.5.6'}, object())


def test_submodule_error_contract_remains_compatible(monkeypatch):
    monkeypatch.setattr(pool, 'git_file', lambda *_args, **_kwargs: (
        '[submodule "fixture"]\npath = vendor/fixture\nurl = http://github.com/org/repo\n'
    ))
    with pytest.raises(RuntimeError, match='unsupported Git submodule URL'):
        pool.read_submodules('/unused/mirror', 'f' * 40)
