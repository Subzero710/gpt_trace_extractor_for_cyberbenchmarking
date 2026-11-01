"""Download-only SWE-Gym Lite fetcher regression tests; no network/KVM/VM."""
from __future__ import annotations
import hashlib
import contextlib
import concurrent.futures
import io
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('superbench_pool_under_test', ROOT / 'scripts/superbench_pool.py')
pool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pool)


def fixture_target(full_version="3.10.14", *, platform_tag="manylinux_2_17_x86_64"):
    model=pool._target_environment_module()
    major,minor,_=full_version.split(".")
    base=model.TargetEnvironment(
        markers={
            "implementation_name":"cpython", "implementation_version":"3.13.0",
            "os_name":"posix", "platform_machine":"x86_64",
            "platform_release":"fixture-kernel", "platform_system":"Linux",
            "platform_version":"fixture-kernel-version",
            "python_full_version":"3.13.0", "python_version":"3.13",
            "platform_python_implementation":"CPython", "sys_platform":"linux",
        },
        tags=("cp313-cp313-"+platform_tag, "py3-none-any"),
        implementation="cpython", abi="cp313", architecture="x86_64",
        source="verified-target-interpreter", interpreter_sha256="f"*64,
    )
    return model.conda_target(
        full_version=full_version, base_target=base,
        python_artifact_sha256=hashlib.sha256(full_version.encode()).hexdigest(),
        source="test-locked-conda:"+major+"."+minor,
    )


class TestStaticDependencyResolution(unittest.TestCase):
    def test_moto_named_install_requires(self):
        source = '''from setuptools import setup\ninstall_requires = ["requests>=2", "boto3>=1.9"]\nsetup(install_requires=install_requires)\n'''
        requirements, issues = pool.setup_static(source)
        self.assertEqual(requirements, {'requests>=2', 'boto3>=1.9'})
        self.assertEqual(issues, [])

    def test_dask_conditional_setup_requires_keeps_both_literal_cases(self):
        # The 13 historical pinned Dask setup.py files switch on sys.argv.
        source = ("""import sys
from setuptools import setup
install_requires = ["pyyaml"]
if {"pytest", "test", "ptr"}.intersection(sys.argv):
    setup_requires = ["pytest-runner"]
else:
    setup_requires = []
setup(install_requires=install_requires, setup_requires=setup_requires)
""")
        requirements, issues = pool.setup_static(source, python_version='3.8')
        self.assertEqual(issues, [])
        self.assertEqual(requirements, {'pyyaml', 'pytest-runner'})

    def test_unknown_conditional_dynamic_requirement_is_rejected(self):
        source = ("""if unknown_condition():
    setup_requires = unknown_package_list()
else:
    setup_requires = []
setup(setup_requires=setup_requires)
""")
        requirements, issues = pool.setup_static(source)
        self.assertEqual(requirements, set())
        self.assertTrue(any('setup_requires' in issue for issue in issues))

    def test_conditional_install_requires_union_is_lossless(self):
        source = ("""if unknown_condition():
    install_requires = ["alpha>=1", "shared"]
else:
    install_requires = ["beta>=2", "shared"]
setup(install_requires=install_requires)
""")
        requirements, issues = pool.setup_static(source)
        self.assertEqual(issues, [])
        self.assertEqual(requirements, {'alpha>=1', 'beta>=2', 'shared'})

    def test_dynamic_setup_metadata_is_not_silently_ignored(self):
        requirements, issues = pool.setup_static('setup(install_requires=dynamic())')
        self.assertFalse(requirements)
        self.assertTrue(issues)

    def test_dynamic_setup_kwargs_is_not_silently_ignored(self):
        source = 'setup_args={"name": dynamic_name(), "install_requires": ["dep==1"]}\nsetup(**setup_args)\n'
        requirements, issues = pool.setup_static(source)
        self.assertFalse(requirements)
        self.assertTrue(any('**kwargs' in item for item in issues))

    def test_requirements_and_constraints_remain_separate(self):
        sources = {'nested.txt': 'urllib3>=1\n', 'limits.txt': 'urllib3<2\n'}
        reqs, git, constraints = pool.parse_requirements(
            '-r nested.txt\n-c limits.txt\nrequests\n', 'base.txt',
            lambda name, required=False: sources[name])
        self.assertEqual(reqs, {'urllib3>=1', 'requests'})
        self.assertEqual(constraints, {'urllib3<2'})
        self.assertEqual(git, set())

    def test_hydra_git_protocol_rewrite_and_pep508(self):
        command = "sed -i 's|isort@git+git://github.com/timothycrosley/isort|isort@git+https://github.com/timothycrosley/isort|g' requirements/dev.txt"
        raw = 'isort@git+git://github.com/timothycrosley/isort.git@c54b3dd#egg=isort\n'
        changed = pool.transformed_source('facebookresearch/hydra', 'requirements/dev.txt', raw, [command])
        deps, vcs, constraints = pool.parse_requirements(changed, 'requirements/dev.txt', lambda *_: '')
        self.assertEqual(deps, set())
        self.assertEqual(constraints, set())
        self.assertEqual(vcs, {'git+https://github.com/timothycrosley/isort.git@c54b3dd#egg=isort'})

    def test_pydantic_make_install_invocations_keep_order(self):
        commands = ['python -m pip install -U pip', 'pip install -r requirements/all.txt', 'pip install -e .']
        _, filenames, _, issues, _, _, steps = pool.pip_commands(commands)
        self.assertEqual(issues, [])
        self.assertEqual(len(steps), 3)
        self.assertIn('requirements/all.txt', filenames)
        self.assertEqual(steps[0]['requirements'], {'pip'})

    def test_setup_cfg_install_requires(self):
        specs, issues = pool.setup_cfg_static('[options]\ninstall_requires =\n  numpy>=1\n  pytest\n')
        self.assertEqual(specs, {'numpy>=1', 'pytest'})
        self.assertEqual(issues, [])

    def test_conda_five_python_versions_and_contract_shape(self):
        contract = json.loads((ROOT / 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/contract.json').read_bytes())
        self.assertEqual(len(contract['tasks']), 230)
        self.assertEqual(len(contract['environments']), 25)
        self.assertEqual(len({row['repo'] for row in contract['tasks'].values()}), 11)
        self.assertEqual(set(pool.PYTHONS), {'3.8','3.9','3.10','3.11','3.12'})

    def test_conda_recipe_fingerprint_changes_with_recipe_bytes(self):
        contract = json.loads((ROOT / 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/contract.json').read_bytes())
        script = contract['environments']['0bb835c6e5fbdbe6998741']['original_script']
        original = pool.conda_recipe_fingerprint(script)
        changed = list(script);changed[-1] = changed[-1] + ' '
        self.assertRegex(original, r'^[0-9a-f]{64}$')
        self.assertNotEqual(original, pool.conda_recipe_fingerprint(changed))

    def test_failed_captured_command_logs_stdout(self):
        failure = subprocess.CalledProcessError(
            1,
            ['fixture-tool'],
            output='{"success":false,"problems":["unsupported request"]}\n',
        )
        captured = io.StringIO()
        with patch.object(pool.subprocess, 'run', side_effect=failure), \
             contextlib.redirect_stderr(captured), \
             self.assertRaises(subprocess.CalledProcessError):
            pool.invoke(['fixture-tool', '--json'], capture=True)
        self.assertIn('failed command captured stdout', captured.getvalue())
        self.assertIn('unsupported request', captured.getvalue())

    def test_dvc_file_backed_tests_extra_and_target_python_append_are_static(self):
        setup = """from pathlib import Path
import sys
from setuptools import setup
install_requires=["base>=1"]
if sys.version_info[0] == 2:
    install_requires.append("networkx>=2.1,<2.3")
else:
    install_requires.append("networkx>=2.1")
tests_requirements=(Path("test_requirements.txt").read_text().strip().splitlines())
if sys.version_info >= (3, 6):
    tests_requirements.append("black==19.3b0")
setup(install_requires=install_requires, extras_require={"tests": tests_requirements})
"""
        files={'test_requirements.txt':'pytest>=6\ncollective.checkdocs\n'}
        deps, remote, issues = pool.setup_requirements_from_sources(
            setup, lambda name, required=False: files.get(name),
            extras={'tests'}, python_version='3.8')
        self.assertEqual(remote, set())
        self.assertEqual(issues, [])
        self.assertTrue({'base>=1','networkx>=2.1','pytest>=6',
                         'collective.checkdocs','black==19.3b0'} <= deps)
        self.assertNotIn('networkx>=2.1,<2.3', deps)

    def test_pep621_self_extras_expand_locally_instead_of_fetching_dvc(self):
        pyproject = """[build-system]
requires=["setuptools>=61"]
[project]
name="dvc"
dependencies=["base>=1"]
[project.optional-dependencies]
azure=["dvc-azure==2.21.1"]
testing=["pytest-test-utils"]
tests=["dvc[testing]", "pytest>=7"]
dev=["dvc[azure,tests]"]
"""
        deps, vcs, issues = pool.static_project(pyproject, extra_groups={'dev'})
        self.assertEqual(vcs, set())
        self.assertEqual(issues, [])
        self.assertTrue({'dvc-azure==2.21.1','pytest-test-utils','pytest>=7','base>=1'} <= deps)
        self.assertFalse(any(item.startswith('dvc[') for item in deps))

    def test_conda_solution_python_records_base_interpreter_phase(self):
        solution=[{'name':'openssl','version':'3.0.0'},
                  {'name':'python','version':'3.11.9','url':'https://example/python','sha256':'a'*64}]
        self.assertEqual(pool.conda_solution_python(solution),'3.11')



class TestAcquisitionFallbacks(unittest.TestCase):
    def test_source_only_package_is_resolved_from_static_metadata_without_host_execution(self):
        target=fixture_target("3.10.14")
        sha="1"*64
        source={"name":"collective.checkdocs","version":"0.2.1",
                "requested":"collective.checkdocs==0.2.1",
                "filename":"collective.checkdocs-0.2.1.tar.gz",
                "url":"https://files.pythonhosted.org/packages/collective.checkdocs-0.2.1.tar.gz",
                "sha256":sha,"requirements":[],"provides_extra":[]}
        project={"releases":{"0.2.1":[{"packagetype":"sdist",
            "filename":source["filename"],"url":source["url"],
            "digests":{"sha256":sha},"requires_python":">=3.8"}]}}
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);candidate=pool.Pool(stage);(stage/"metadata").mkdir()
            def api(url,**_kwargs):
                if url.endswith('/pypi/collective-checkdocs/json') or url.endswith('/pypi/collective.checkdocs/json'):return project
                if url.endswith('/pypi/collective-checkdocs/0.2.1/json') or url.endswith('/pypi/collective.checkdocs/0.2.1/json'):
                    return {'info':{'name':'collective.checkdocs','version':'0.2.1',
                                    'requires_dist':[],'provides_extra':[]},
                            'urls':project['releases']['0.2.1']}
                raise AssertionError('unexpected PyPI endpoint '+url)
            def acquire_source(*_args,**_kwargs):
                artifact=candidate.objects/sha[:2]/sha
                artifact.parent.mkdir(parents=True,exist_ok=True);artifact.write_bytes(b'source')
                return source
            with patch.object(pool,"_pypi_simple_project",return_value=('0.2.1',)), \
                 patch.object(pool,"_pypi_json",side_effect=api), \
                 patch.object(pool,"acquire_source_distribution",side_effect=acquire_source) as acquire, \
                 patch.object(pool.subprocess,"run",side_effect=AssertionError("host package execution is forbidden")):
                pool.pip_closure(candidate,target,{"collective.checkdocs==0.2.1"},"plan-key")
            plan=json.loads((stage/"metadata/pip-plan-plan-key.json").read_text())
        self.assertEqual(plan["plan_schema"],pool.PIP_PLAN_SCHEMA)
        self.assertEqual(plan["target"],target.as_dict())
        self.assertEqual(plan["source_archives"],[{k:source[k] for k in ("name","version","filename","url","sha256","requirements","provides_extra")}])
        acquire.assert_called_once()

    def test_invalid_legacy_metadata_is_normalized_without_synthetic_resolver_wheels(self):
        self.assertFalse(hasattr(pool,"_write_resolver_stub"))
        self.assertFalse(hasattr(pool,"_resolver_stub_constraint"))
        self.assertEqual(pool.normalize_legacy_source_requirement("PyYAML (>=5.1.*)"),"PyYAML==5.1")
        source=(ROOT/"scripts/superbench_pool.py").read_text()
        self.assertNotIn("metadata-only wheel",source)
        self.assertNotIn("swegym-static-source-resolver",source)

    def test_dynamic_source_metadata_fails_closed_in_host_fetcher(self):
        target=fixture_target("3.10.14")
        sha="2"*64
        requirement,_,_,_,_=pool._packaging_symbols()
        selected={"packagetype":"sdist","filename":"demo-1.0.tar.gz",
                  "url":"https://files.pythonhosted.org/packages/demo-1.0.tar.gz",
                  "digests":{"sha256":sha}}
        metadata={"urls":[selected],"info":{"name":"demo"}}
        with tempfile.TemporaryDirectory() as tmp:
            candidate=pool.Pool(Path(tmp));obj=candidate.objects/sha[:2]/sha
            obj.parent.mkdir(parents=True);obj.write_bytes(b"source")
            with patch.object(pool,"_select_source_release",return_value=(requirement("demo==1.0"),"1.0",selected)), \
                 patch.object(pool,"_pypi_json",return_value=metadata), \
                 patch.object(candidate,"download",return_value=sha), \
                 patch.object(pool,"_source_archive_files",return_value={"setup.py":b"setup(install_requires=dynamic())"}), \
                 patch.object(pool.subprocess,"run",side_effect=AssertionError("dynamic setup must not execute")):
                with self.assertRaisesRegex(RuntimeError,"requires isolated target evaluation"):
                    pool.acquire_source_distribution(candidate,"demo==1.0","plan",target)

    def test_historical_pypi_inclusive_wildcard_metadata_is_pinned_to_lower_bound(self):
        Requirement,_,_,_,_=pool._packaging_symbols()
        requirement=Requirement('omegaconf==2.0.6')
        sha='a'*64
        selected={'packagetype':'sdist','filename':'omegaconf-2.0.6.tar.gz',
                  'url':'https://files.pythonhosted.org/packages/omegaconf-2.0.6.tar.gz',
                  'digests':{'sha256':sha}}
        metadata={'urls':[selected],
                  'info':{'name':'omegaconf','requires_dist':['PyYAML (>=5.1.*)']}}
        with tempfile.TemporaryDirectory() as tmp:
            candidate=pool.Pool(Path(tmp))
            with patch.object(pool,'_select_source_release',return_value=(requirement,'2.0.6',selected)), \
                 patch.object(pool,'_pypi_json',return_value=metadata), \
                 patch.object(candidate,'download',return_value=sha), \
                 patch.object(pool,'_source_archive_files',return_value={}):
                target=candidate.objects/sha[:2]/sha
                target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(b'source')
                result=pool.acquire_source_distribution(candidate,'omegaconf==2.0.6','plan',fixture_target('3.8.20'))
        self.assertEqual(result['requirements'],['PyYAML==5.1'])
        Requirement(result['requirements'][0])

    def test_legacy_metadata_compatibility_is_narrow_and_exact(self):
        self.assertEqual(pool.normalize_legacy_source_requirement('PyYAML (>=5.1.*)'),
                         'PyYAML==5.1')
        self.assertEqual(pool.normalize_legacy_source_requirement(
            'demo (>=1.2.*); python_version < "3.9"'),
            'demo==1.2; python_version < "3.9"')
        for value in ('PyYAML (>5.1.*)','PyYAML (<=5.1.*)','PyYAML (~=5.1.*)',
                      'PyYAML (>=banana.*)'):
            with self.subTest(value=value), self.assertRaisesRegex(
                    RuntimeError,'invalid source dependency metadata'):
                pool.normalize_legacy_source_requirement(value)

    def test_source_range_prefers_cached_compatible_version(self):
        def release(version):
            return [{'packagetype':'sdist','filename':f'demo-{version}.tar.gz',
                     'url':f'https://files.pythonhosted.org/packages/demo-{version}.tar.gz',
                     'digests':{'sha256':hashlib.sha256(version.encode()).hexdigest()},
                     'requires_python':'>=3.8'}]
        project={'releases':{'1.4':release('1.4'),'1.5':release('1.5'),'1.9':release('1.9'),'2.0':release('2.0')}}
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);candidate=pool.Pool(stage)
            shared=stage/'wheels/shared';shared.mkdir(parents=True)
            (shared/'demo-1.9-py3-none-any.whl').write_bytes(b'cached')
            with patch.object(pool,'_pypi_json',return_value=project):
                _,selected,_=pool._select_source_release(candidate,'demo>1,<2',fixture_target('3.10.14'))
        self.assertEqual(selected,'1.9')

    def test_source_range_without_cache_selects_latest_compatible(self):
        def release(version):
            return [{'packagetype':'sdist','filename':f'demo-{version}.tar.gz',
                     'url':f'https://files.pythonhosted.org/packages/demo-{version}.tar.gz',
                     'digests':{'sha256':hashlib.sha256(version.encode()).hexdigest()},
                     'requires_python':'>=3.8'}]
        project={'releases':{'1.4':release('1.4'),'1.5':release('1.5'),'1.9':release('1.9'),'2.0':release('2.0')}}
        with tempfile.TemporaryDirectory() as tmp:
            candidate=pool.Pool(Path(tmp))
            with patch.object(pool,'_pypi_json',return_value=project):
                _,selected,_=pool._select_source_release(candidate,'demo>1.4,<2',fixture_target('3.10.14'))
        self.assertEqual(selected,'1.9')

    def test_source_greater_equal_prefers_latest_compatible_release(self):
        def release(version):
            return [{'packagetype':'sdist','filename':f'demo-{version}.tar.gz',
                     'url':f'https://files.pythonhosted.org/packages/demo-{version}.tar.gz',
                     'digests':{'sha256':hashlib.sha256(version.encode()).hexdigest()},
                     'requires_python':'>=3.8'}]
        project={'releases':{'5.1':release('5.1'),'5.2':release('5.2'),'6.0':release('6.0')}}
        with tempfile.TemporaryDirectory() as tmp:
            candidate=pool.Pool(Path(tmp))
            with patch.object(pool,'_pypi_json',return_value=project):
                _,selected,_=pool._select_source_release(candidate,'demo>=5.1',fixture_target('3.10.14'))
        self.assertEqual(selected,'6.0')

    def test_source_greater_equal_skips_yanked_and_prefers_latest_release(self):
        def release(version, *, yanked=False):
            return [{'packagetype':'sdist','filename':f'demo-{version}.tar.gz',
                     'url':f'https://files.pythonhosted.org/packages/demo-{version}.tar.gz',
                     'digests':{'sha256':hashlib.sha256(version.encode()).hexdigest()},
                     'requires_python':'>=3.8','yanked':yanked}]
        project={'releases':{'5.1':release('5.1',yanked=True),
                             '5.2':release('5.2'),'6.0':release('6.0')}}
        with tempfile.TemporaryDirectory() as tmp:
            candidate=pool.Pool(Path(tmp))
            with patch.object(pool,'_pypi_json',return_value=project):
                _,selected,_=pool._select_source_release(
                    candidate,'demo>=5.1',fixture_target('3.10.14'))
        self.assertEqual(selected,'6.0')

    def test_source_greater_equal_prefers_compatible_cached_version_over_lower_pin(self):
        def release(version):
            return [{'packagetype':'sdist','filename':f'demo-{version}.tar.gz',
                     'url':f'https://files.pythonhosted.org/packages/demo-{version}.tar.gz',
                     'digests':{'sha256':hashlib.sha256(version.encode()).hexdigest()},
                     'requires_python':'>=3.8'}]
        project={'releases':{'5.1':release('5.1'),'5.2':release('5.2'),'6.0':release('6.0')}}
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);candidate=pool.Pool(stage)
            shared=stage/'wheels/shared';shared.mkdir(parents=True)
            (shared/'demo-6.0-py3-none-any.whl').write_bytes(b'cached')
            with patch.object(pool,'_pypi_json',return_value=project):
                _,selected,_=pool._select_source_release(candidate,'demo>=5.1',fixture_target('3.10.14'))
        self.assertEqual(selected,'6.0')

    def test_source_bounded_greater_equal_is_range_and_uses_latest_without_cache(self):
        def release(version):
            return [{'packagetype':'sdist','filename':f'demo-{version}.tar.gz',
                     'url':f'https://files.pythonhosted.org/packages/demo-{version}.tar.gz',
                     'digests':{'sha256':hashlib.sha256(version.encode()).hexdigest()},
                     'requires_python':'>=3.8'}]
        project={'releases':{'5.1':release('5.1'),'5.2':release('5.2'),
                             '6.0':release('6.0'),'6.1':release('6.1')}}
        with tempfile.TemporaryDirectory() as tmp:
            candidate=pool.Pool(Path(tmp))
            with patch.object(pool,'_pypi_json',return_value=project):
                _,selected,_=pool._select_source_release(candidate,'demo>=5.1,<6.1',fixture_target('3.10.14'))
        self.assertEqual(selected,'6.0')

    def test_constraint_only_greater_equal_without_cache_prefers_latest(self):
        def release(version):
            return [{'packagetype':'sdist','filename':f'demo-{version}.tar.gz',
                     'url':f'https://files.pythonhosted.org/packages/demo-{version}.tar.gz',
                     'digests':{'sha256':hashlib.sha256(version.encode()).hexdigest()},
                     'requires_python':'>=3.8'}]
        project={'releases':{'5.1':release('5.1'),'5.2':release('5.2'),'6.0':release('6.0')}}
        with tempfile.TemporaryDirectory() as tmp:
            candidate=pool.Pool(Path(tmp))
            with patch.object(pool,'_pypi_json',return_value=project):
                _,selected,_=pool._select_source_release(
                    candidate,'demo',fixture_target('3.10.14'),constraints={'demo>=5.1'})
        self.assertEqual(selected,'6.0')

    def test_exact_source_pin_accepts_explicit_yanked_release(self):
        sha=hashlib.sha256(b'source').hexdigest()
        item={'packagetype':'sdist','filename':'demo-1.0.tar.gz',
              'url':'https://files.pythonhosted.org/packages/demo-1.0.tar.gz',
              'digests':{'sha256':sha},'requires_python':'>=3.8','yanked':True}
        release={'info':{'name':'demo','version':'1.0'},'urls':[item]}
        with tempfile.TemporaryDirectory() as tmp:
            candidate=pool.Pool(Path(tmp))
            with patch.object(pool,'_pypi_exact_release',return_value=('1.0',release)):
                _req,selected,artifact=pool._select_source_release(
                    candidate,'demo==1.0',fixture_target('3.10.14'))
        self.assertEqual(selected,'1.0');self.assertEqual(artifact,item)

    def test_exact_source_pin_uses_release_endpoint_without_project_index(self):
        sha=hashlib.sha256(b'source').hexdigest()
        item={'packagetype':'sdist','filename':'demo-1.0.tar.gz',
              'url':'https://files.pythonhosted.org/packages/demo-1.0.tar.gz',
              'digests':{'sha256':sha},'requires_python':'>=3.8'}
        calls=[]
        def api(url,**_kwargs):
            calls.append(url)
            if url.endswith('/pypi/demo/1.0/json'):
                return {'info':{'name':'demo','version':'1.0'},'urls':[item]}
            raise AssertionError('full project index must not be fetched for exact source pin: '+url)
        with tempfile.TemporaryDirectory() as tmp:
            candidate=pool.Pool(Path(tmp))
            with patch.object(pool,'_pypi_simple_project',return_value=('1.0',)), \
                 patch.object(pool,'_pypi_json',side_effect=api):
                _req,version,selected=pool._select_source_release(
                    candidate,'demo==1.0',fixture_target('3.10.14'))
        self.assertEqual(version,'1.0')
        self.assertEqual(selected,item)
        self.assertEqual(calls,['https://pypi.org/pypi/demo/1.0/json'])


    def test_apt_key_uses_downloaded_content_address(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp)
            candidate = pool.Pool(stage)
            sha = hashlib.sha256(b'key-bytes').hexdigest()
            target = candidate.objects / sha[:2] / sha
            target.parent.mkdir(parents=True)
            target.write_bytes(b'key-bytes')
            def network(url, category, identity, **kwargs):
                self.assertEqual(category, 'apt')
                self.assertEqual(identity, 'signing-key')
                return sha
            def commands(args, *, cwd=None, capture=False, env=None):
                if args[0] == 'gpg': return 'fpr:::::::::' + pool.KALI_SIGNING_FPR + ':\n'
                if 'install' in args:
                    archives = stage / 'apt/archives'
                    (archives/'testpkg_1_all.deb').write_bytes(b'fixture .deb')
                return ''
            def dpkg(args, **kwargs): return 'Package: testpkg\nVersion: 1\nArchitecture: all\n'
            with patch.object(candidate, 'download', side_effect=network), \
                 patch.object(pool, 'invoke', side_effect=commands), \
                 patch.object(pool.subprocess, 'run', return_value=subprocess.CompletedProcess(['gpg'], 0)), \
                 patch.object(pool.subprocess, 'check_output', side_effect=dpkg), \
                 patch.object(pool, '_target_debian_architecture', return_value='amd64'):
                pool.apt_closure(candidate, {'testpkg'})
            self.assertEqual(json.loads((stage / 'metadata/apt-closure.json').read_text())['requested'], ['testpkg'])


# GPT_TRACE_SWEGYM_GLOBAL_ARTIFACT_POOL_V1
class TestGlobalPipArtifactPool(unittest.TestCase):
    def make_pool(self, root):
        root=Path(root)
        for name in ('metadata','wheels','downloads'):(root/name).mkdir(parents=True,exist_ok=True)
        return pool.Pool(root)

    @staticmethod
    def wheel_bytes(name='demo',version='1.0',requires=()):
        import zipfile
        buffer=io.BytesIO();dist=name.replace('-','_')+'-'+version+'.dist-info'
        metadata=['Metadata-Version: 2.1','Name: '+name,'Version: '+version]
        metadata.extend('Requires-Dist: '+row for row in requires);metadata.extend(['',''])
        with zipfile.ZipFile(buffer,'w') as archive:
            archive.writestr(dist+'/METADATA','\n'.join(metadata))
            archive.writestr(dist+'/WHEEL','Wheel-Version: 1.0\nTag: py3-none-any\n')
            archive.writestr(dist+'/RECORD','')
        return buffer.getvalue()

    def project(self,payload,*,name='demo',version='1.0'):
        sha=hashlib.sha256(payload).hexdigest()
        return {'releases':{version:[{'packagetype':'bdist_wheel',
            'filename':f'{name}-{version}-py3-none-any.whl',
            'url':f'https://files.pythonhosted.org/packages/{name}-{version}-py3-none-any.whl',
            'digests':{'sha256':sha},'requires_python':'>=3.8'}]}},sha

    def test_group_identity_is_order_independent_but_target_specific(self):
        target=fixture_target('3.10.14')
        one=pool.pip_group_key(target,{'pillow','pandas'},{'numpy<2'},False)
        two=pool.pip_group_key(target,{'pandas','pillow'},{'numpy<2'},False)
        other=pool.pip_group_key(fixture_target('3.10.15'),{'pandas','pillow'},{'numpy<2'},False)
        self.assertEqual(one,two);self.assertNotEqual(one,other)

    def test_static_registry_plan_uses_target_tags_without_spawning_pip(self):
        target=fixture_target('3.10.14');payload=self.wheel_bytes();project,sha=self.project(payload)
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);candidate=self.make_pool(stage);calls=[]
            def fetch(url,path,*,sha=None,sri=None,limit=2**37,integrity_digests=None):
                calls.append(url);Path(path).write_bytes(payload);return hashlib.sha256(payload).hexdigest()
            def api(url,**_kwargs):
                if url.endswith('/pypi/demo/json'):return project
                if url.endswith('/pypi/demo/1.0/json'):
                    return {'info':{'name':'demo','version':'1.0','requires_dist':[],
                                    'provides_extra':[]},'urls':project['releases']['1.0']}
                raise AssertionError('unexpected PyPI endpoint '+url)
            with patch.object(pool,'_pypi_simple_project',return_value=('1.0',)), \
                 patch.object(pool,'_pypi_json',side_effect=api), \
                 patch.object(pool,'fetch',side_effect=fetch), \
                 patch.object(pool.subprocess,'run',side_effect=AssertionError('pip/build execution is forbidden')):
                pool.pip_closure(candidate,target,{'demo==1.0'},'group')
            plan=json.loads((stage/'metadata/pip-plan-group.json').read_text())
            self.assertEqual(plan['plan_schema'],pool.PIP_PLAN_SCHEMA)
            self.assertEqual(plan['target'],target.as_dict())
            self.assertEqual(plan['files'],[{'filename':'demo-1.0-py3-none-any.whl','sha256':sha}])
            self.assertEqual(calls,['https://files.pythonhosted.org/packages/demo-1.0-py3-none-any.whl'])

    def test_registry_exact_pin_uses_release_endpoint_without_project_index(self):
        target=fixture_target('3.10.14')
        sha=hashlib.sha256(b'demo').hexdigest()
        item={'packagetype':'bdist_wheel','filename':'demo-1.0-py3-none-any.whl',
              'url':'https://files.pythonhosted.org/packages/demo-1.0-py3-none-any.whl',
              'digests':{'sha256':sha},'requires_python':'>=3.8'}
        calls=[]
        def api(url,**_kwargs):
            calls.append(url)
            if url.endswith('/pypi/demo/1.0/json'):
                return {'info':{'name':'demo','version':'1.0','requires_dist':[],
                                'provides_extra':[]},'urls':[item]}
            raise AssertionError('full project index must not be fetched for exact registry pin: '+url)
        Requirement,_,_,_,_=pool._packaging_symbols()
        with tempfile.TemporaryDirectory() as tmp:
            candidate=self.make_pool(Path(tmp))
            with patch.object(pool,'_pypi_simple_project',return_value=('1.0',)), \
                 patch.object(pool,'_pypi_json',side_effect=api):
                rows=pool._candidate_versions(candidate,'demo',[Requirement('demo==1.0')],[],target)
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['version'],'1.0')
        self.assertEqual(calls,['https://pypi.org/pypi/demo/1.0/json'])

    def test_exact_pin_maps_pep440_equivalent_text_to_stored_release_identity(self):
        with patch.object(pool,'_pypi_simple_project',return_value=('23.3','24.0','24.1')):
            self.assertEqual(pool._canonical_pypi_release('pip','24.0.0'),'24.0')

    def test_exact_release_uses_direct_endpoint_before_simple_fallback(self):
        calls=[]
        payload={'info':{'name':'demo','version':'1.0'},'urls':[]}
        def api(url,**_kwargs):
            calls.append(url);return payload
        with patch.object(pool,'_pypi_json',side_effect=api),              patch.object(pool,'_pypi_simple_project',side_effect=AssertionError('simple index must stay cold')):
            stored,result=pool._pypi_exact_release('demo','1.0')
        self.assertEqual(stored,'1.0');self.assertIs(result,payload)
        self.assertEqual(calls,['https://pypi.org/pypi/demo/1.0/json'])

    def test_exact_release_uses_simple_index_only_after_alias_404(self):
        calls=[]
        failure=__import__('urllib').error.HTTPError(
            'https://pypi.org/pypi/pip/24.0.0/json',404,'missing',{},None)
        payload={'info':{'name':'pip','version':'24.0'},'urls':[]}
        def api(url,**_kwargs):
            calls.append(url)
            if url.endswith('/24.0.0/json'):raise failure
            if url.endswith('/24.0/json'):return payload
            raise AssertionError(url)
        with patch.object(pool,'_pypi_json',side_effect=api),              patch.object(pool,'_pypi_simple_project',return_value=('23.3','24.0','24.1')) as simple:
            stored,result=pool._pypi_exact_release('pip','24.0.0')
        self.assertEqual(stored,'24.0');self.assertIs(result,payload);simple.assert_called_once_with('pip')
        self.assertEqual(calls,['https://pypi.org/pypi/pip/24.0.0/json',
                                'https://pypi.org/pypi/pip/24.0/json'])

    def test_exact_registry_pin_accepts_explicit_yanked_release(self):
        target=fixture_target('3.10.14');payload=self.wheel_bytes('demo','1.0')
        sha=hashlib.sha256(payload).hexdigest()
        item={'packagetype':'bdist_wheel','filename':'demo-1.0-py3-none-any.whl',
              'url':'https://files.pythonhosted.org/packages/demo-1.0-py3-none-any.whl',
              'digests':{'sha256':sha},'requires_python':'>=3.8','yanked':True}
        release={'info':{'name':'demo','version':'1.0','requires_dist':[],
                         'provides_extra':[]},'urls':[item]}
        Requirement,_,_,_,_=pool._packaging_symbols()
        with tempfile.TemporaryDirectory() as tmp:
            candidate=self.make_pool(Path(tmp))
            with patch.object(pool,'_pypi_exact_release',return_value=('1.0',release)):
                rows=pool._candidate_versions(candidate,'demo',[Requirement('demo==1.0')],[],target)
        self.assertEqual([(row['name'],row['version']) for row in rows],[('demo','1.0')])

    def test_exact_pin_prefers_candidate_specific_pep658_metadata(self):
        target=fixture_target('3.10.14')
        core=(b'Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n'
              b'Requires-Dist: dep==2\n\n')
        sha=hashlib.sha256(b'demo').hexdigest()
        candidate={'kind':'wheel','name':'demo','version':'1.0',
                   'filename':'demo-1.0-py3-none-any.whl',
                   'item':{'url':'https://files.pythonhosted.org/packages/demo-1.0-py3-none-any.whl',
                           'digests':{'sha256':sha},
                           'core-metadata':{'sha256':hashlib.sha256(core).hexdigest()}},
                   '_release_info':{'requires_dist':['dep==1'],'provides_extra':[]}}
        with tempfile.TemporaryDirectory() as tmp:
            candidate_pool=self.make_pool(Path(tmp))
            with patch.object(pool,'_read_https',return_value=core) as read:
                record=pool._candidate_release_metadata(
                    candidate_pool,candidate,'exact',target,{}, {})
        self.assertEqual(record['requirements'],['dep==2'])
        read.assert_called_once()



    def test_yanked_only_historical_dependency_is_resolved_and_audited(self):
        # An all-yanked project with no explicit pin is still reproducible;
        # package names, artifact digests and versions are fixture-derived.
        target=fixture_target('3.10.14')
        payloads={v:self.wheel_bytes('historic-stubs',v) for v in ('1.0','1.1')}
        releases={};downloads={}
        for version,body in payloads.items():
            sha=hashlib.sha256(body).hexdigest()
            url=f'https://files.pythonhosted.org/packages/historic_stubs-{version}-py3-none-any.whl'
            entry={'packagetype':'bdist_wheel',
                   'filename':f'historic_stubs-{version}-py3-none-any.whl',
                   'url':url,'digests':{'sha256':sha},
                   'requires_python':'>=3.8','yanked':True,
                   'yanked_reason':'upstream withdrew this historical stub'}
            releases[version]=[entry];downloads[url]=body
        def api(url,**_kwargs):
            if url.endswith('/pypi/historic-stubs/json'):
                return {'releases':releases}
            version=url.split('/pypi/historic-stubs/',1)[1].removesuffix('/json')
            return {'info':{'name':'historic-stubs','version':version,
                            'requires_dist':[],'provides_extra':[]},
                    'urls':releases[version]}
        def fetch(url,path,*,sha=None,**kwargs):
            body=downloads[url];self.assertEqual(hashlib.sha256(body).hexdigest(),sha)
            Path(path).write_bytes(body);return hashlib.sha256(body).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);candidate=self.make_pool(root);output=io.StringIO()
            with patch.object(pool,'_pypi_json',side_effect=api), \
                 patch.object(pool,'fetch',side_effect=fetch), \
                 contextlib.redirect_stdout(output):
                pool.pip_closure(candidate,target,{'historic-stubs>=1'},'withdrawn')
            plan=json.loads((root/'metadata/pip-plan-withdrawn.json').read_text())
            self.assertEqual(plan['resolver_policy']['name'],pool.PIP_RESOLVER_POLICY)
            self.assertEqual(plan['packages'][0]['version'],max(payloads,key=pool._packaging_symbols()[2]))
            self.assertIs(plan['packages'][0]['yanked'],True)
            self.assertEqual(plan['packages'][0]['yanked_reason'],
                             'upstream withdrew this historical stub')
            self.assertIn('WARNING',output.getvalue())

    def test_active_release_wins_over_newer_yanked_version(self):
        target=fixture_target('3.10.14')
        project={};Requirement,_,_,_,_=pool._packaging_symbols()
        for version,is_yanked in [('1.0',False),('2.0',True)]:
            project[version]=[{'packagetype':'bdist_wheel',
                'filename':f'example-{version}-py3-none-any.whl',
                'url':f'https://files.pythonhosted.org/packages/example-{version}-py3-none-any.whl',
                'digests':{'sha256':hashlib.sha256(version.encode()).hexdigest()},
                'requires_python':'>=3.8','yanked':is_yanked}]
        with tempfile.TemporaryDirectory() as tmp:
            candidate=self.make_pool(Path(tmp))
            with patch.object(pool,'_pypi_json',return_value={'releases':project}):
                result=pool._candidate_versions(candidate,'example',
                    [Requirement('example>=1')],[],target)
            self.assertEqual([r['version'] for r in result],['1.0'])

    def test_yanked_candidate_requires_compatible_version_and_target(self):
        target=fixture_target('3.10.14')
        Requirement,_,_,_,_=pool._packaging_symbols()
        row={'packagetype':'bdist_wheel','filename':'example-1.0-py3-none-any.whl',
             'url':'https://files.pythonhosted.org/packages/example-1.0-py3-none-any.whl',
             'digests':{'sha256':hashlib.sha256(b'candidate').hexdigest()},
             'requires_python':'>=3.8','yanked':True}
        with tempfile.TemporaryDirectory() as tmp:
            candidate=self.make_pool(Path(tmp))
            with patch.object(pool,'_pypi_json',return_value={'releases':{'1.0':[row]}}):
                result=pool._candidate_versions(candidate,'example',
                    [Requirement('example>=2')],[],target)
            self.assertEqual(result,[])
            incompatible={**row,'requires_python':'>=999'}
            with patch.object(pool,'_pypi_json',return_value={'releases':{'1.0':[incompatible]}}):
                result=pool._candidate_versions(candidate,'example',
                    [Requirement('example>=1')],[],target)
            self.assertEqual(result,[])

    def test_new_resolver_policy_salvages_cas_without_reusing_stale_pip_decisions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);old=root/'old';fresh=root/'fresh'
            for stage in (old,fresh):
                (stage/'objects/sha256').mkdir(parents=True)
                (stage/'metadata').mkdir()
                (stage/'STAGING').write_text('retained stage')
            archive=b'completed Conda content from previous download'
            sha=hashlib.sha256(archive).hexdigest()
            file=old/'objects/sha256'/sha[:2]/sha
            file.parent.mkdir(parents=True);file.write_bytes(archive)
            previous_plan={'artifact_model':pool.PIP_ARTIFACT_MODEL,
                'plan_schema':pool.PIP_PLAN_SCHEMA-1,
                'packages':[{'kind':'wheel','name':'fixture','version':'1.0',
                             'filename':'fixture-1.0-py3-none-any.whl','sha256':sha}]}
            (old/'metadata/pip-plan-stale.json').write_text(json.dumps(previous_plan))
            recovered=pool.salvage_verified_stage(old,fresh,conda_artifacts={sha:{}})
            materialized=fresh/'objects/sha256'/sha[:2]/sha
            self.assertIn(sha,recovered)
            self.assertTrue(materialized.samefile(file))
            self.assertEqual(materialized.read_bytes(),archive)
            self.assertFalse((fresh/'metadata/pip-plan-stale.json').exists())
            self.assertTrue((old/'metadata/pip-plan-stale.json').exists())

    def test_yanked_range_can_resolve_only_when_active_version_violates_constraint(self):
        target=fixture_target('3.10.14');Requirement,_,_,_,_=pool._packaging_symbols()
        def entry(version,withdrawn):
            return {'packagetype':'bdist_wheel',
                'filename':f'example-{version}-py3-none-any.whl',
                'url':f'https://files.pythonhosted.org/packages/example-{version}-py3-none-any.whl',
                'digests':{'sha256':hashlib.sha256(version.encode()).hexdigest()},
                'requires_python':'>=3.8','yanked':withdrawn}
        projects={'releases':{'1.0':[entry('1.0',True)],'2.0':[entry('2.0',False)]}}
        with tempfile.TemporaryDirectory() as tmp:
            candidate=self.make_pool(Path(tmp))
            with patch.object(pool,'_pypi_json',return_value=projects):
                chosen=pool._candidate_versions(candidate,'example',
                    [Requirement('example>=1')],[Requirement('example<2')],target)
            self.assertEqual([c['version'] for c in chosen],['1.0'])
            self.assertIs(chosen[0]['item']['yanked'],True)

    def test_registry_lower_bound_prefers_latest_compatible_release(self):
        target=fixture_target('3.10.14')
        payloads={
            ('root','1.0'):self.wheel_bytes('root','1.0',requires=('dep<2',)),
            ('root','2.0'):self.wheel_bytes('root','2.0',requires=('dep>=2',)),
            ('dep','1.0'):self.wheel_bytes('dep','1.0'),
            ('dep','2.0'):self.wheel_bytes('dep','2.0'),
        }
        projects={};downloads={}
        for (name,version),payload in payloads.items():
            sha=hashlib.sha256(payload).hexdigest()
            url=f'https://files.pythonhosted.org/packages/{name}-{version}-py3-none-any.whl'
            row={'packagetype':'bdist_wheel','filename':f'{name}-{version}-py3-none-any.whl',
                 'url':url,'digests':{'sha256':sha},'requires_python':'>=3.8'}
            projects.setdefault(name,{'releases':{}})['releases'][version]=[row]
            downloads[url]=payload
        dependencies={('root','1.0'):['dep<2'],('root','2.0'):['dep>=2'],
                      ('dep','1.0'):[],('dep','2.0'):[]}
        def metadata(url,**_kwargs):
            tail=url.split('/pypi/',1)[1].removesuffix('/json').strip('/').split('/')
            name=tail[0]
            if len(tail)==1:return projects[name]
            version=tail[1]
            return {'info':{'name':name,'version':version,
                            'requires_dist':dependencies[(name,version)],'provides_extra':[]},
                    'urls':projects[name]['releases'][version]}
        calls=[]
        def fetch(url,path,*,sha=None,sri=None,limit=2**37,integrity_digests=None):
            calls.append(url);payload=downloads[url];Path(path).write_bytes(payload)
            actual=hashlib.sha256(payload).hexdigest();self.assertEqual(actual,sha);return actual
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);candidate=self.make_pool(stage)
            with patch.object(pool,'_pypi_json',side_effect=metadata),patch.object(pool,'fetch',side_effect=fetch):
                pool.pip_closure(candidate,target,{'root>=1.0','dep>=2.0'},'lower-bound')
            plan=json.loads((stage/'metadata/pip-plan-lower-bound.json').read_text())
        selected={row['name']:row['version'] for row in plan['packages']}
        self.assertEqual(selected,{'dep':'2.0','root':'2.0'})
        self.assertEqual(set(downloads)-set(calls),{
            'https://files.pythonhosted.org/packages/root-1.0-py3-none-any.whl',
            'https://files.pythonhosted.org/packages/dep-1.0-py3-none-any.whl'})
        self.assertEqual(len(calls),2)
        self.assertEqual(plan['plan_schema'],pool.PIP_PLAN_SCHEMA)
        self.assertEqual(plan['resolver_policy']['name'],pool.PIP_RESOLVER_POLICY)


    def test_registry_lower_bound_skips_yanked_exact_release(self):
        target=fixture_target('3.10.14')
        def row(version, *, yanked=False):
            payload=self.wheel_bytes('demo',version)
            sha=hashlib.sha256(payload).hexdigest()
            return payload,{'packagetype':'bdist_wheel',
                'filename':f'demo-{version}-py3-none-any.whl',
                'url':f'https://files.pythonhosted.org/packages/demo-{version}-py3-none-any.whl',
                'digests':{'sha256':sha},'requires_python':'>=3.8','yanked':yanked}
        payload_200,r200=row('2.0.0',yanked=True)
        payload_201,r201=row('2.0.1')
        payload_202,r202=row('2.0.2')
        project={'releases':{'2.0.0':[r200],'2.0.1':[r201],'2.0.2':[r202]}}
        payloads={r201['url']:payload_201,r202['url']:payload_202}
        def api(url,**_kwargs):
            if url.endswith('/pypi/demo/json'):return project
            version=url.split('/pypi/demo/',1)[1].removesuffix('/json')
            selected={'2.0.1':r201,'2.0.2':r202}[version]
            return {'info':{'name':'demo','version':version,'requires_dist':[],
                            'provides_extra':[]},'urls':[selected]}
        calls=[]
        def fetch(url,path,*,sha=None,sri=None,limit=2**37,integrity_digests=None):
            calls.append(url);payload=payloads[url];Path(path).write_bytes(payload)
            actual=hashlib.sha256(payload).hexdigest();self.assertEqual(actual,sha);return actual
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);candidate=self.make_pool(stage)
            with patch.object(pool,'_pypi_json',side_effect=api),patch.object(pool,'fetch',side_effect=fetch):
                pool.pip_closure(candidate,target,{'demo>=2'},'missing-lower')
            plan=json.loads((stage/'metadata/pip-plan-missing-lower.json').read_text())
        self.assertEqual([(row['name'],row['version']) for row in plan['packages']],[('demo','2.0.2')])
        self.assertEqual(calls,[r202['url']])

    def test_registry_broad_lower_bound_prefers_newest_without_version_ladder(self):
        target=fixture_target('3.10.14')
        _,_,Version,_,_=pool._packaging_symbols()
        def candidate(name,version):
            return {'kind':'wheel','name':name,'version':str(version),
                    'filename':f'{name}-{version}-py3-none-any.whl',
                    'item':{'url':f'https://files.pythonhosted.org/{name}-{version}.whl',
                            'digests':{'sha256':hashlib.sha256(f'{name}-{version}'.encode()).hexdigest()}}}
        aws=tuple((Version(str(version)),candidate('awscli',version)) for version in range(1,129))
        bot=((Version('128'),candidate('botocore',128)),)
        def releases(name,_target,_cache=None):
            if name=='awscli':return aws
            raise AssertionError('unexpected project '+name)
        def exact(name,version,_target,_cache=None):
            if name=='botocore' and version=='128':return bot
            raise AssertionError('unexpected exact release '+name+'=='+str(version))
        def metadata(_pool,item,_key,_target,_probe_cache,_artifact_cache,**_kwargs):
            requirements=['botocore=='+item['version']] if item['name']=='awscli' else []
            return {**item,'sha256':item['item']['digests']['sha256'],'url':item['item']['url'],
                    'requirements':requirements,'provides_extra':[]}
        with tempfile.TemporaryDirectory() as tmp:
            candidate_pool=self.make_pool(Path(tmp));output=io.StringIO()
            with patch.object(pool,'_registry_release_candidates',side_effect=releases), \
                 patch.object(pool,'_registry_exact_release_candidate',side_effect=exact), \
                 patch.object(pool,'_candidate_release_metadata',side_effect=metadata), \
                 contextlib.redirect_stdout(output):
                solved=pool._resolve_registry_plan(
                    candidate_pool,target,{'awscli>=1','botocore==128'},(),'wide',materialize=False)
        self.assertEqual({row['name']:row['version'] for row in solved},{'awscli':'128','botocore':'128'})
        self.assertEqual(output.getvalue().count('decision '),1)

    def test_resolver_decision_logging_is_logarithmically_bounded(self):
        target=fixture_target('3.10.14');domain_size=64
        def candidate(version):
            return {'kind':'wheel','name':'conflict','version':str(version),
                    'filename':f'conflict-{version}-py3-none-any.whl','item':{}}
        def versions(_pool,name,_requirements,_constraints,_target,release_cache=None,preferred_versions=None):
            if name=='conflict':return [candidate(version) for version in range(domain_size,0,-1)]
            if name=='missing':return []
            raise AssertionError('unexpected package '+name)
        def metadata(_pool,item,_key,_target,_probe_cache,_artifact_cache,**_kwargs):
            return {**item,'sha256':'a'*64,'url':'https://files.pythonhosted.org/fixture.whl',
                    'requirements':['missing==1'],'provides_extra':[]}
        with tempfile.TemporaryDirectory() as tmp:
            candidate_pool=self.make_pool(Path(tmp));output=io.StringIO()
            with patch.object(pool,'_candidate_versions',side_effect=versions), \
                 patch.object(pool,'_candidate_release_metadata',side_effect=metadata), \
                 contextlib.redirect_stdout(output), \
                 self.assertRaisesRegex(RuntimeError,'unsatisfiable'):
                pool._resolve_registry_plan(candidate_pool,target,{'conflict>=1'},(),'bounded-log',materialize=False)
        self.assertEqual(output.getvalue().count('decision '),domain_size.bit_length())

    def test_conflict_directed_backjump_skips_irrelevant_version_combinations(self):
        target=fixture_target('3.10.14');noise=[f'noise-{index}' for index in range(8)]
        requirements={name+'>=1' for name in noise}|{'conflict>=1'}
        calls=[]
        def candidate(name,version):
            return {'kind':'wheel','name':name,'version':str(version),
                    'filename':f'{name}-{version}-py3-none-any.whl','item':{}}
        def versions(_pool,name,_requirements,_constraints,_target,release_cache=None,preferred_versions=None):
            if name=='conflict':return [candidate(name,index) for index in range(1,4)]
            if name=='missing':return []
            if name in noise:return [candidate(name,1),candidate(name,2)]
            raise AssertionError('unexpected package '+name)
        def metadata(_pool,item,_key,_target,_probe_cache,_artifact_cache,**_kwargs):
            calls.append((item['name'],item['version']))
            dependencies=['missing==1'] if item['name']=='conflict' else []
            return {**item,'sha256':'a'*64,'url':'https://files.pythonhosted.org/fixture.whl',
                    'requirements':dependencies,'provides_extra':[]}
        with tempfile.TemporaryDirectory() as tmp:
            candidate_pool=self.make_pool(Path(tmp))
            with patch.object(pool,'_candidate_versions',side_effect=versions),                  patch.object(pool,'_candidate_release_metadata',side_effect=metadata),                  self.assertRaisesRegex(RuntimeError,'unsatisfiable'):
                pool._resolve_registry_plan(candidate_pool,target,requirements,(),'backjump')
        self.assertEqual(len(calls),len(noise)+3)
        self.assertEqual(sum(name=='conflict' for name,_version in calls),3)
        self.assertTrue(all(sum(name==noise_name for name,_version in calls)==1 for noise_name in noise))

    def test_shared_resolver_cache_reuses_parsed_metadata_across_closures(self):
        target=fixture_target('3.10.14')
        payloads={
            'root-a':self.wheel_bytes('root-a','1.0',requires=('shared==1.0',)),
            'root-b':self.wheel_bytes('root-b','1.0',requires=('shared==1.0',)),
            'shared':self.wheel_bytes('shared','1.0'),
        }
        projects={};downloads={}
        for name,payload in payloads.items():
            sha=hashlib.sha256(payload).hexdigest();filename=f"{name.replace('-', '_')}-1.0-py3-none-any.whl"
            url=f'https://files.pythonhosted.org/packages/{filename}'
            projects[name]={'releases':{'1.0':[{'packagetype':'bdist_wheel',
                'filename':filename,'url':url,
                'digests':{'sha256':sha},'requires_python':'>=3.8'}]}}
            downloads[url]=payload
        project_calls=[];release_calls=[];metadata_reads=[];real_metadata=pool._wheel_core_metadata
        def project(url,**_kwargs):
            tail=url.split('/pypi/',1)[1].removesuffix('/json').strip('/').split('/')
            name=tail[0]
            if len(tail)==1:
                project_calls.append(name);return projects[name]
            version=tail[1];release_calls.append((name,version))
            requirements={'root-a':['shared==1.0'],'root-b':['shared==1.0'],'shared':[]}[name]
            return {'info':{'name':name,'version':version,'requires_dist':requirements,
                            'provides_extra':[]},'urls':projects[name]['releases'][version]}
        def fetch(url,path,*,sha=None,sri=None,limit=2**37,integrity_digests=None):
            payload=downloads[url];Path(path).write_bytes(payload)
            actual=hashlib.sha256(payload).hexdigest();self.assertEqual(actual,sha);return actual
        def read_metadata(path):
            metadata_reads.append(Path(path).name);return real_metadata(path)
        with tempfile.TemporaryDirectory() as tmp:
            candidate_pool=self.make_pool(Path(tmp));cache={'release_metadata':{},'artifact_metadata':{},'releases':{}}
            with patch.object(pool,'_pypi_simple_project',return_value=('1.0',)),                  patch.object(pool,'_pypi_json',side_effect=project),                  patch.object(pool,'fetch',side_effect=fetch),                  patch.object(pool,'_wheel_core_metadata',side_effect=read_metadata):
                pool.pip_closure(candidate_pool,target,{'root-a==1.0'},'first',resolver_cache=cache)
                pool.pip_closure(candidate_pool,target,{'root-b==1.0'},'second',resolver_cache=cache)
        self.assertEqual(project_calls.count('shared'),0)
        self.assertEqual(release_calls.count(('shared','1.0')),1)
        self.assertEqual(len(metadata_reads),3)

    def test_pep658_core_metadata_avoids_release_json_and_rejected_artifact_downloads(self):
        target=fixture_target('3.10.14')
        root1=self.wheel_bytes('root','1.0',requires=('dep<2',))
        root2=self.wheel_bytes('root','2.0',requires=('dep>=2',))
        dep2=self.wheel_bytes('dep','2.0')
        payloads={('root','1.0'):root1,('root','2.0'):root2,('dep','2.0'):dep2}
        metadata={
            ('root','1.0'):b'Metadata-Version: 2.1\nName: root\nVersion: 1.0\nRequires-Dist: dep<2\n\n',
            ('root','2.0'):b'Metadata-Version: 2.1\nName: root\nVersion: 2.0\nRequires-Dist: dep>=2\n\n',
            ('dep','2.0'):b'Metadata-Version: 2.1\nName: dep\nVersion: 2.0\n\n',
        }
        projects={};downloads={};metadata_urls={}
        for (name,version),payload in payloads.items():
            sha=hashlib.sha256(payload).hexdigest();meta=metadata[(name,version)]
            filename=f'{name}-{version}-py3-none-any.whl'
            url=f'https://files.pythonhosted.org/packages/{filename}'
            row={'packagetype':'bdist_wheel','filename':filename,'url':url,
                 'digests':{'sha256':sha},'requires_python':'>=3.8',
                 'core-metadata':{'sha256':hashlib.sha256(meta).hexdigest()}}
            projects.setdefault(name,{'releases':{}})['releases'][version]=[row]
            downloads[url]=payload;metadata_urls[url+'.metadata']=meta
        calls=[];metadata_calls=[]
        def api(url,**_kwargs):
            tail=url.split('/pypi/',1)[1].removesuffix('/json').strip('/').split('/')
            if len(tail)!=1:raise AssertionError('release JSON should not be needed with PEP 658')
            return projects[tail[0]]
        def read(url,**_kwargs):
            metadata_calls.append(url);return metadata_urls[url]
        def fetch(url,path,*,sha=None,sri=None,limit=2**37,integrity_digests=None):
            calls.append(url);payload=downloads[url];Path(path).write_bytes(payload)
            actual=hashlib.sha256(payload).hexdigest();self.assertEqual(actual,sha);return actual
        with tempfile.TemporaryDirectory() as tmp:
            candidate=self.make_pool(Path(tmp))
            with patch.object(pool,'_pypi_json',side_effect=api), \
                 patch.object(pool,'_read_https',side_effect=read), \
                 patch.object(pool,'fetch',side_effect=fetch):
                pool.pip_closure(candidate,target,{'root>=1.0','dep>=2.0'},'pep658')
        self.assertIn('https://files.pythonhosted.org/packages/root-2.0-py3-none-any.whl.metadata',metadata_calls)
        self.assertNotIn('https://files.pythonhosted.org/packages/root-1.0-py3-none-any.whl.metadata',metadata_calls)
        self.assertNotIn('https://files.pythonhosted.org/packages/root-1.0-py3-none-any.whl',calls)
        self.assertEqual(set(calls),{
            'https://files.pythonhosted.org/packages/root-2.0-py3-none-any.whl',
            'https://files.pythonhosted.org/packages/dep-2.0-py3-none-any.whl'})

    def test_release_metadata_is_verified_against_winning_artifact(self):
        target=fixture_target('3.10.14')
        payload=self.wheel_bytes('demo','1.0',requires=('dep==1.0',));project,sha=self.project(payload)
        def api(url,**_kwargs):
            if url.endswith('/pypi/demo/json'):return project
            if url.endswith('/pypi/demo/1.0/json'):
                return {'info':{'name':'demo','version':'1.0','requires_dist':[],
                                'provides_extra':[]},'urls':project['releases']['1.0']}
            raise AssertionError('unexpected PyPI endpoint '+url)
        def fetch(url,path,*,sha=None,sri=None,limit=2**37,integrity_digests=None):
            Path(path).write_bytes(payload);return hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            candidate=self.make_pool(Path(tmp))
            with patch.object(pool,'_pypi_simple_project',return_value=('1.0',)), \
                 patch.object(pool,'_pypi_json',side_effect=api),patch.object(pool,'fetch',side_effect=fetch), \
                 self.assertRaisesRegex(RuntimeError,'release metadata differs from selected artifact'):
                pool.pip_closure(candidate,target,{'demo==1.0'},'metadata-mismatch')

    def test_different_logical_plans_share_one_physical_cas_object(self):
        payload=self.wheel_bytes();project,sha=self.project(payload)
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);candidate=self.make_pool(stage);calls=[]
            def fetch(url,path,*,sha=None,sri=None,limit=2**37,integrity_digests=None):
                calls.append(url);Path(path).write_bytes(payload);return hashlib.sha256(payload).hexdigest()
            def api(url,**_kwargs):
                if url.endswith('/pypi/demo/json'):return project
                if url.endswith('/pypi/demo/1.0/json'):
                    return {'info':{'name':'demo','version':'1.0','requires_dist':[],
                                    'provides_extra':[]},'urls':project['releases']['1.0']}
                raise AssertionError('unexpected PyPI endpoint '+url)
            with patch.object(pool,'_pypi_simple_project',return_value=('1.0',)), \
                 patch.object(pool,'_pypi_json',side_effect=api),patch.object(pool,'fetch',side_effect=fetch):
                pool.pip_closure(candidate,fixture_target('3.8.20'),{'demo==1.0'},'first')
                pool.pip_closure(candidate,fixture_target('3.10.14'),{'demo==1.0'},'second')
            self.assertEqual(set(candidate.links),{sha})
            self.assertEqual(set(candidate.provenance['python']),{'first','second'})
            self.assertEqual(len(calls),1)
            self.assertFalse((stage/'wheels/shared').exists())

    def test_verified_completed_plan_reuses_cas_without_resolver_or_network(self):
        target_env=fixture_target('3.10.14')
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);candidate=self.make_pool(stage);payload=self.wheel_bytes();sha=hashlib.sha256(payload).hexdigest()
            artifact=candidate.objects/sha[:2]/sha;artifact.parent.mkdir(parents=True);artifact.write_bytes(payload)
            candidate.verified_objects.add(sha);key=pool.pip_group_key(target_env,{'demo==1.0'})
            package={'kind':'wheel','name':'demo','version':'1.0','filename':'demo-1.0-py3-none-any.whl',
                     'sha256':sha,'url':'https://files.pythonhosted.org/packages/demo-1.0-py3-none-any.whl',
                     'requirements':[],'provides_extra':[]}
            plan={'artifact_model':pool.PIP_ARTIFACT_MODEL,'plan_schema':pool.PIP_PLAN_SCHEMA,
                  'target':target_env.as_dict(),'python':target_env.python_full_version,
                  'requested':['demo==1.0'],'constraints':[],'no_deps':False,
                  'packages':[package],'files':[{'filename':package['filename'],'sha256':sha}],
                  'source_archives':[]}
            (stage/'metadata'/('pip-plan-'+key+'.json')).write_text(json.dumps(plan))
            with patch.object(pool,'_resolve_registry_plan',side_effect=AssertionError('resolver must not run')):
                self.assertTrue(pool.reuse_pip_plan(candidate,target_env,{'demo==1.0'},key))
            self.assertEqual(set(candidate.links),{sha})

    def test_resume_reuses_verified_bytes_but_not_legacy_resolution_decisions(self):
        target_env=fixture_target('3.10.14')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);old=root/'old';new=root/'new'
            (old/'objects/sha256').mkdir(parents=True);(old/'metadata').mkdir();(old/'downloads').mkdir();(old/'STAGING').write_text('legacy')
            payload=b'legacy bytes';sha=hashlib.sha256(payload).hexdigest();obj=old/'objects/sha256'/sha[:2]/sha
            obj.parent.mkdir();obj.write_bytes(payload)
            key=pool.pip_group_key(target_env,{'demo==1.0'})
            legacy={'python':'3.10','requested':['demo==1.0'],'constraints':[],'no_deps':False,
                    'files':[{'filename':'demo.whl','sha256':sha}],'source_archives':[]}
            (old/'metadata'/('pip-plan-'+key+'.json')).write_text(json.dumps(legacy))
            new.mkdir();(new/'objects').mkdir();(new/'metadata').mkdir();(new/'downloads').mkdir()
            verified=pool.salvage_verified_stage(old,new)
            self.assertEqual(verified,{sha})
            self.assertTrue((new/'objects/sha256'/sha[:2]/sha).is_file())
            self.assertFalse((new/'metadata'/('pip-plan-'+key+'.json')).exists())

    def test_pip_groups_use_configured_parallelism(self):
        target_env=fixture_target('3.10.14').as_dict()
        groups={str(index):{'target':target_env,'requirements':['demo==1.0'],
                            'constraints':[],'no_deps':False,'required':True,
                            'tasks':['task-'+str(index)],'steps':['install']}
                for index in range(4)}
        lock=__import__('threading').Lock();gate=__import__('threading').Barrier(2)
        active=0;maximum=0
        def resolve(_pool,_target,_reqs,_constraints,key,**_kwargs):
            nonlocal active,maximum
            with lock:
                active+=1;maximum=max(maximum,active)
            gate.wait(timeout=5)
            with lock:active-=1
            return [{'kind':'wheel','name':'demo','version':'1.0','filename':key+'.whl',
                     'sha256':hashlib.sha256(key.encode()).hexdigest(),
                     'url':'https://files.pythonhosted.org/'+key+'.whl',
                     'requirements':[],'provides_extra':[]}]
        def materialize(_pool,records,*_args,**_kwargs):
            for row in records:
                payload=row['url'].rsplit('/',1)[-1].removesuffix('.whl').encode()
                self.assertEqual(hashlib.sha256(payload).hexdigest(),row['sha256'])
                path=_pool.objects/row['sha256'][:2]/row['sha256']
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(payload)
            return records
        with tempfile.TemporaryDirectory() as tmp:
            candidate=self.make_pool(Path(tmp))
            with patch.object(pool,'_pip_worker_controls',return_value=(2,2)), \
                 patch.object(pool,'_resolve_registry_plan',side_effect=resolve), \
                 patch.object(pool,'_materialize_solution',side_effect=materialize):
                pool.acquire_pip_groups(candidate,groups)
        self.assertEqual(maximum,2)

    def test_required_parallel_group_failure_remains_fatal(self):
        target_env=fixture_target('3.10.14').as_dict()
        groups={
            'a':{'target':target_env,'requirements':['broken'],'constraints':[],'no_deps':False,'required':True,'tasks':['task-a'],'steps':['install']},
            'b':{'target':target_env,'requirements':['later'],'constraints':[],'no_deps':False,'required':True,'tasks':['task-b'],'steps':['install']},
        }
        def resolve(_pool,_target,_reqs,_constraints,key,**_kwargs):
            if key=='a':raise RuntimeError('boom')
            return [{'kind':'wheel','name':'later','version':'1.0','filename':'later.whl',
                     'sha256':hashlib.sha256(b'later').hexdigest(),
                     'url':'https://files.pythonhosted.org/later.whl',
                     'requirements':[],'provides_extra':[]}]
        with tempfile.TemporaryDirectory() as tmp:
            candidate=self.make_pool(Path(tmp))
            with patch.object(pool,'_pip_worker_controls',return_value=(2,2)),                  patch.object(pool,'_resolve_registry_plan',side_effect=resolve),                  self.assertRaisesRegex(RuntimeError,'required pip closure a failed: boom'):
                pool.acquire_pip_groups(candidate,groups)

    def test_each_completed_closure_checkpoints_before_another_closure_fails(self):
        target_env=fixture_target('3.10.14').as_dict()
        groups={name:{'target':target_env,'requirements':[name+'==1.0'],
                      'constraints':[],'no_deps':False,'required':True,
                      'tasks':['task-'+name],'steps':['install']}
                for name in ('alpha','beta')}
        threading=__import__('threading')
        persisted=threading.Event()
        original_write=pool._write_pip_plan

        def resolve(_pool,_target,_reqs,_constraints,key,**_kwargs):
            if key=='beta':
                self.assertTrue(persisted.wait(timeout=5),
                                'other closure must become durable before this failure')
                raise RuntimeError('planned sibling failure')
            return [{'kind':'wheel','name':'alpha','version':'1.0',
                     'filename':'alpha-1.0-py3-none-any.whl',
                     'sha256':hashlib.sha256(b'alpha').hexdigest(),
                     'url':'https://files.pythonhosted.org/alpha.whl',
                     'requirements':[],'provides_extra':[]}]

        def materialize(_pool,records,*_args,**_kwargs):
            for row in records:
                payload=row['url'].rsplit('/',1)[-1].removesuffix('.whl').encode()
                self.assertEqual(hashlib.sha256(payload).hexdigest(),row['sha256'])
                path=_pool.objects/row['sha256'][:2]/row['sha256']
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(payload)
            return records

        def checkpoint(*args,**kwargs):
            result=original_write(*args,**kwargs)
            persisted.set()
            return result

        with tempfile.TemporaryDirectory() as tmp:
            candidate=self.make_pool(Path(tmp))
            with patch.object(pool,'_pip_worker_controls',return_value=(2,2)), \
                 patch.object(pool,'_resolve_registry_plan',side_effect=resolve), \
                 patch.object(pool,'_materialize_solution',side_effect=materialize), \
                 patch.object(pool,'_write_pip_plan',side_effect=checkpoint), \
                 self.assertRaisesRegex(RuntimeError,'required pip closure beta failed: planned sibling failure'):
                pool.acquire_pip_groups(candidate,groups)
            self.assertTrue(persisted.is_set())
            plan=json.loads((Path(tmp)/'metadata/pip-plan-alpha.json').read_text())
            self.assertEqual(plan['requested'],['alpha==1.0'])
            self.assertEqual(plan['packages'][0]['name'],'alpha')

    def test_cached_dependency_compatibility_prevents_pairwise_version_explosion(self):
        target=fixture_target('3.10.14')
        _,_,Version,_,_=pool._packaging_symbols()
        versions=range(1,41)
        def candidate(name,version):
            value=str(version)
            return {'kind':'wheel','name':name,'version':value,
                    'filename':f'{name}-{value}-py3-none-any.whl',
                    'item':{'url':f'https://files.pythonhosted.org/{name}-{value}.whl',
                            'digests':{'sha256':hashlib.sha256(f'{name}-{value}'.encode()).hexdigest()}}}
        universes={name:tuple((Version(str(v)),candidate(name,v)) for v in versions)
                   for name in ('awscli','boto3','botocore')}
        def release(name,_target,_cache=None,**_kwargs):return universes[name]
        def exact(name,version,_target,_cache=None):
            return tuple(row for row in universes[name] if row[0]==Version(version))
        def metadata(_pool,item,_key,_target,_probe,_artifact,**_kwargs):
            def compute():
                deps=(['botocore=='+item['version']] if item['name']=='awscli'
                      else ['botocore==1'] if item['name']=='boto3' else [])
                return {**item,'sha256':item['item']['digests']['sha256'],
                        'url':item['item']['url'],'requirements':deps,'provides_extra':[]}
            identity=pool._candidate_probe_identity(item,_target,False)
            return pool._memo_get_or_compute(_probe,identity,compute)
        with tempfile.TemporaryDirectory() as tmp:
            candidate_pool=self.make_pool(Path(tmp));output=io.StringIO()
            with patch.object(pool,'_registry_release_candidates',side_effect=release), \
                 patch.object(pool,'_registry_exact_release_candidate',side_effect=exact), \
                 patch.object(pool,'_candidate_release_metadata',side_effect=metadata), \
                 contextlib.redirect_stdout(output):
                result=pool._resolve_registry_plan(candidate_pool,target,
                    {'awscli>=1','boto3>=1'},(),'aws-pair-regression',materialize=False)
            chosen={row['name']:row['version'] for row in result}
            self.assertEqual(chosen['awscli'],'1')
            self.assertEqual(chosen['botocore'],'1')
            self.assertIn(chosen['boto3'],{str(v) for v in versions})
            summary=output.getvalue()
            import re
            decisions=int(re.search(r'decisions=(\d+)',summary).group(1))
            pruning=int(re.search(r'forward_prunes=(\d+)',summary).group(1))
            self.assertLess(decisions,len(versions)*3,summary)
            self.assertGreater(pruning,0,summary)

    def test_adaptive_prefetch_expands_as_resolvers_finish(self):
        activity=pool._ResolverActivity(8)
        for _ in range(8):activity.enter()
        self.assertEqual(activity.width(),1)
        for _ in range(4):activity.leave()
        self.assertEqual(activity.width(),2)
        for _ in range(3):activity.leave()
        self.assertEqual(activity.width(),8)
        activity.leave()

    def test_resolver_prefetches_candidate_metadata_concurrently(self):
        target=fixture_target('3.10.14')
        barrier=__import__('threading').Barrier(2)
        candidate_rows=[
            {'kind':'wheel','name':'demo','version':'1.0',
             'filename':'demo-1.0-py3-none-any.whl','item':{}},
            {'kind':'wheel','name':'demo','version':'2.0',
             'filename':'demo-2.0-py3-none-any.whl','item':{}},
        ]
        def versions(*_args,**_kwargs):return candidate_rows
        def metadata(_pool,item,_key,_target,_probe_cache,_artifact_cache,**_kwargs):
            barrier.wait(timeout=5)
            return {**item,'sha256':hashlib.sha256(item['version'].encode()).hexdigest(),
                    'url':'https://files.pythonhosted.org/'+item['filename'],
                    'requirements':[],'provides_extra':[]}
        def materialize(_pool,records,_key,_target,_cache,**_kwargs):return records
        with tempfile.TemporaryDirectory() as tmp:
            candidate=self.make_pool(Path(tmp))
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor, \
                 patch.object(pool,'_candidate_versions',side_effect=versions), \
                 patch.object(pool,'_candidate_release_metadata',side_effect=metadata), \
                 patch.object(pool,'_materialize_solution',side_effect=materialize):
                result=pool._resolve_registry_plan(
                    candidate,target,{'demo>=1'},(),'prefetch',
                    resolver_cache={'release_metadata':pool._SingleFlightCache(),
                                    'artifact_metadata':pool._SingleFlightCache(),
                                    'releases':pool._SingleFlightCache(),
                                    'preferred_versions':{},
                                    'metadata_prefetch':2,
                                    'metadata_executor':executor})
        self.assertEqual(len(result),1)

    def test_resolver_discovers_unresolved_domains_concurrently(self):
        target=fixture_target('3.10.14')
        barrier=__import__('threading').Barrier(2)
        def versions(_pool,name,*_args,**_kwargs):
            barrier.wait(timeout=5)
            return [{'kind':'wheel','name':name,'version':'1.0',
                     'filename':name+'-1.0-py3-none-any.whl','item':{}}]
        def metadata(_pool,item,_key,_target,_probe_cache,_artifact_cache,**_kwargs):
            return {**item,'sha256':hashlib.sha256(item['name'].encode()).hexdigest(),
                    'url':'https://files.pythonhosted.org/'+item['filename'],
                    'requirements':[],'provides_extra':[]}
        def materialize(_pool,records,_key,_target,_cache,**_kwargs):return records
        with tempfile.TemporaryDirectory() as tmp:
            candidate=self.make_pool(Path(tmp))
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor, \
                 patch.object(pool,'_candidate_versions',side_effect=versions), \
                 patch.object(pool,'_candidate_release_metadata',side_effect=metadata), \
                 patch.object(pool,'_materialize_solution',side_effect=materialize):
                result=pool._resolve_registry_plan(
                    candidate,target,{'alpha==1.0','beta==1.0'},(),'domains',
                    resolver_cache={'release_metadata':pool._SingleFlightCache(),
                                    'artifact_metadata':pool._SingleFlightCache(),
                                    'releases':pool._SingleFlightCache(),
                                    'preferred_versions':{},
                                    'metadata_prefetch':1,
                                    'metadata_executor':executor})
        self.assertEqual({row['name'] for row in result},{'alpha','beta'})

    def test_singleton_domain_and_metadata_use_io_executor(self):
        target=fixture_target('3.10.14')
        threads=[]
        row={'kind':'wheel','name':'demo','version':'1.0',
             'filename':'demo-1.0-py3-none-any.whl','item':{}}
        def versions(*_args,**_kwargs):
            threads.append(('domain',__import__('threading').current_thread().name))
            return [row]
        def metadata(_pool,item,_key,_target,_probe_cache,_artifact_cache,**_kwargs):
            threads.append(('metadata',__import__('threading').current_thread().name))
            return {**item,'sha256':hashlib.sha256(b'demo').hexdigest(),
                    'url':'https://files.pythonhosted.org/demo.whl',
                    'requirements':[],'provides_extra':[]}
        with tempfile.TemporaryDirectory() as tmp:
            candidate=self.make_pool(Path(tmp))
            with concurrent.futures.ThreadPoolExecutor(max_workers=1,thread_name_prefix='fixture-io') as executor,                  patch.object(pool,'_candidate_versions',side_effect=versions),                  patch.object(pool,'_candidate_release_metadata',side_effect=metadata),                  patch.object(pool,'_materialize_solution',side_effect=lambda _pool,records,*_args,**_kwargs:records):
                result=pool._resolve_registry_plan(
                    candidate,target,{'demo==1.0'},(),'singleton',
                    resolver_cache={'release_metadata':pool._SingleFlightCache(),
                                    'artifact_metadata':pool._SingleFlightCache(),
                                    'releases':pool._SingleFlightCache(),
                                    'preferred_versions':{},
                                    'metadata_prefetch':1,
                                    'metadata_executor':executor})
        self.assertEqual(len(result),1)
        self.assertEqual([kind for kind,_name in threads],['domain','metadata'])
        self.assertTrue(all(name.startswith('fixture-io') for _kind,name in threads))

    def test_winning_artifacts_materialize_concurrently(self):
        target=fixture_target('3.10.14')
        barrier=__import__('threading').Barrier(2)
        records=[]
        for name in ('alpha','beta'):
            records.append({'kind':'wheel','name':name,'version':'1.0',
                            'filename':name+'-1.0-py3-none-any.whl',
                            'sha256':hashlib.sha256(name.encode()).hexdigest(),
                            'url':'https://files.pythonhosted.org/'+name+'.whl',
                            'requirements':[],'provides_extra':[]})
        def materialize(_pool,candidate,_key,_target,_cache):
            barrier.wait(timeout=5)
            return {'kind':candidate['kind'],'name':candidate['name'],'version':candidate['version'],
                    'filename':candidate['filename'],
                    'sha256':candidate['item']['digests']['sha256'],
                    'url':candidate['item']['url'],'requirements':[],'provides_extra':[]}
        with tempfile.TemporaryDirectory() as tmp:
            candidate_pool=self.make_pool(Path(tmp))
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor,                  patch.object(pool,'_materialize_candidate_metadata',side_effect=materialize):
                result=pool._materialize_solution(
                    candidate_pool,records,'materialize',target,{},executor=executor)
        self.assertEqual([row['name'] for row in result],['alpha','beta'])


    def test_git_mirrors_bound_pack_work_by_cpu_affinity(self):
        barrier=__import__('threading').Barrier(2);calls=[];lock=__import__('threading').Lock()
        def mirror(_stage,repo,commits,*,label='git'):
            with lock:calls.append((repo,tuple(sorted(commits)),label))
            barrier.wait(timeout=5)
            return Path('/tmp')/(repo.replace('/','_')+'.git')
        repositories={'one/repo':{'a'*40},'two/repo':{'b'*40}}
        with patch.object(pool,'_acquisition_workers',return_value=8), \
             patch.object(pool.os,'sched_getaffinity',return_value={0,1}), \
             patch.object(pool,'mirror_commits',side_effect=mirror), \
             patch.object(pool,'ensure_version_refs',return_value={}):
            mirrors,refs=pool._acquire_git_mirrors(
                Path('/tmp'),repositories,freeze_version_refs=True)
        self.assertEqual(set(mirrors),set(repositories))
        self.assertEqual(refs,{repo:{} for repo in repositories})
        self.assertEqual(len(calls),2)

    def test_git_fetch_retries_quietly_inside_same_preparation(self):
        failure=subprocess.CompletedProcess(['git'],128,stdout='',stderr='RPC failed; curl 92 HTTP/2 stream closed')
        success=subprocess.CompletedProcess(['git'],0,stdout='',stderr='')
        with patch.object(pool.subprocess,'run',side_effect=[failure,success]) as runner, \
             patch.object(pool.time,'sleep') as sleeper:
            pool._git_fetch(Path('/tmp/mirror.git'),'modin-project/modin',['a'*40])
        self.assertEqual(runner.call_count,2)
        sleeper.assert_called_once_with(1)
        command=runner.call_args_list[0].args[0]
        self.assertIn('--quiet',command)
        self.assertIn('--no-recurse-submodules',command)
        self.assertIn('--no-auto-maintenance',command)
        self.assertIn('--no-tags',command)

    def test_git_fetch_exhaustion_reports_bounded_stderr(self):
        failure=subprocess.CompletedProcess(['git'],128,stdout='',stderr='fatal: '+('x'*5000))
        with patch.object(pool.subprocess,'run',return_value=failure) as runner, \
             patch.object(pool.time,'sleep'):
            with self.assertRaisesRegex(RuntimeError,'Git fetch failed after 5 attempts for modin-project/modin') as raised:
                pool._git_fetch(Path('/tmp/mirror.git'),'modin-project/modin',['a'*40])
        self.assertEqual(runner.call_count,pool.DOWNLOAD_ATTEMPTS)
        self.assertLess(len(str(raised.exception)),800)

    def test_same_filename_different_bytes_are_separate_cas_objects(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate=self.make_pool(Path(tmp));first=Path(tmp)/'one.whl';second=Path(tmp)/'two.whl'
            first.write_bytes(b'one');second.write_bytes(b'two')
            one=candidate.put(first,'python','one');two=candidate.put(second,'python','two')
            self.assertNotEqual(one,two)
            self.assertTrue((candidate.objects/one[:2]/one).is_file())
            self.assertTrue((candidate.objects/two[:2]/two).is_file())

    def test_required_network_acquisition_is_never_issue_accumulation(self):
        source=(ROOT/'scripts/superbench_pool.py').read_text()
        self.assertNotIn("pool.issue('pip:'",source);self.assertNotIn("pool.issue('APT'",source)
        self.assertNotIn("pool.issue('npm-global'",source)
        self.assertIn("raise RuntimeError('required VCS closure failed",source)
        self.assertIn('PIP_ARTIFACT_MODEL',source)


class TestResolverConcurrency(unittest.TestCase):
    def test_single_flight_computes_one_value_for_concurrent_waiters(self):
        memo=pool._SingleFlightCache()
        gate=__import__('threading').Barrier(4)
        calls=[];lock=__import__('threading').Lock()
        def worker():
            gate.wait(timeout=5)
            return memo.get_or_compute('shared',produce)
        def produce():
            with lock:calls.append('produce')
            __import__('time').sleep(0.02)
            return 'value'
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            results=list(executor.map(lambda _index:worker(),range(4)))
        self.assertEqual(results,['value']*4)
        self.assertEqual(calls,['produce'])


class TestNetworkRetries(unittest.TestCase):
    class Response:
        def __init__(self, url, events, headers=None):
            self.url = url
            self.events = list(events)
            self.headers = headers or {}

        def __enter__(self): return self
        def __exit__(self, *args): return False

        def read(self, _size):
            if not self.events: return b''
            item = self.events.pop(0)
            if isinstance(item, BaseException): raise item
            return item

    def test_midstream_timeout_retries_from_zero_and_discards_partial(self):
        url = 'https://repo.example.test/pkg.conda'
        payload = b'complete artifact'
        expected = hashlib.sha256(payload).hexdigest()
        first = self.Response(url, [b'partial bytes', TimeoutError('read timed out')])
        second = self.Response(url, [payload, b''])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'artifact'
            log = io.StringIO()
            with patch.object(pool.urllib.request, 'urlopen', side_effect=[first, second]) as opener, \
                 patch.object(pool.time, 'sleep') as sleeper, \
                 contextlib.redirect_stderr(log):
                actual = pool.fetch(url, path, sha=expected)
            self.assertEqual(actual, expected)
            self.assertEqual(path.read_bytes(), payload)
            self.assertEqual(opener.call_count, 2)
            sleeper.assert_called_once_with(1)
            self.assertIn('network retry 2/5 in 1s after TimeoutError', log.getvalue())

    def test_expected_https_metadata_reuses_one_connection_per_thread(self):
        class Response:
            status=200;reason='OK';headers={'Content-Length':'2'}
            def getheader(self,name,default=''):return self.headers.get(name,default)
            def read(self,*_args):return b'{}'
        class Connection:
            def __init__(self,*_args,**_kwargs):self.sock=None;self.requests=[]
            def request(self,*args,**kwargs):self.requests.append((args,kwargs))
            def getresponse(self):return Response()
            def close(self):pass
        pool._HTTPS_CONNECTIONS.connections={}
        with patch.object(pool.http.client,'HTTPSConnection',side_effect=Connection) as factory:
            self.assertEqual(pool._read_expected_https_once(
                'https://pypi.org/pypi/a/json',timeout=10,limit=1024,
                user_agent='test',expected_host='pypi.org'),b'{}')
            self.assertEqual(pool._read_expected_https_once(
                'https://pypi.org/pypi/b/json',timeout=10,limit=1024,
                user_agent='test',expected_host='pypi.org'),b'{}')
        self.assertEqual(factory.call_count,1)

    def test_expected_https_metadata_requests_and_decodes_gzip(self):
        import gzip
        payload=b'{"name":"demo","values":['+b'1,'*256+b'0]}'
        encoded=gzip.compress(payload)
        class Response:
            status=200;reason='OK'
            def __init__(self):
                self.headers={'Content-Length':str(len(encoded)),'Content-Encoding':'gzip'}
                self._stream=io.BytesIO(encoded)
            def getheader(self,name,default=''):return self.headers.get(name,default)
            def read(self,*args):return self._stream.read(*args)
        class Connection:
            def __init__(self,*_args,**_kwargs):self.sock=None;self.headers=None
            def request(self,_method,_path,headers=None):self.headers=headers
            def getresponse(self):return Response()
            def close(self):pass
        connection=Connection()
        pool._HTTPS_CONNECTIONS.connections={}
        with patch.object(pool.http.client,'HTTPSConnection',return_value=connection):
            raw=pool._read_expected_https_once(
                'https://pypi.org/pypi/demo/json',timeout=10,limit=len(payload),
                user_agent='test',expected_host='pypi.org')
        self.assertEqual(raw,payload)
        self.assertEqual(connection.headers['Accept-Encoding'],'gzip')

    def test_metadata_size_rejection_does_not_drain_unbounded_body(self):
        class Response:
            headers={'Content-Length':'4096','Content-Encoding':'identity'}
            def getheader(self,name,default=''):return self.headers.get(name,default)
            def read(self,*_args):raise AssertionError('oversized body must not be drained')
        with self.assertRaisesRegex(RuntimeError,'exceeds limit'):
            pool._read_metadata_response(Response(),1024)

    def test_corrupt_gzip_metadata_is_retried(self):
        url='https://pypi.org/pypi/retry-gzip-fixture/json'
        with patch.object(pool,'_read_expected_https_once',
                          side_effect=[pool.MetadataDecodeError('truncated'),b'{"ok":true}']) as reader,              patch.object(pool.time,'sleep') as sleeper:
            self.assertEqual(pool._pypi_json(url),{'ok':True})
        self.assertEqual(reader.call_count,2)
        sleeper.assert_called_once_with(1)


    def test_retryable_http_503_is_retried_for_metadata(self):
        url = 'https://pypi.org/pypi/demo/json'
        failure = pool.urllib.error.HTTPError(url, 503, 'service unavailable', {}, None)
        with patch.object(pool,'_read_expected_https_once',
                          side_effect=[failure,b'{"name":"demo"}']) as reader, \
             patch.object(pool.time, 'sleep') as sleeper:
            self.assertEqual(pool._pypi_json(url), {'name': 'demo'})
        self.assertEqual(reader.call_count, 2)
        sleeper.assert_called_once_with(1)

    def test_nonretryable_http_404_fails_immediately(self):
        url = 'https://pypi.org/pypi/missing/json'
        failure = pool.urllib.error.HTTPError(url, 404, 'missing', {}, None)
        with patch.object(pool,'_read_expected_https_once',side_effect=failure) as reader, \
             patch.object(pool.time, 'sleep') as sleeper, \
             self.assertRaises(pool.urllib.error.HTTPError):
            pool._pypi_json(url)
        self.assertEqual(reader.call_count, 1)
        sleeper.assert_not_called()

    def test_network_retry_budget_is_bounded(self):
        url = 'https://repo.example.test/pkg.conda'
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(pool.urllib.request, 'urlopen', side_effect=[TimeoutError('x')] * 5) as opener, \
             patch.object(pool.time, 'sleep') as sleeper, \
             self.assertRaises(TimeoutError):
            pool.fetch(url, Path(tmp) / 'artifact')
        self.assertEqual(opener.call_count, 5)
        self.assertEqual(sleeper.call_count, 4)

    def test_checksum_mismatch_retries_from_zero_and_discards_bad_bytes(self):
        url = 'https://repo.example.test/pkg.conda'
        good = b'good bytes'
        expected = hashlib.sha256(good).hexdigest()
        first = self.Response(url, [b'bad bytes', b''])
        second = self.Response(url, [good, b''])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'artifact'
            log = io.StringIO()
            with patch.object(pool.urllib.request, 'urlopen', side_effect=[first, second]) as opener, \
                 patch.object(pool.time, 'sleep') as sleeper, \
                 contextlib.redirect_stderr(log):
                actual = pool.fetch(url, path, sha=expected)
            self.assertEqual(actual, expected)
            self.assertEqual(path.read_bytes(), good)
            self.assertEqual(opener.call_count, 2)
            sleeper.assert_called_once_with(1)
            self.assertIn('network retry 2/5 in 1s after DownloadIntegrityError', log.getvalue())

    def test_checksum_mismatch_retry_budget_is_bounded(self):
        url = 'https://repo.example.test/pkg.conda'
        expected = hashlib.sha256(b'good bytes').hexdigest()
        responses = [self.Response(url, [b'bad bytes', b'']) for _ in range(pool.DOWNLOAD_ATTEMPTS)]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'artifact'
            with patch.object(pool.urllib.request, 'urlopen', side_effect=responses) as opener, \
                 patch.object(pool.time, 'sleep') as sleeper, \
                 self.assertRaisesRegex(pool.DownloadIntegrityError, 'sha256 mismatch'):
                pool.fetch(url, path, sha=expected)
            self.assertEqual(opener.call_count, pool.DOWNLOAD_ATTEMPTS)
            self.assertEqual(sleeper.call_count, pool.DOWNLOAD_ATTEMPTS - 1)
            self.assertFalse(path.exists())


class TestDeduplication(unittest.TestCase):
    def test_concurrent_same_url_is_downloaded_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            acquired=pool.Pool(Path(tmp))
            payload=b'concurrent immutable payload'
            sha=hashlib.sha256(payload).hexdigest()
            calls=[];lock=__import__('threading').Lock();gate=__import__('threading').Barrier(2)
            def network(url,path,*,sha=None,sri=None,limit=2**37,integrity_digests=None):
                with lock:calls.append(url)
                Path(path).write_bytes(payload)
                return hashlib.sha256(payload).hexdigest()
            def work(identity):
                gate.wait(timeout=5)
                return acquired.download('https://example.test/shared','python',identity,sha=sha)
            with patch.object(pool,'fetch',side_effect=network), \
                 concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                results=list(executor.map(work,('one','two')))
            self.assertEqual(results,[sha,sha])
            self.assertEqual(calls,['https://example.test/shared'])
            self.assertEqual(set(acquired.provenance['python']),{'one','two'})

    def test_npm_sri_closure_uses_versioned_parallel_io_capacity(self):
        urls={
            'https://registry.npmjs.org/a/-/a-1.0.0.tgz':'sha512-a',
            'https://registry.npmjs.org/b/-/b-1.0.0.tgz':'sha512-b',
        }
        barrier=__import__('threading').Barrier(2)
        active=[];lock=__import__('threading').Lock()
        with tempfile.TemporaryDirectory() as tmp:
            candidate=pool.Pool(Path(tmp))
            def download(url,category,identity,*,sha=None,sri=None):
                with lock:active.append((url,category,identity,sri))
                barrier.wait(timeout=5)
                return hashlib.sha256(url.encode()).hexdigest()
            with patch.object(candidate,'download',side_effect=download), \
                 patch.object(pool,'_acquisition_workers',return_value=2):
                result=pool._download_sri_closure(candidate,urls,'npm')
        self.assertEqual(set(result),set(urls))
        self.assertEqual(len(active),2)
        self.assertTrue(all(category=='npm' and identity==url for url,category,identity,_sri in active))

    def test_sha_and_url_share_one_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            acquired = pool.Pool(Path(tmp))
            data = b'one identical upstream file\n'
            sha = hashlib.sha256(data).hexdigest()
            calls = []
            def network(url, path, *, sha=None, sri=None, limit=2**37, integrity_digests=None):
                calls.append(url)
                Path(path).write_bytes(data)
                if integrity_digests is not None:
                    import hashlib as h
                    integrity_digests.update({'sha384': h.sha384(data).digest(), 'sha512': h.sha512(data).digest()})
                return hashlib.sha256(data).hexdigest()
            with patch.object(pool, 'fetch', side_effect=network):
                acquired.download('https://example.test/one', 'python', 'task-a', sha=sha)
                acquired.download('https://example.test/one', 'python', 'task-b', sha=sha)
                acquired.download('https://example.test/two', 'python', 'task-c', sha=sha)
            self.assertEqual(calls, ['https://example.test/one'])
            self.assertEqual(len(acquired.links), 1)
            self.assertEqual(set(acquired.provenance['python']), {'task-a','task-b','task-c'})


class TestVerifiedPoolResume(unittest.TestCase):
    def test_cas_reuse_is_hardlinked_verified_and_no_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);old=root/'old';new=root/'fresh'
            (old/'objects'/'sha256').mkdir(parents=True)
            (old/'STAGING').write_text('legacy stage')
            data=b'locked conda payload';sha=hashlib.sha256(data).hexdigest()
            obj=old/'objects'/'sha256'/sha[:2]/sha
            obj.parent.mkdir();obj.write_bytes(data)
            (old/'downloads').mkdir()
            raw=old/'downloads'/hashlib.sha256(b'https://example.test/pkg').hexdigest()
            os.link(obj,raw)
            new.mkdir()
            for name in ('objects','downloads'):(new/name).mkdir()
            verified=pool.salvage_verified_stage(old,new)
            self.assertEqual(verified,{sha})
            copy=new/'objects'/'sha256'/sha[:2]/sha
            self.assertTrue(obj.samefile(copy))
            candidate=pool.Pool(new);candidate.verified_objects.update(verified)
            with patch.object(pool,'fetch',side_effect=AssertionError('network forbidden')):
                self.assertEqual(candidate.download('https://example.test/pkg','conda','env',sha=sha),sha)

    def test_corrupt_old_object_is_not_reused(self):
        with tempfile.TemporaryDirectory() as tmp:
            old=Path(tmp)/'old';new=Path(tmp)/'new'
            (old/'objects'/'sha256').mkdir(parents=True)
            (old/'STAGING').write_text('legacy')
            sha='a'*64
            item=old/'objects'/'sha256'/sha[:2]/sha
            item.parent.mkdir();item.write_bytes(b'corrupt')
            new.mkdir();(new/'objects').mkdir()
            self.assertEqual(pool.salvage_verified_stage(old,new),set())
            self.assertFalse((new/'objects'/'sha256'/sha[:2]/sha).exists())
            self.assertEqual(item.read_bytes(),b'corrupt')

    def test_retained_partial_or_unpinned_download_is_discarded(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);artifact=pool.Pool(stage)
            url='https://example.test/unpinned';raw=stage/'downloads'/hashlib.sha256(url.encode()).hexdigest()
            raw.parent.mkdir(exist_ok=True);raw.write_bytes(b'partial')
            full=b'complete';calls=[]
            def fake_fetch(u,p,*,sha=None,sri=None,limit=2**37,integrity_digests=None):
                calls.append(u);Path(p).write_bytes(full);return hashlib.sha256(full).hexdigest()
            with patch.object(pool,'fetch',side_effect=fake_fetch):
                artifact.download(url,'test','identity')
            self.assertEqual(calls,[url]);self.assertEqual(raw.read_bytes(),full)

    def test_git_mirror_with_exact_pinned_commit_avoids_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);repo='test/example';commit='a'*40
            folder=root/'git'/'test_example.git'
            folder.mkdir(parents=True)
            def command(argv,*,cwd=None,capture=False,env=None,timeout=3600):
                if 'rev-parse' in argv:return 'true'
                if 'cat-file' in argv:return ''
                raise AssertionError('network or git init forbidden: '+repr(argv))
            with patch.object(pool,'invoke',side_effect=command),patch.object(
                    pool.subprocess,'run',return_value=type('Result',(),{'returncode':0})()):
                self.assertEqual(pool.mirror_commits(root,repo,{commit}),folder)

    def test_broker_selects_only_a_quiescent_matching_legacy_stage(self):
        import ast
        import re
        import types
        source=(ROOT/'apps/workstation-broker/src/workstation_broker/preparation.py').read_text()
        tree=ast.parse(source)
        method=next(x for x in tree.body if isinstance(x,ast.FunctionDef)
                    and x.name=='retained_dependency_stage')
        class Scope:
            members=staticmethod(lambda state: [])
        namespace={'Path':Path,'SHA':re.compile(r'[0-9a-f]{64}\Z'),
                   'TERMINAL':{'interrupted','canceled','failed','ready'},
                   'JobScope':Scope,'hashlib':hashlib,'RuntimeError':RuntimeError}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[method],type_ignores=[])),
                     '<retained-stage>', 'exec'),namespace)
        select=namespace['retained_dependency_stage']
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);poolroot=root/'pool';poolroot.mkdir()
            legacy=poolroot/'incoming';legacy.mkdir(mode=0o700)
            (legacy/'STAGING').write_text('legacy')
            jobs=root/'preparations';jobs.mkdir()
            operation='1'*64;(jobs/operation).mkdir()
            previous={'phase':'interrupted','compatibility':{
                'pins':{'same':True},'conda_lock_sha256':'c'*64,'fetcher_sha256':'a'*64},
                'operation_id':operation,'attempt':1,'result':None}
            active={'compatibility':{**previous['compatibility'],'fetcher_sha256':'b'*64}}
            class Manager:
                root=jobs
                def _read(self,op):return previous
                def _containers(self,state):return []
            account=types.SimpleNamespace(pw_uid=os.getuid())
            self.assertEqual(select(Manager(),poolroot,active,account),legacy)
            previous['phase']='running'
            self.assertIsNone(select(Manager(),poolroot,active,account))
            previous['phase']='interrupted'
            previous['compatibility']['pins']={'same':False}
            self.assertIsNone(select(Manager(),poolroot,active,account))

    def test_retained_symlink_is_rejected_without_modification(self):
        with tempfile.TemporaryDirectory() as tmp:
            old=Path(tmp)/'old';new=Path(tmp)/'new'
            old.mkdir();new.mkdir();(old/'STAGING').write_text('legacy')
            (old/'bad').symlink_to('/etc')
            with self.assertRaisesRegex(RuntimeError,'unsafe retained'):
                pool.salvage_verified_stage(old,new)
            self.assertTrue((old/'bad').is_symlink())


class TestPublicationRecovery(unittest.TestCase):
    def test_published_verified_pool_is_reconciled_without_rehash_or_retry(self):
        import ast
        import types
        source = (ROOT / 'apps/workstation-broker/src/workstation_broker/preparation.py').read_text()
        tree = ast.parse(source)
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'PreparationManager')
        method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == '_reconcile')
        class Scope:
            @staticmethod
            def members(state): return []
            @staticmethod
            def close(state): return state
        namespace = {'JobScope': Scope, 'TERMINAL': {'ready','failed','canceled','interrupted'},
                     'RuntimeError': RuntimeError, 'Path': Path, 'json': json,
                     'safe': lambda path, **kwargs: Path(path)}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])),
                     str(ROOT / 'apps/workstation-broker/src/workstation_broker/preparation.py'), 'exec'), namespace)
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp) / 'golden.qcow2'; base.write_bytes(b'unrelated')
            ready = base.parent / 'dependency-pool' / 'ready'; ready.mkdir(parents=True)
            operation = '7' * 64
            contract=json.loads((ROOT/'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/contract.json').read_bytes())
            coverage={'tasks':len(contract['tasks']),'repos':len({row['repo'] for row in contract['tasks'].values()}),
                      'conda_recipes':len(contract['environments'])}
            record = {'operation_id': operation, 'complete': True, **coverage}
            (ready/'inventory.json').write_text(json.dumps(record))
            expected = {'kind':'download-only-pool','complete':True,
                        'pool_directory':str(ready),**coverage,'runtime_integrated':True,
                        'offline_replay':True,'generation':'8'*64}
            state = {'phase':'interrupted','operation_id':operation,
                     'publication_verified':expected, 'error':'worker died after rename'}
            class FakeManager:
                def __init__(self): self.base=base; self.saved=[]
                def _reap(self): pass
                def _containers(self, *_): return []
                def _write(self, value): self.saved.append(value)
                def slot_busy(self): return False
            manager = FakeManager()
            recovered = namespace['_reconcile'](manager, state)
            self.assertEqual(recovered['phase'], 'ready')
            self.assertEqual(recovered['result'], expected)
            self.assertEqual(len(manager.saved), 1)

    def test_unverified_published_pool_is_not_automatically_accepted(self):
        source = (ROOT / 'apps/workstation-broker/src/workstation_broker/preparation.py').read_text()
        self.assertIn('publication_verified', source)
        self.assertIn("inventory.get('operation_id')", source)
        self.assertIn('actual_files != expected | {"inventory.json"}', source)


class TestPinnedRealWorldRegressions(unittest.TestCase):
    def test_hydra_file_backed_install_requires_without_execution(self):
        # Matches actual hydra 94bbaaad setup.py metadata source syntax.
        setup = ("""from setuptools import setup
import pathlib
import pkg_resources
with pathlib.Path("requirements/requirements.txt").open() as requirements_txt:
    install_requires = [str(requirement) for requirement in pkg_resources.parse_requirements(requirements_txt)]
setup(install_requires=install_requires)
""")
        data = {'requirements/requirements.txt':'omegaconf>=2.0\nantlr4-python3-runtime==4.8\n'}
        deps, remote, issues = pool.setup_requirements_from_sources(setup,
            lambda name, required=False:data[name])
        self.assertEqual(issues, [])
        self.assertEqual(remote, set())
        self.assertEqual(deps, {'omegaconf>=2.0','antlr4-python3-runtime==4.8'})

    def test_conan_file_backed_install_requires_without_execution(self):
        # Matches actual conan 345be91 setup.py metadata source syntax.
        setup = ("""from setuptools import setup
project_requirements = get_requires("conans/requirements.txt")
project_requirements.extend(get_requires("conans/requirements_server.txt"))
setup(install_requires=project_requirements)
""")
        data = {'conans/requirements.txt':'requests>=2\n',
                'conans/requirements_server.txt':'bottle==0.12\n',
                'conans/requirements_dev.txt':'pytest>=6\n'}
        deps, remote, issues = pool.setup_requirements_from_sources(setup,
            lambda name, required=False:data[name], extras={'dev'})
        self.assertEqual(issues, [])
        self.assertEqual(remote, set())
        self.assertEqual(deps, {'requests>=2','bottle==0.12'})

    def test_conan_legacy_single_runtime_file_without_execution(self):
        # Matches the older Conan layout used by eight pinned SWE-Gym commits.
        setup = ("""from setuptools import setup
project_requirements = get_requires('conans/requirements.txt')
dev_requirements = get_requires('conans/requirements_dev.txt')
setup(install_requires = project_requirements,
      extras_require={'dev': dev_requirements, 'test': dev_requirements})
""")
        data = {'conans/requirements.txt':'requests>=2\nurllib3<2\n',
                'conans/requirements_dev.txt':'pytest>=6\n'}
        deps, remote, issues = pool.setup_requirements_from_sources(setup,
            lambda name, required=False:data[name], extras={'test'})
        self.assertEqual(issues, [])
        self.assertEqual(remote, set())
        self.assertEqual(deps, {'requests>=2','urllib3<2','pytest>=6'})

    def test_modin_spreadsheet_setup_kwargs_reads_pinned_runtime_requirements(self):
        # Matches modin-spreadsheet@49ffd89: dynamic setup_args metadata plus a
        # fixed requirements.txt used for install_requires.
        setup = ("""from setuptools import setup

def read_requirements(basename):
    return dynamic_reader(basename)

def extras_require():
    return {'test': ['pytest']}

reqs = read_requirements("requirements.txt")
setup_args = {
    "name": dynamic_name(),
    "install_requires": reqs,
    "extras_require": extras_require(),
}
setup(version=dynamic_version(), **setup_args)
""")
        data = {'requirements.txt':'jupyter>=1.0.0\nnotebook>=6.0.3\nipywidgets>=7.0.0\n'}
        deps, remote, issues = pool.setup_requirements_from_sources(setup,
            lambda name, required=False:data[name])
        self.assertEqual(issues, [])
        self.assertEqual(remote, set())
        self.assertEqual(deps, {'jupyter>=1.0.0','notebook>=6.0.3','ipywidgets>=7.0.0'})

    def test_unrecognized_dynamic_setup_fails_closed(self):
        deps, remote, issues = pool.setup_requirements_from_sources(
            'setup(install_requires=run_untrusted_setup())',
            lambda name, required=False: 'bad')
        self.assertFalse(deps); self.assertFalse(remote); self.assertTrue(issues)

    def test_git_project_with_tool_only_pyproject_still_parses_setup(self):
        with patch.object(pool, 'git_file', side_effect=lambda mirror, commit, path, **kwargs:
                {'pyproject.toml':'[tool.black]\nline-length=88\n',
                 'setup.py':'setup(install_requires=["dep==1.0"])\n'}.get(path)):
            deps,remote,issues = pool.git_requirements('unused','a'*40)
        self.assertEqual(deps,{'dep==1.0'})
        self.assertEqual(remote,set()); self.assertEqual(issues,[])

    def test_git_project_with_pep508_nested_reference(self):
        with patch.object(pool, 'git_file', side_effect=lambda mirror, commit, path, **kwargs:
                {'pyproject.toml':('[project]\nname="thing"\n'
                    'dependencies=["other @ git+https://github.com/example/other.git@'
                    + 'a'*40 + '"]\n')}.get(path)):
            deps,remote,issues = pool.git_requirements('unused','a'*40)
        self.assertEqual(deps,set()); self.assertEqual(issues,[])
        self.assertEqual(len(remote),1)

    def test_no_deps_is_not_dropped_by_pip_parser(self):
        _,_,_,problems,_,_,steps = pool.pip_commands(['python -m pip install --no-deps -e .'])
        self.assertEqual(problems,[])
        self.assertEqual(len(steps),1)
        self.assertTrue(steps[0]['no_deps'])

    def test_version_refs_are_derived_from_source_metadata_not_repository_name(self):
        mirror=Path('/tmp/mirror')
        repo='example/project'
        pinned='b'*40
        def fake(args,**kwargs):
            if 'show-ref' not in args:
                raise AssertionError('unexpected Git command '+str(args))
            return ('a'*40)+' refs/tags/v1\n'
        # Freeze tags through the actual _git_fetch entry point. Invoking a
        # real Git subprocess against a fabricated mirror is not a unit test.
        with patch.object(pool,'_source_requires_version_refs',return_value=True) as needs_refs, \
             patch.object(pool,'_git_fetch') as fetch_tags, \
             patch.object(pool,'invoke',side_effect=fake) as invoke_git:
            refs=pool.ensure_version_refs(mirror,repo,{pinned})
        self.assertEqual(refs,{'refs/tags/v1':'a'*40})
        needs_refs.assert_called_once_with(mirror,pinned)
        fetch_tags.assert_called_once_with(
            mirror,repo,['+refs/tags/*:refs/tags/*'],explicit_tags=True)
        invoke_git.assert_called_once_with(
            ['git','--git-dir',mirror,'show-ref','--tags','-d'],capture=True)
        source=(ROOT/'scripts/superbench_pool.py').read_text()
        self.assertNotIn("repo in {'bokeh/bokeh','pandas-dev/pandas'}",source)

    def test_version_refs_skip_git_network_when_source_does_not_need_tags(self):
        with patch.object(pool,'_source_requires_version_refs',return_value=False), \
             patch.object(pool,'_git_fetch',side_effect=AssertionError('unexpected Git network')), \
             patch.object(pool,'invoke',side_effect=AssertionError('unexpected Git command')):
            self.assertEqual(pool.ensure_version_refs(
                Path('/tmp/mirror'),'example/project',{'b'*40}),{})

    def test_published_contract_cannot_be_empty_cas(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp)
            (stage/'metadata').mkdir()
            candidate=pool.Pool(stage)
            with self.assertRaisesRegex(RuntimeError,'incomplete dependency closure'):
                pool.audit_inventory(candidate,{}, {}, {}, 'a'*64)
            inventory=json.loads((stage/'inventory.json').read_text())
            self.assertFalse(inventory['complete'])
            self.assertTrue(any('no acquired content-addressed objects' in x for x in inventory['issues']))

    def test_broker_does_not_export_credential_environment(self):
        broker=(ROOT/'apps/workstation-broker/src/workstation_broker/preparation.py').read_text()
        physical=broker.split('def _prepare(manager, state):',1)[1].split('def worker(operation_id, slot_fd):',1)[0]
        self.assertNotIn('os.environ.copy()',physical)
        self.assertNotIn('dict(os.environ',physical)
        self.assertIn('PIP_CONFIG_FILE',physical)
        self.assertIn('acquisition_timeout = acquisition_job_timeout_seconds(manager.source_root)',physical)
        self.assertIn('child.wait(timeout=acquisition_timeout)',physical)
        import tomllib
        from workstation_broker.preparation import acquisition_job_timeout_seconds
        controls = tomllib.loads((ROOT/'config/preparation.toml').read_text())
        self.assertEqual(acquisition_job_timeout_seconds(ROOT), controls['acquisition']['job_timeout_hours'] * 3600)
        self.assertIn('os.killpg(child.pid, signal.SIGKILL)',physical)

    def test_conda_lock_downloads_each_sha_once_and_materializes_transactions(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp)
            for name in ('objects','downloads','metadata'):(stage/name).mkdir()
            candidate=pool.Pool(stage)
            one=b'archive-one';two=b'archive-two'
            sha1=hashlib.sha256(one).hexdigest();sha2=hashlib.sha256(two).hexdigest()
            lock={'artifacts':{
                sha1:{'name':'python','version':'3.10.1','build':'x','url':'https://conda.anaconda.org/conda-forge/linux-64/python-3.10.1-x.conda','sha256':sha1,'channel':'https://conda.anaconda.org/conda-forge/linux-64','subdir':'linux-64'},
                sha2:{'name':'pip','version':'24.0','build':'y','url':'https://conda.anaconda.org/conda-forge/noarch/pip-24.0-y.conda','sha256':sha2,'channel':'https://conda.anaconda.org/conda-forge/noarch','subdir':'noarch'}},
                'environments':{
                    'a':{'transactions':[{'key':'env-a','python':'3.10','packages':[sha1,sha2]}]},
                    'b':{'transactions':[{'key':'env-b','python':'3.10','packages':[sha1]}]}}}
            payload={lock['artifacts'][sha1]['url']:one,lock['artifacts'][sha2]['url']:two}
            calls=[]
            def network(url,path,*,sha=None,sri=None,limit=2**37,integrity_digests=None,on_block=None):
                calls.append(url);Path(path).write_bytes(payload[url])
                if on_block is not None:on_block(len(payload[url]))
                actual=hashlib.sha256(payload[url]).hexdigest()
                self.assertEqual(actual,sha);return actual
            with patch.object(pool,'fetch',side_effect=network):
                plans,base=pool.acquire_locked_conda(candidate,lock)
            self.assertEqual(set(calls),set(payload));self.assertEqual(len(calls),2)
            self.assertEqual(plans,{'a':['env-a'],'b':['env-b']})
            self.assertEqual(base,{'a':'3.10','b':'3.10'})
            self.assertTrue((stage/'metadata/conda-env-a.json').is_file())
            self.assertTrue((stage/'metadata/conda-env-b.json').is_file())
            self.assertEqual(set(candidate.provenance['conda']),{'env-a','env-b'})

class TestContractClosureRegressionV4(unittest.TestCase):
    def test_contract_direct_conda_create_covers_all_five_non_yaml_envs(self):
        contract = json.loads((ROOT / 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/contract.json').read_bytes())
        direct = {}
        tasks = {}
        for env, entry in contract['environments'].items():
            if pool.conda_yaml(entry['original_script']) is None:
                direct[env] = pool.conda_direct_specs(entry['original_script'])
        for task in contract['tasks'].values():
            tasks[task['env_hash']] = tasks.get(task['env_hash'], 0) + 1
        self.assertEqual(len(direct), 5)
        self.assertEqual(sum(tasks[env] for env in direct), 205)
        self.assertEqual({tuple(value) for value in direct.values()},
                         {('python=3.8',),('python=3.9',),('python=3.10',),
                          ('python=3.11',),('python=3.12',)})

    def test_contract_post_create_conda_overrides_are_detected_as_separate_transactions(self):
        contract = json.loads((ROOT / 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/contract.json').read_bytes())
        post = {env: pool.conda_post_install_specs(entry['original_script'])
                for env, entry in contract['environments'].items()}
        post = {env: value for env, value in post.items() if value}
        self.assertEqual(len(post), 5)
        self.assertTrue(all(len(value) == 1 for value in post.values()))
        self.assertEqual(sorted(value[0][0] for value in post.values()),
                         ['python=3.10','python=3.9','python=3.9','python=3.9','python=3.9'])

    def test_committed_conda_lock_covers_all_25_envs_and_30_transactions(self):
        adapter=ROOT/'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym'
        pins=json.loads((adapter/'pins.json').read_bytes())
        contract=json.loads((adapter/'contract.json').read_bytes())
        lock,lock_sha=pool.load_conda_lock(adapter,pins,contract)
        self.assertRegex(lock_sha,r'^[0-9a-f]{64}$')
        self.assertEqual(len(lock['environments']),25)
        self.assertEqual(sum(len(row['transactions']) for row in lock['environments'].values()),30)
        self.assertEqual(set(row['transactions'][-1]['python'] for row in lock['environments'].values()),set(pool.PYTHONS))
        source=(ROOT/'scripts/superbench_pool.py').read_text()
        self.assertNotIn('micromamba',source.lower())
        self.assertNotIn('def conda_resolve(',source)

    def test_contract_environment_pip_phase_precedes_python_override(self):
        adapter=ROOT/'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym'
        contract = json.loads((adapter/'contract.json').read_bytes())
        pins = json.loads((adapter/'pins.json').read_bytes())
        lock,_ = pool.load_conda_lock(adapter,pins,contract)
        phased=[]
        for env,entry in contract['environments'].items():
            content=pool.conda_yaml(entry['original_script'])
            if not content: continue
            _,pips=pool.conda_pip_split(content)
            post=pool.conda_post_install_specs(entry['original_script'])
            if pips and post: phased.append((env,pips,post))
        self.assertEqual(len(phased),5)
        for env,rows,post in phased:
            self.assertTrue(rows and post)
            self.assertEqual(len(lock['environments'][env]['transactions']),2)
        source=(ROOT/'scripts/superbench_pool.py').read_text()
        self.assertIn("base_target_by_env[env]=transaction_targets[row['transactions'][0]['key']]",source)
        self.assertIn('acquire_locked_conda(pool,conda_lock)',source)
        self.assertIn("bucket='environment'",source)

    def test_poetry_isort_optional_dependencies_do_not_become_invalid_pip_specs(self):
        pyproject = """[tool.poetry]
name="isort"
version="4.3.21"
[tool.poetry.dependencies]
python="^3.6"
appdirs={version="^1.4.0", optional=true}
pipreqs={version="*", optional=true}
tomlkit={version="0.5.3", optional=true}
[tool.poetry.extras]
xdg_home=["appdirs"]
[build-system]
requires=["poetry>=0.12"]
build-backend="poetry.masonry.api"
"""
        deps, vcs, issues = pool.static_project(pyproject)
        self.assertEqual(issues, [])
        self.assertEqual(vcs, set())
        self.assertEqual(deps, {'poetry>=0.12'})
        deps, _, issues = pool.static_project(pyproject, extra_groups={'xdg_home'})
        self.assertEqual(issues, [])
        self.assertIn('appdirs>=1.4.0,<2.0.0', deps)

    def test_dvc_shell_chain_keeps_second_and_command_and_optional_true_steps(self):
        command = ('python -m pip install "cython<3.0.0" && '
                   'python -m pip install --no-build-isolation pyyaml==5.4.1; '
                   'python -m pip install -r test-requirements.txt || true')
        _, _, _, issues, _, _, steps = pool.pip_commands([command])
        self.assertEqual(issues, [])
        self.assertEqual(len(steps), 3)
        self.assertEqual(steps[0]['requirements'], {'cython<3.0.0'})
        self.assertEqual(steps[1]['requirements'], {'pyyaml==5.4.1'})
        self.assertFalse(steps[1]['optional'])
        self.assertEqual(steps[2]['files'], {'test-requirements.txt'})
        self.assertTrue(steps[2]['optional'])

    def test_dvc_setup_extras_resolve_all_remote_lists_without_execution(self):
        setup = """from setuptools import setup
install_requires=["ply>=3.9"]
gs=["google-cloud-storage==1.13.0"]
s3=["boto3==1.7.4"]
azure=["azure-storage-blob==1.3.0"]
ssh=["paramiko>=2.4.1"]
all_remotes=gs+s3+azure+ssh
setup(install_requires=install_requires,
      extras_require={"all":all_remotes,"gs":gs,"s3":s3,"azure":azure,"ssh":ssh})
"""
        deps, issues = pool.setup_static(
            setup, extras={'tests','dev','all_remotes','all','testing'})
        self.assertEqual(issues, [])
        self.assertTrue({'google-cloud-storage==1.13.0','boto3==1.7.4',
                         'azure-storage-blob==1.3.0','paramiko>=2.4.1'} <= deps)

    def test_modin_spreadsheet_setup_args_reads_pinned_requirements(self):
        setup = """def read_requirements(basename): pass
reqs = read_requirements("requirements.txt")
setup_args = {"install_requires": reqs}
setup(version=get_version(), **setup_args)
"""
        files = {'requirements.txt':'jupyter>=1.0.0\nnotebook>=6.0.3\nipywidgets>=7.0.0\n'}
        deps, remote, issues = pool.setup_requirements_from_sources(
            setup, lambda name, required=False: files.get(name))
        self.assertEqual(issues, [])
        self.assertEqual(remote, set())
        self.assertEqual(deps, {'jupyter>=1.0.0','notebook>=6.0.3','ipywidgets>=7.0.0'})

    def test_mock_ssh_server_file_backed_requirements_are_static(self):
        setup = """def read_requirements():
    with open("requirements.txt") as stream:
        return stream.read().splitlines()
setup(install_requires=read_requirements())
"""
        files = {'requirements.txt':'paramiko>=2.1\ncryptography>=1.5\n'}
        deps, remote, issues = pool.setup_requirements_from_sources(
            setup, lambda name, required=False: files.get(name))
        self.assertEqual(issues, [])
        self.assertEqual(remote, set())
        self.assertEqual(deps, {'paramiko>=2.1','cryptography>=1.5'})

    def test_normal_install_does_not_require_setup_tests_require(self):
        setup = """from setuptools import setup
def run_setup():
    tests_require = read_tests()
    setup(install_requires=["six>=1.4"], tests_require=tests_require)
"""
        deps, issues = pool.setup_static(setup)
        self.assertEqual(deps, {'six>=1.4'})
        self.assertEqual(issues, [])

    def test_contract_apt_upgrade_is_explicitly_identified_for_64_tasks(self):
        contract = json.loads((ROOT / 'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/contract.json').read_bytes())
        upgrade = []
        packages = set()
        for logical, task in contract['tasks'].items():
            found, verbs = pool.apt_recipe_operations(task['repo_script_list'])
            packages.update(found)
            if verbs: upgrade.append(logical)
        self.assertEqual(len(upgrade), 64)
        self.assertTrue({'cmake','build-essential','openjdk-17-jdk',
                         'openjdk-17-jre','libpq-dev'} <= packages)

    def test_vcs_npm_resolution_is_lock_only_and_ignores_scripts(self):
        package = json.dumps({'name':'fixture','version':'1.0.0',
                              'dependencies':{'dep':'^1.0.0'}})
        integrity = 'sha512-' + __import__('base64').b64encode(
            hashlib.sha512(b'archive').digest()).decode()
        with tempfile.TemporaryDirectory() as tmp:
            candidate = pool.Pool(Path(tmp))
            (Path(tmp)/'npm').mkdir()
            (Path(tmp)/'metadata').mkdir()
            commands = []
            def git_source(mirror, commit, path, **kwargs):
                return package if path == 'package.json' else None
            def run(candidate_pool, args, *, cwd, env, timeout=1800):
                commands.append([str(x) for x in args])
                lock={'packages':{'':{'name':'fixture','version':'1.0.0'},
                                  'node_modules/dep':{
                                      'version':'1.2.3',
                                      'resolved':'https://registry.npmjs.org/dep/-/dep-1.2.3.tgz',
                                      'integrity':integrity}}}
                (Path(cwd)/'package-lock.json').write_text(json.dumps(lock))
                return ''
            with patch.object(pool,'git_files_named',return_value=['package.json']), \
                 patch.object(pool,'git_file',side_effect=git_source), \
                 patch.object(pool,'_run_pinned_npm',side_effect=run), \
                 patch.object(candidate,'download',return_value='a'*64), \
                 patch.object(pool,'_pinned_npm_version',return_value='10.9.9'):
                artifacts=pool.npm_package_json_closure(
                    candidate,'mirror','b'*40,'owner/repo','identity')
            self.assertEqual(len(artifacts),1)
            flat=' '.join(commands[0])
            self.assertIn('--package-lock-only',flat)
            self.assertIn('--ignore-scripts',flat)
            self.assertEqual(list((Path(tmp)/'npm').iterdir()), [])
            self.assertNotIn("invoke(['npm'", (ROOT/'scripts/superbench_pool.py').read_text())

    def test_pip_parallelism_uses_versioned_io_capacity_not_cpu_affinity(self):
        controls=tomllib.loads((ROOT/'config/preparation.toml').read_text())
        configured=controls['acquisition']['workers']
        self.assertEqual(pool._metadata_prefetch_width(configured,configured),1)
        with patch.object(pool.os,'sched_getaffinity',side_effect=AssertionError('CPU affinity must not throttle network I/O')):
            self.assertEqual(pool._pip_worker_controls(),(configured,configured))
        source=(ROOT/'scripts/superbench_pool.py').read_text()
        self.assertIn("config/preparation.toml",source)
        # HTTP acquisition capacity is configured independently from CPU affinity.
        # Git mirror acquisition legitimately consults affinity for pack inflation,
        # so a global source-string prohibition is incorrect.
        import inspect
        io_functions=(pool._acquisition_workers,pool._pip_worker_controls,
                      pool._metadata_prefetch_width,pool.acquire_locked_conda,
                      pool.acquire_pip_groups,pool._download_sri_closure)
        for function in io_functions:
            with self.subTest(function=function.__name__):
                self.assertNotIn('sched_getaffinity',inspect.getsource(function))
        self.assertNotIn("CONDA_LOCK_WORKERS",source)
        self.assertIn("_download_sri_closure(pool,npm_urls,'npm')",source)
        self.assertIn("_acquire_git_mirrors(stage,submodule_commits,label='git-extra')",source)
        self.assertNotIn("pip_closure_workers",source)
        self.assertNotIn("pip_metadata_workers",source)

    def test_pip_parallelism_requires_versioned_acquisition_capacity(self):
        original=pool.__file__
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);(root/'scripts').mkdir();(root/'config').mkdir()
                fake=root/'scripts/superbench_pool.py';fake.write_text('# fixture')
                pool.__file__=str(fake);pool._acquisition_workers.cache_clear()
                with self.assertRaisesRegex(RuntimeError,'missing staged preparation controls'):
                    pool._acquisition_workers()
                (root/'config/preparation.toml').write_text('[acquisition]\nworkers = 0\n')
                pool._acquisition_workers.cache_clear()
                with self.assertRaisesRegex(RuntimeError,'invalid acquisition worker control'):
                    pool._acquisition_workers()
        finally:
            pool.__file__=original;pool._acquisition_workers.cache_clear()

    def test_execution_host_requirements_include_fetch_runtime(self):
        requirements=(ROOT/'requirements.txt').read_text().splitlines()
        self.assertIn('python3-pip', requirements)
        self.assertIn('openssl', requirements)
        self.assertIn('nodejs', requirements)
        self.assertIn('npm', requirements)


    def test_npm_cli_version_is_derived_from_verified_golden_dependency_identity(self):
        dependency={'schema':1,'target_environment':{'schema':2},'npm_version':'10.9.9'}
        with patch.object(pool,'_golden_dependency',return_value=dependency):
            self.assertEqual(pool._pinned_npm_version(),'10.9.9')
        source=(ROOT/'scripts/superbench_pool.py').read_text()
        self.assertNotIn('NPM_NODE18_VERSION',source)
        self.assertNotIn('registry.npmjs.org/npm/latest',source)
        self.assertNotIn('config/distributed.toml',source)
        self.assertIn('golden-dependency.json',source)
        self.assertIn('_pinned_npm_version()',source)

    def test_pipx_application_uses_verified_golden_target_not_testbed_minor(self):
        dependency={'schema':1,'target_environment':{
            'schema':2,'markers':{'python_full_version':'3.13.7'}},'npm_version':'10.9.9'}
        with patch.object(pool,'_golden_dependency',return_value=dependency):
            self.assertEqual(pool._golden_system_python(),'3.13.7')
        source=(ROOT/'scripts/superbench_pool.py').read_text()
        self.assertNotIn('GOLDEN_SYSTEM_PYTHON',source)
        self.assertIn('resolver_target=golden_target',source)
        guest=(ROOT/'apps/runner/src/gpt_trace_runner/superbench/adapters/swe_gym/guest_runtime.py').read_text()
        self.assertNotIn('--python /usr/bin/python3',guest)
        self.assertIn('shutil.which("python3")',guest)



if __name__ == '__main__':
    unittest.main()
