"""Download-only SWE-Gym Lite fetcher regression tests; no network/KVM/VM."""
from __future__ import annotations
import hashlib
import contextlib
import io
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('superbench_pool_under_test', ROOT / 'scripts/superbench_pool.py')
pool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pool)


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
    def test_non_exact_source_only_requirement_uses_static_resolver_stub(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            candidate = pool.Pool(Path(tmp))
            (Path(tmp) / 'metadata').mkdir()
            (Path(tmp) / 'wheels').mkdir()
            calls = []
            def pipeline(argv, **kwargs):
                calls.append(argv)
                if len(calls) == 1:
                    return subprocess.CompletedProcess(argv, 1,
                        stdout='ERROR: Could not find a version that satisfies the requirement collective.checkdocs (from versions: none)\n')
                return subprocess.CompletedProcess(argv, 0, stdout='')
            source = {'name':'collective.checkdocs','version':'0.2.1',
                      'requested':'collective.checkdocs','filename':'collective.checkdocs-0.2.1.tar.gz',
                      'sha256':'1'*64,'requirements':['setuptools'],'provides_extra':[]}
            with patch.object(pool.subprocess, 'run', side_effect=pipeline), \
                 patch.object(pool, 'acquire_source_distribution', return_value=source) as acquire:
                pool.pip_closure(candidate, '3.10', {'collective.checkdocs'}, 'plan-key')
            plan = json.loads((Path(tmp) / 'metadata/pip-plan-plan-key.json').read_text())
            self.assertEqual(plan['artifact_model'], pool.PIP_ARTIFACT_MODEL)
            self.assertEqual(plan['source_archives'], [source])
            self.assertEqual(plan['files'], [])
            self.assertEqual(len(calls), 2)
            self.assertNotIn('--no-cache-dir', calls[0])
            acquire.assert_called_once_with(candidate, 'collective.checkdocs', 'plan-key', '3.10', constraints=())

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
                result=pool.acquire_source_distribution(candidate,'omegaconf==2.0.6','plan','3.8')
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
                _,selected,_=pool._select_source_release(candidate,'demo>1,<2','3.10')
        self.assertEqual(selected,'1.9')

    def test_source_range_without_cache_selects_lowest_compatible_not_latest(self):
        def release(version):
            return [{'packagetype':'sdist','filename':f'demo-{version}.tar.gz',
                     'url':f'https://files.pythonhosted.org/packages/demo-{version}.tar.gz',
                     'digests':{'sha256':hashlib.sha256(version.encode()).hexdigest()},
                     'requires_python':'>=3.8'}]
        project={'releases':{'1.4':release('1.4'),'1.5':release('1.5'),'1.9':release('1.9'),'2.0':release('2.0')}}
        with tempfile.TemporaryDirectory() as tmp:
            candidate=pool.Pool(Path(tmp))
            with patch.object(pool,'_pypi_json',return_value=project):
                _,selected,_=pool._select_source_release(candidate,'demo>1.4,<2','3.10')
        self.assertEqual(selected,'1.5')

    def test_source_greater_equal_uses_exact_lower_release_when_available(self):
        def release(version):
            return [{'packagetype':'sdist','filename':f'demo-{version}.tar.gz',
                     'url':f'https://files.pythonhosted.org/packages/demo-{version}.tar.gz',
                     'digests':{'sha256':hashlib.sha256(version.encode()).hexdigest()},
                     'requires_python':'>=3.8'}]
        project={'releases':{'5.1':release('5.1'),'5.2':release('5.2'),'6.0':release('6.0')}}
        with tempfile.TemporaryDirectory() as tmp:
            candidate=pool.Pool(Path(tmp))
            with patch.object(pool,'_pypi_json',return_value=project):
                _,selected,_=pool._select_source_release(candidate,'demo>=5.1','3.10')
        self.assertEqual(selected,'5.1')

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
                 patch.object(pool.subprocess, 'check_output', side_effect=dpkg):
                pool.apt_closure(candidate, {'testpkg'})
            self.assertEqual(json.loads((stage / 'metadata/apt-closure.json').read_text())['requested'], ['testpkg'])


# GPT_TRACE_SWEGYM_GLOBAL_ARTIFACT_POOL_V1
class TestGlobalPipArtifactPool(unittest.TestCase):
    def make_pool(self, root):
        root = Path(root)
        for name in ('metadata','wheels','downloads'):
            (root / name).mkdir(parents=True, exist_ok=True)
        return pool.Pool(root)

    def test_group_identity_is_not_task_or_optionality_scoped(self):
        one = pool.pip_group_key('3.10', {'pillow', 'pandas'}, {'numpy<2'}, False)
        two = pool.pip_group_key('3.10', {'pandas', 'pillow'}, {'numpy<2'}, False)
        self.assertEqual(one, two)
        self.assertEqual(
            one,
            hashlib.sha256(json.dumps(
                ['3.10', ['pandas','pillow'], ['numpy<2'], False, False],
                sort_keys=True).encode()).hexdigest()[:20],
        )

    def test_failed_resolver_attempt_promotes_finished_wheel_before_retry(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);candidate=self.make_pool(stage)
            payload=b'shared wheel bytes'
            filename='sharedpkg-1.0-py3-none-any.whl'
            calls=[]
            def pipeline(argv, **kwargs):
                calls.append((list(argv), kwargs))
                dest=Path(argv[argv.index('--dest')+1])
                if len(calls)==1:
                    (dest/filename).write_bytes(payload)
                    return subprocess.CompletedProcess(argv,1,stdout=(
                        'ERROR: Could not find a version that satisfies the requirement '
                        'collective.checkdocs (from versions: none)\n'))
                shared=stage/'wheels'/'shared'/filename
                self.assertTrue(shared.is_file())
                os.link(shared,dest/filename)
                return subprocess.CompletedProcess(argv,0,stdout='')
            source={'name':'collective.checkdocs','version':'0.2.1',
                    'requested':'collective.checkdocs','filename':'collective.checkdocs-0.2.1.tar.gz',
                    'sha256':'1'*64,'requirements':['setuptools'],'provides_extra':[]}
            with patch.object(pool.subprocess,'run',side_effect=pipeline), \
                 patch.object(pool,'acquire_source_distribution',return_value=source):
                pool.pip_closure(candidate,'3.10',{'sharedpkg','collective.checkdocs'},'group')
            sha=hashlib.sha256(payload).hexdigest()
            cas=candidate.objects/sha[:2]/sha
            shared=stage/'wheels'/'shared'/filename
            self.assertTrue(cas.is_file())
            self.assertTrue(shared.samefile(cas))
            self.assertFalse((stage/'wheels'/'group').exists())
            self.assertEqual(len(candidate.links),1)
            self.assertNotIn('PIP_NO_CACHE_DIR',calls[0][1]['env'])
            self.assertEqual(calls[0][1]['env']['PIP_CACHE_DIR'],str(candidate.pip_cache))
            plan=json.loads((stage/'metadata/pip-plan-group.json').read_text())
            self.assertEqual(plan['files'],[{'filename':filename,'sha256':sha}])

    def test_different_logical_closures_share_one_physical_wheel(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);candidate=self.make_pool(stage)
            payload=b'one universal wheel'
            filename='demo-1.0-py3-none-any.whl'
            def pipeline(argv, **kwargs):
                dest=Path(argv[argv.index('--dest')+1])
                shared=stage/'wheels'/'shared'/filename
                if shared.exists(): os.link(shared,dest/filename)
                else: (dest/filename).write_bytes(payload)
                return subprocess.CompletedProcess(argv,0,stdout='')
            with patch.object(pool.subprocess,'run',side_effect=pipeline):
                pool.pip_closure(candidate,'3.8',{'demo==1.0'},'first')
                pool.pip_closure(candidate,'3.10',{'demo==1.0'},'second')
            sha=hashlib.sha256(payload).hexdigest()
            self.assertEqual(set(candidate.links),{sha})
            self.assertEqual(set(candidate.provenance['python']),{'first','second'})
            self.assertTrue((stage/'wheels/shared'/filename).samefile(candidate.objects/sha[:2]/sha))
            self.assertFalse((stage/'wheels/first').exists())
            self.assertFalse((stage/'wheels/second').exists())

    def test_verified_completed_plan_reuses_cas_without_pip(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage=Path(tmp);candidate=self.make_pool(stage)
            payload=b'already acquired';sha=hashlib.sha256(payload).hexdigest()
            target=candidate.objects/sha[:2]/sha
            target.parent.mkdir(parents=True);target.write_bytes(payload)
            candidate.verified_objects.add(sha)
            key=pool.pip_group_key('3.10',{'demo==1'})
            plan={'artifact_model':pool.PIP_ARTIFACT_MODEL,'python':'3.10',
                  'requested':['demo==1'],'constraints':[],'no_deps':False,
                  'files':[{'filename':'demo-1-py3-none-any.whl','sha256':sha}],
                  'source_archives':[]}
            (stage/'metadata'/('pip-plan-'+key+'.json')).write_text(json.dumps(plan))
            with patch.object(pool.subprocess,'run',side_effect=AssertionError('pip must not run')):
                self.assertTrue(pool.reuse_pip_plan(candidate,'3.10',{'demo==1'},key))
            self.assertEqual(set(candidate.links),{sha})
            self.assertTrue((stage/'wheels/shared/demo-1-py3-none-any.whl').samefile(target))

    def test_resume_upgrades_only_verified_successful_legacy_plans(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);old=root/'old';new=root/'new'
            (old/'objects/sha256').mkdir(parents=True)
            (old/'metadata').mkdir();(old/'wheels/shared').mkdir(parents=True)
            (old/'STAGING').write_text('legacy')
            payload=b'legacy wheel';sha=hashlib.sha256(payload).hexdigest()
            obj=old/'objects/sha256'/sha[:2]/sha
            obj.parent.mkdir();obj.write_bytes(payload)
            os.link(obj,old/'wheels/shared/demo.whl')
            key=pool.pip_group_key('3.10',{'demo==1'})
            legacy={'python':'3.10','requested':['demo==1'],'constraints':[],
                    'no_deps':False,'files':[{'filename':'demo.whl','sha256':sha}],
                    'source_archives':[]}
            (old/'metadata'/('pip-plan-'+key+'.json')).write_text(json.dumps(legacy))
            failed={**legacy,'optional_failed':'old failure','files':[]}
            (old/'metadata/pip-plan-optional.json').write_text(json.dumps(failed))
            new.mkdir()
            for name in ('objects','metadata','wheels','downloads'):(new/name).mkdir(exist_ok=True)
            verified=pool.salvage_verified_stage(old,new)
            self.assertEqual(verified,{sha})
            adopted=json.loads((new/'metadata'/('pip-plan-'+key+'.json')).read_text())
            self.assertEqual(adopted['artifact_model'],pool.PIP_ARTIFACT_MODEL)
            self.assertFalse((new/'metadata/pip-plan-optional.json').exists())

    def test_required_group_failure_stops_before_later_groups(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate=self.make_pool(Path(tmp))
            groups={
                'a':{'version':'3.10','requirements':['broken'], 'constraints':[],
                     'no_deps':False,'required':True,'tasks':['task-a'],'steps':['install']},
                'b':{'version':'3.10','requirements':['later'], 'constraints':[],
                     'no_deps':False,'required':True,'tasks':['task-b'],'steps':['install']},
            }
            with patch.object(pool,'pip_closure',side_effect=[RuntimeError('boom'),AssertionError('continued')]) as solve:
                with self.assertRaisesRegex(RuntimeError,'required pip closure a failed'):
                    pool.acquire_pip_groups(candidate,groups)
            self.assertEqual(solve.call_count,1)

    def test_required_network_acquisition_is_never_issue_accumulation(self):
        source=(ROOT/'scripts/superbench_pool.py').read_text()
        self.assertNotIn("pool.issue('pip:'",source)
        self.assertNotIn("pool.issue('APT'",source)
        self.assertNotIn("pool.issue('npm-global'",source)
        self.assertIn("raise RuntimeError('required VCS closure failed",source)
        self.assertIn('PIP_ARTIFACT_MODEL',source)


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

    def test_retryable_http_503_is_retried_for_metadata(self):
        url = 'https://pypi.org/pypi/demo/json'
        failure = pool.urllib.error.HTTPError(url, 503, 'service unavailable', {}, None)
        response = self.Response(url, [b'{"name":"demo"}'])
        with patch.object(pool.urllib.request, 'urlopen', side_effect=[failure, response]) as opener, \
             patch.object(pool.time, 'sleep') as sleeper:
            self.assertEqual(pool._pypi_json(url), {'name': 'demo'})
        self.assertEqual(opener.call_count, 2)
        sleeper.assert_called_once_with(1)

    def test_nonretryable_http_404_fails_immediately(self):
        url = 'https://pypi.org/pypi/missing/json'
        failure = pool.urllib.error.HTTPError(url, 404, 'missing', {}, None)
        with patch.object(pool.urllib.request, 'urlopen', side_effect=failure) as opener, \
             patch.object(pool.time, 'sleep') as sleeper, \
             self.assertRaises(pool.urllib.error.HTTPError):
            pool._pypi_json(url)
        self.assertEqual(opener.call_count, 1)
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
            record = {'operation_id': operation, 'complete': True, 'tasks':230, 'repos':11, 'conda_recipes':25}
            (ready/'inventory.json').write_text(json.dumps(record))
            expected = {'kind':'download-only-pool','complete':True,
                        'pool_directory':str(ready),'tasks':230,'repos':11,'conda_recipes':25}
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
        self.assertEqual(deps, {'requests>=2','bottle==0.12','pytest>=6'})

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

    def test_bokeh_requires_pinned_tags_in_git_mirror(self):
        calls=[]
        def fake(args,**kwargs):
            calls.append([str(x) for x in args])
            if 'tag' in args: return 'v1\nv2\nv3\nv4\nv5\n'
            return ''
        with tempfile.TemporaryDirectory() as tmp,patch.object(pool,'invoke',side_effect=fake):
            pool.mirror_commits(Path(tmp),'bokeh/bokeh',{'a'*40})
        self.assertTrue(any('+refs/tags/*:refs/tags/*' in c for c in calls))

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
        self.assertIn('child.wait(timeout=24 * 3600)',physical)
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
            def network(url,path,*,sha=None,sri=None,limit=2**37,integrity_digests=None):
                calls.append(url);Path(path).write_bytes(payload[url])
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
        self.assertIn('environment_pip_python[env]=locked_base_python[env]',source)
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
        setup = """def read_requirements(): pass
setup(install_requires=read_requirements())
# requirements.txt
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
            with patch.object(pool,'git_file',side_effect=git_source), \
                 patch.object(pool,'_run_pinned_npm',side_effect=run), \
                 patch.object(candidate,'download',return_value='a'*64):
                artifacts=pool.npm_package_json_closure(
                    candidate,'mirror','b'*40,'owner/repo','identity')
            self.assertEqual(len(artifacts),1)
            flat=' '.join(commands[0])
            self.assertIn('--package-lock-only',flat)
            self.assertIn('--ignore-scripts',flat)
            self.assertEqual(list((Path(tmp)/'npm').iterdir()), [])
            self.assertNotIn("invoke(['npm'", (ROOT/'scripts/superbench_pool.py').read_text())

    def test_execution_host_requirements_include_fetch_runtime(self):
        requirements=(ROOT/'requirements.txt').read_text().splitlines()
        self.assertIn('python3-pip', requirements)
        self.assertIn('openssl', requirements)
        self.assertIn('nodejs', requirements)
        self.assertIn('npm', requirements)


    def test_bokeh_npm_cli_is_pinned_to_node18_compatible_npm10(self):
        self.assertEqual(pool.NPM_NODE18_VERSION, '10.9.9')
        source=(ROOT/'scripts/superbench_pool.py').read_text()
        self.assertIn("'https://registry.npmjs.org/npm/'+NPM_NODE18_VERSION", source)
        self.assertNotIn("registry.npmjs.org/npm/latest", source)
        self.assertIn("_run_pinned_npm(pool", source)

    def test_pipx_application_uses_pinned_kali_system_python_not_testbed_python(self):
        self.assertEqual(pool.GOLDEN_SYSTEM_PYTHON, '3.13')
        source=(ROOT/'scripts/superbench_pool.py').read_text()
        self.assertIn("resolver_version=GOLDEN_SYSTEM_PYTHON", source)
        self.assertIn("pipx creates its application venv from Kali's system Python", source)



if __name__ == '__main__':
    unittest.main()
