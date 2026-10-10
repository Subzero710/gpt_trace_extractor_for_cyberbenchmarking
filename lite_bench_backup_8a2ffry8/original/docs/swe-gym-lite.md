# SWE-Gym Lite

`swe-gym-lite` uses the ordinary Kali Workstation App with runner-owned setup,
candidate capture and native grading. Template construction is a separate host
prerequisite. Campaigns never build missing permanent environments.

## Pinned sources and validated contract

| Input | Immutable identifier |
| --- | --- |
| [SWE-Gym/SWE-Gym-Lite](https://huggingface.co/datasets/SWE-Gym/SWE-Gym-Lite) revision | `f70b1a29ab120eb0a0ee7a1deb029825e735b2b0` |
| `data/train-00000-of-00001.parquet` SHA256 | `f3a7cd934e8cc523b6053298d0abb2c82fd7db2b83f9f2ccba5944545aaa4eb1` |
| [SWE-Gym/SWE-Bench-Package](https://github.com/SWE-Gym/SWE-Bench-Package) commit | `16dd480cce9b27bf111a362d280881c6def5d2a7` |
| Safe setup contract SHA256 | `fbb8b762277d09b6732a9697735889f761cf5d1920df0cafb5320809f834f38f` |
| Recipe / registry schema | `1` / `1` |
| Miniconda installer | `Miniconda3-py311_24.7.1-0-Linux-x86_64.sh` |
| Installer SHA256 | `a098a5b1581d8fd078c430b82e27106602223e335efef708a124e723814d120c` |

The actual pinned parquet and official recipe functions validate **230 tasks,
11 repos and 25 globally distinct environment hashes**, with zero unmapped tasks.
Hashes use exactly `sha256(str(env_script_list).encode("utf-8")).hexdigest()[:22]`
with the upstream name `testbed`. Ordered upstream environment-file path searches,
including 404 responses, are recorded at each exact `base_commit`. The builder
independently verifies those contents against Git objects and requires zero
missing base commits before publication.

| Repository | Tasks | Distinct envs within repo | Template suffix |
| --- | ---: | ---: | --- |
| Project-MONAI/MONAI | 27 | 1 | Project-MONAI_MONAI |
| bokeh/bokeh | 1 | 1 | bokeh_bokeh |
| conan-io/conan | 12 | 1 | conan-io_conan |
| dask/dask | 14 | 10 | dask_dask |
| facebookresearch/hydra | 11 | 1 | facebookresearch_hydra |
| getmoto/moto | 59 | 1 | getmoto_moto |
| iterative/dvc | 36 | 2 | iterative_dvc |
| modin-project/modin | 5 | 4 | modin-project_modin |
| pandas-dev/pandas | 5 | 5 | pandas-dev_pandas |
| pydantic/pydantic | 20 | 1 | pydantic_pydantic |
| python/mypy | 40 | 4 | python_mypy |

Some hashes are shared across repos. Template IDs prepend `swe-gym-lite/` to
these suffixes. The first 11 tasks cycle through all 11 repositories.

## Images, setup and trust

Every attempt uses `overlay -> repo.qcow2 -> common.qcow2 -> kali-base.qcow2`.
The common image contains all 25 environments under `swegym_<official_env_hash>`,
shared Conda/pip/npm/PDM/pipx caches, frozen public VCS dependencies, inventories
and safe recipes. Each of the 11 repo images adds its local Git mirror. Task
overlays receive a proper Conda clone named `testbed`, exact `/testbed` checkout,
and official repo installation. The teacher workspace links to that checkout;
login shells activate the environment. No benchmark MCP helpers are added.

The host builder runs one VM at a time, uses sparse QCOW2 files, grows the ext4
guest root partition/filesystem, monitors host free space, and reports virtual
and physical allocated sizes. The existing 64 GiB attempt reservation remains
separate from permanent template capacity.

Published paths are under
`/var/lib/libvirt/images/gpt-trace/templates/swe-gym-lite/generations/<generation>/`:
`common.qcow2`, `repos/<suffix>.qcow2`, `manifest.json`, and build logs.
The generation hashes source pins, installed Kali base, host/guest recipe bytes,
virtual capacity and installer digest. All images and generation directories
become read-only before atomic publication of `swe-gym-lite/registry.json`.

Publication requires complete mappings, inventories, commits, digests, QCOW2
checks and backing chains. All 230 official task setups are replayed in fresh
environments with networking disabled and compared with their build-time package
inventories. A historical recipe or missing-cache failure stops publication and
preserves its build disks/logs; it never replaces a good generation.

The broker accepts validated IDs only and rejects unknown IDs, traversal,
symlinks, mutable or modified images, and broken backing chains. Relative backing
filenames are resolved from the image directory. Attempt and domain metadata
record backing path/SHA256, template ID, generation and source fingerprint.
Recovery and cleanup verify the original recorded generation after publication
of a newer one. `workstation_template=None` retains normal Kali/GAIA behavior.

## Real-host commands

Use the dedicated Ubuntu/KVM host with the existing runtime requirements and
packages in `requirements-golden-build.txt`. The builder requires Docker, Git,
QEMU, `virt-customize` and `virt-cat`. Stop active/manual attempts before replacing
the installed Kali base.

```bash
make build
make superbench-fetch ADAPTER=swe-gym-lite
sudo make swe-gym-lite-templates
make template-doctor ADAPTER=swe-gym-lite
make doctor
make auth
make run ADAPTER=swe-gym-lite LIMIT=1
make status
```

Optional sparse capacity, margin and per-VM deadline:

```bash
sudo make swe-gym-lite-templates \
  TEMPLATE_BUILD_ARGS="--virtual-gib 512 --free-space-gib 64 --build-timeout-hours 96"
```

Read the builder's physical-size report. Failed `.build-<id>` directories retain
host logs and guest disks. Guest logs are in `/var/log/swe-gym-lite-builder.log`
and `/opt/swe-gym-lite/logs/`; inspect stopped images with `virt-cat`.

After a successful single-task smoke:

```bash
make run ADAPTER=swe-gym-lite LIMIT=11
make run ADAPTER=swe-gym-lite LIMIT=25
make run ADAPTER=swe-gym-lite
```

Completed rows are skipped under the existing contract checks. Each new campaign
preflights its selected immutable templates before committing active-run state
or connecting the teacher; unselected dataset sources are not discovered.

## Grading and recovery

The teacher receives public issue text and ordinary Kali tools. Gold code patches
never enter the guest. Hidden test/oracle data remain evaluator-side until the
teacher has finished and durable conversation/candidate checkpoints exist.

Capture uses a temporary Git index with `git add -A` and a binary diff against the
exact base, preserving the real index and including new files and deletions. A
clean checkout must accept the candidate. The exported bytes and SHA256 are
durable before grading starts. Evaluation recreates a separate checkout, applies
the exact persisted candidate, performs official setup, injects the hidden test
patch, runs the official command, and uses the pinned upstream log parser and
FAIL_TO_PASS/PASS_TO_PASS grading. Full logs remain artifacts; stored evaluation
metadata contains compact counts, identities, hashes and exit status.

| Event | Outcome |
| --- | --- |
| Native pass | Storage completed, evaluation `pass`, continue |
| Normally executed native benchmark reports incorrect candidate | Storage completed, evaluation `fail`, continue |
| Template/setup/capture/parser/broker/QEMU/storage error | Preserve running attempt and journal; `needs_intervention`; stop |
| First SIGINT/cooperative pause | Existing durable paused state |
| Rate limit | Existing durable Retry-After/defer behavior |

Preparation recovery reruns deterministic setup in the same attempt. Once
`submission_started` is durable, recovery never sends a duplicate task.
`conversation_checkpointed` loads the saved capture; `candidate_checkpointed`
also loads the exact persisted patch and recreates only the evaluator. Neither
phase resumes ChatGPT generation. Checkpoints are cleaned only after storage
completion and runtime cleanup. Conversation deletion connects the teacher
browser only after evaluation succeeds.

```bash
make status
make resume
```

Explicit abandonment of an irreparable attempt retries the same frozen task:

```bash
make reset-recovery TASK=<run_task_id_from_status>
make resume
```

Technical errors never automatically skip tasks or destroy diagnostic VMs.
`make auth` retains its refusal during an unfinished run; resolve authentication
in the operator browser and resume. Typed Parquet/SFT export remains compatible;
default SFT filtering retains native passes.

## Validation and operational limit

**314 tests passed** across runner, broker, Kali guest/controller and MCP gateway.
This includes the actual pinned parquet, official recipe/hash derivation, native
parsers, real Git candidate capture, backing selection/security, and recovery
barriers. Baseline fixtures were aligned with the already-current constructor,
GAIA Level-3 split, cookie-session endpoint and password-based KasmVNC auth;
behavioral model, rate-limit and tool assertions remain active.

With runner test dependencies and broker installed:

```bash
GPT_TRACE_SUPERBENCH_SOURCE_ROOT=/absolute/path/to/fetched/sources \
PYTHONPATH=apps/runner/src:apps/workstation-broker/src:apps/kali-workstation/src:apps/mcp-gateway/src \
python -m pytest apps/runner/tests apps/workstation-broker/tests \
  apps/kali-workstation/tests apps/mcp-gateway/tests -q
```

That directory must contain
`swe-gym-lite/train-00000-of-00001.parquet` with the pinned checksum. Without the
source-root variable, the live parquet test is skipped. Original pinned harness
escape-sequence syntax warnings are retained without altering upstream bytes.

No real host template generation or ChatGPT smoke campaign was executed in the
implementation workspace. The host commands must build and validate all 12
permanent images before a campaign starts. Fresh offline setup replay and native
end-to-end host execution remain operational acceptance checks.
