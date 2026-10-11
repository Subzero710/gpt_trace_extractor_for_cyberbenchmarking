# GPT Trace Extractor for Cyber Benchmarking

This project runs benchmarks through the ChatGPT web UI, captures tool trajectories, and stores every exportable trajectory in one canonical Parquet corpus. The teacher browser and storage/control services run in Docker. A trusted host broker creates one disposable KVM/QEMU Kali workstation per model attempt. The single local MCP App is `kali-workstation` 3.0.0.

SWE-Gym Lite uses the same teacher and App with pinned native grading and immutable
common/repo VM templates, host-only task-scoped sources, and a fresh isolated
evaluator for native grading. Recipe/schema/adapter version 2 rejects old unsafe
Lite generations. See [the local preparation and recovery guide](docs/swe-gym-lite.md).

## Workflow

```bash
make requirements  # optional explicit host preflight; make build runs it too
sudo make build
make up
make doctor
make tunnels
make auth
make superbench-fetch ADAPTER=gaia
make run ADAPTER=gaia
make pause
make resume
make status
make reset-recovery TASK=<run_task_id>
make export-parquet
make down
```

Every Make operation reads the committed `config/distributed.toml` plus host-local `.env` role and Cloudflare routing credentials. The execution host runs the native KVM broker and a dedicated Cloudflare Tunnel proxying its Unix socket. The control host connects over HTTPS using a Cloudflare Access Service Token and distinct broker admin/controller tokens; no LAN broker address or private PKI is needed. See [the deployment guide](docs/distributed.md).

Provision Cloudflare Access and the independent broker bearer tokens using [the distributed guide](docs/distributed.md), then run the execution host's `build`/`up` before the control host's `build`/`up`. The control host owns `run`, `resume`, App registration, manual Kali orchestration and export. Its `doctor` also runs the real runtime smoke against execution host. `make down` runs on the control host and coordinates authenticated, owned-resource cleanup on the execution host before stopping control host services. It preserves database/profile/source volumes, journals, checkpoints and permanent images; uncertain remote cleanup is an error. The execution host rejects control-plane operations. Its `make down` performs local cleanup and broker shutdown, explicitly reports `scope=execution-local; global=false`, and leaves control host campaign/services outside its scope.

Put deployment-local values in `.env` using `.env.example`: PostgreSQL password, the independent teacher-browser KasmVNC password, `TEACHER_BROWSER_TUNNEL_TOKEN`, the non-secret `TEACHER_BROWSER_PUBLIC_URL` for the Cloudflare Kasm hostname, control plane API key, optional benchmark source token, and `APP_KALI_WORKSTATION_TUNNEL_ID`. Other non-secret runner/workstation settings remain versioned in `config/runner.toml`. Docker Compose injects `TEACHER_BROWSER_PUBLIC_URL` into runner containers, so `make auth` uses the deployment hostname without hardcoding it in TOML. The App registry and manifest live in `apps/registry/` and `apps/kali-workstation/`.

On the execution host, root `requirements.txt` is deliberately a Debian/Ubuntu **system-package** manifest, not a pip file. The control host instead uses `requirements-control.txt`, which has no libvirt/QEMU/nftables dependency. `requirements-golden-build.txt` adds the heavier `libguestfs-tools` and `p7zip-full` packages required on the execution host for local golden and benchmark preparation. Application Python dependencies stay in Docker, and Kali guest dependencies stay in the image lock. `make build` fails before creating artifacts if a listed runtime package, a functional Python `venv`/`ensurepip`, Docker Engine, Compose, or Buildx is missing, and prints the exact `apt-get install` command for missing host packages.

## Kali golden image

The execution host builds the golden locally from the official Kali archive pinned by URL and SHA-256 in `infra/workstation/image/build.py`. Guest dependencies, browser and provisioning recipes retain their existing pins. The installed base and three provenance/package files become root-owned and read-only, with the base activated last from a durable verified installation journal. Interrupted activation resumes only from the exact prepared bytes; an invalid existing permanent image is preserved and rejected. Golden images remain on the execution host's SSD and are excluded from Git.

`sudo make build` on the execution host prepares the broker and this golden. `make up` starts the broker without constructing or downloading templates. On the control host, the only Lite preparation entry point is:

```bash
make superbench-fetch ADAPTER=swe-gym-lite
make run ADAPTER=swe-gym-lite LIMIT=1
```

Fetch verifies the official pinned 230-task dataset on the control host, identifies an administrative local preparation on the execution host over the Cloudflare Access channel, starts or rediscovers its finite worker and waits for validated activation. The execution host builds the 25 environments, 11 repository images and 230 scoped source/setup archives once. All image bytes remain on the execution host. Repeated fetch reuses verified permanent bytes; lost responses are rediscovered without blindly repeating mutations. `run` and `resume` cannot construct templates and fail with this fetch command when local artifacts are absent or incompatible.

## Manual Kali lifecycle

The OpenAI Secure MCP Tunnel and the Kali VM have separate lifecycles. `make tunnels` ensures the persistent tunnel is running and does **not** create a VM. If the tunnel container is already running with unchanged Compose configuration it is reused rather than recreated. Tunnel readiness means the tunnel-client process is live and an immediate read-only lookup of the configured tunnel succeeds against the OpenAI control plane; it does not wait for the normal 30-second command long-poll. `/readyz` may still report the MCP backend unavailable until a Kali runtime is attached. Benchmark entry points (`make run`, `make resume`, and `make auth`) ensure the tunnel is ready automatically.

For an operator-driven disposable Kali outside a benchmark:

```bash
make start_kali
make status_kali
# use @Kali Workstation from ChatGPT
make stop_kali
```

`start_kali` returns after the VM is ready; it does not keep a terminal process alive. Its identity is persisted atomically in the runner state volume, so `status_kali` and `stop_kali` work from a later Cockpit/SSH session. `stop_kali` resets the controller, detaches the gateway, destroys the libvirt attempt, verifies cleanup, and removes the persisted manual state. Manual Kali and Superbench ownership are mutually exclusive.

`make register_apps` is the separate interactive App-registration helper. It may create a temporary registration VM, but `make tunnels` never does.

## Deployment on the control host and execution host

The single historical Make interface dispatches automatically from the local role configuration. See [distributed operations](docs/distributed.md) for Cloudflare Access, migration, local preparation and physical acceptance. No host-prefixed Make targets exist.

`make export-parquet` exports every captured, exportable PostgreSQL trajectory regardless of execution status or native verdict, including failed and unevaluated captures. It retains normalized messages/tool calls/results, original messages, App provenance, metadata, evaluations and tool-coherence diagnostics. Invalid data aborts the atomic export; no trajectory is silently dropped by a verdict filter.

The shutdown admission barrier is durable across broker restarts. Explicit execution host `make up` reopens it only after the managed broker and confirmation child are stopped and a fresh ownership audit proves temporary project resources absent. It never repairs templates or destroys resources while starting.
