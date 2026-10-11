# GPT Trace Extractor for Cyber Benchmarking

This project runs benchmarks through the ChatGPT web UI, captures tool trajectories, and stores every exportable trajectory in one canonical Parquet corpus. The teacher browser and storage/control services run in Docker. A trusted host broker creates one disposable KVM/QEMU Kali workstation per model attempt. The single local MCP App is `kali-workstation` 3.0.0.

SWE-Gym Lite uses the same teacher and App with pinned native grading and immutable
common/repo VM templates, host-only task-scoped sources, and a fresh isolated
evaluator for native grading. Recipe/schema/adapter version 2 rejects old unsafe
Lite generations. See [the publication, installation and recovery guide](docs/swe-gym-lite.md).

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

Every Make operation reads `config/distributed.toml`. On Acer, `build` installs the native broker, verifies/installs the permanent Kali golden, retrieves the matching immutable Lite Release and installs the systemd unit. `up` starts only this broker; `doctor` validates its storage/images/inventory. On Fossil, `build` builds only control-plane Docker images and initializes only new empty storage; `up` starts PostgreSQL, storage, the ChatGPT teacher browser and MCP services. Fossil never probes or starts KVM. Acer never starts these control-plane services.

Provision the private mTLS configuration first using [the distributed guide](docs/distributed.md), then run Acer's `build`/`up` before Fossil's `build`/`up`. Fossil owns `run`, `resume`, App registration, manual Kali orchestration and export. Its `doctor` also runs the real runtime smoke against Acer. `make down` runs on Fossil and coordinates authenticated, owned-resource cleanup on Acer before stopping Fossil services. It preserves database/profile/source volumes, journals, checkpoints and permanent images; uncertain remote cleanup is an error. Acer rejects control-plane operations and local-only shutdown.

Put deployment-local values in `.env` using `.env.example`: PostgreSQL password, the independent teacher-browser KasmVNC password, `TEACHER_BROWSER_TUNNEL_TOKEN`, the non-secret `TEACHER_BROWSER_PUBLIC_URL` for the Cloudflare Kasm hostname, control plane API key, optional benchmark source token, and `APP_KALI_WORKSTATION_TUNNEL_ID`. Other non-secret runner/workstation settings remain versioned in `config/runner.toml`. Docker Compose injects `TEACHER_BROWSER_PUBLIC_URL` into runner containers, so `make auth` uses the deployment hostname without hardcoding it in TOML. The App registry and manifest live in `apps/registry/` and `apps/kali-workstation/`.

On Acer, root `requirements.txt` is deliberately a Debian/Ubuntu **system-package** manifest, not a pip file. Fossil instead uses `requirements-control.txt`, which has no libvirt/QEMU/nftables dependency. `requirements-golden-build.txt` adds the heavier `libguestfs-tools` and `p7zip-full` packages used only on a machine that locally builds/publishes the Kali golden. Application Python dependencies stay in Docker, and Kali guest dependencies stay in the image lock. `make build` fails before creating artifacts if a listed runtime package, a functional Python `venv`/`ensurepip`, Docker Engine, Compose, or Buildx is missing, and prints the exact `apt-get install` command for missing host packages.

## Kali golden image

Benchmark hosts do not build Kali locally. The heavy provisioning path is built once and published to Docker Hub under `aad7xppz4fd4r8emr/gpt-trace-kali-golden`. The tag is derived from the full `golden_build_input_sha256`, so a checkout automatically requests the image matching its exact guest source, lockfile, provisioning script, Kali source pin, and package set. Acer `make build` pulls that image, copies the four verified artifacts into `/var/lib/libvirt/images/gpt-trace/`, verifies the qcow2 and package/provenance hashes, and retains the permanent installed disk. Publication and installation never run on Fossil.

To publish a golden after changing any guest-image input, use a separate build-capable KVM host, authenticate Docker first, then run:

```bash
sudo make publish-kali-golden
```

That target checks `requirements.txt` plus `requirements-golden-build.txt`, performs the existing real-KVM Kali provisioning, verifies the resulting qcow2, packages `kali-base.qcow2`, `kali-base.provenance.json`, `kali-packages.txt`, and `kali-python-packages.txt` into the Docker image, and pushes the deterministic tag.

The teacher browser is the `teacher-browser` Compose service, with identity in the persistent `browser_profile` volume. It drives the ChatGPT UI only. KasmVNC now listens only inside that container on TCP 6902 with its existing HTTPS Basic Auth. A same-container HTTPS auth proxy listens on TCP 6901 and is the only browser-facing endpoint: it shows a normal HTML password form, issues a signed `Secure`/`HttpOnly`/`SameSite=Strict` session cookie, forwards authenticated HTTP and WebSocket traffic to KasmVNC, and injects the internal `kasm_user` Basic credential. This removes the dependency on inconsistent native HTTP Basic Auth dialogs in Chromium- and Firefox-derived browsers while preserving KasmVNC's internal authwall. The `teacher-browser-tunnel` Compose service still connects to `https://teacher-browser:6901`, so the remotely managed Cloudflare Tunnel hostname/origin does not change; keep `No TLS Verify` enabled because the proxy reuses the container-local self-signed certificate. Put the tunnel token in `TEACHER_BROWSER_TUNNEL_TOKEN` and the same public HTTPS URL in `.env` as `TEACHER_BROWSER_PUBLIC_URL`. Sign in to the HTML page with `TEACHER_BROWSER_PASSWORD`, then authenticate to ChatGPT separately inside CloakBrowser. The ChatGPT cookies/session remain in `browser_profile`. CDP stays host-loopback-only on port 9222 and the clipboard helper stays Docker-internal. The agent browser, shell, interactive Unix PTY and desktop all run in the same disposable Kali VM. Its workspace is `/home/kali/workspace`, its Downloads folder is `/home/kali/Downloads`, and a new attempt uses a fresh qcow2 overlay over the immutable golden disk. The Fossil runner uses a private mTLS broker connection with an admin certificate/token; the MCP controller receives a separate data-plane certificate/token. Neither receives Docker or libvirt access, and neither mounts an Acer Unix socket.

See [workstation architecture and operations](docs/workstation.md), [tool surface](docs/tools.md), and [artifact transfer](docs/file-transfer.md). Acer needs KVM/libvirt, nftables, and adequate local SSD space; on a VMware Ubuntu development VM, enable nested virtualization. The guest has NAT egress to public IPv4 addresses and cannot route to private control networks by default.

`make run` freezes selected task IDs and task/App/config fingerprints. Pause, resume, recovery, status, evaluation, and unfiltered Parquet export remain managed by the runner and storage service.

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

## Deployment on Fossil and Acer

The single historical Make interface dispatches automatically from the local role configuration. See [distributed operations](docs/distributed.md) for PKI, migration, immutable publication and physical acceptance. No host-prefixed Make targets exist.

`make export-parquet` exports every captured, exportable PostgreSQL trajectory regardless of execution status or native verdict, including failed and unevaluated captures. It retains normalized messages/tool calls/results, original messages, App provenance, metadata, evaluations and tool-coherence diagnostics. Invalid data aborts the atomic export; no trajectory is silently dropped by a verdict filter.
