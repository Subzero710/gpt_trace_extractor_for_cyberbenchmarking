# GPT Trace Extractor for Cyber Benchmarking

This project runs benchmarks through the ChatGPT web UI, captures tool trajectories, and stores traces for SFT export. The teacher browser and storage/control services run in Docker. A trusted host broker creates one disposable KVM/QEMU Kali workstation per model attempt. The single local MCP App is `kali-workstation` 3.0.0.

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
make export-sft
make down
```

`doctor` checks the Ubuntu host, then creates and destroys dedicated VM smoke attempts through the runner. `build` first validates the host-only system package manifest plus Python venv and Docker Engine/Compose/Buildx, builds the host broker and trusted Docker images, verifies the MCP manifest inside the built controller image, then pulls the checksum-verified Kali golden disk prebuilt on Docker Hub. `up` starts the host broker plus persistent Docker services. `tunnels` starts/refreshes the OpenAI Secure MCP Tunnel without creating a Kali VM and validates readiness from tunnel-client liveness plus a successful OpenAI control-plane poll; the MCP readiness probe may remain red while no Kali backend is attached. `register_apps` is the separate interactive App-registration lifecycle. `down` destroys project-owned VM attempts and Docker execution containers without deleting database or teacher browser profile volumes. The host broker needs root privileges for loop mounts and nftables; run its lifecycle on a dedicated Ubuntu host with KVM.

Put deployment-local values in `.env` using `.env.example`: PostgreSQL password, the independent teacher-browser KasmVNC password, `TEACHER_BROWSER_TUNNEL_TOKEN`, the non-secret `TEACHER_BROWSER_PUBLIC_URL` for the Cloudflare Kasm hostname, control plane API key, optional benchmark source token, and `APP_KALI_WORKSTATION_TUNNEL_ID`. Other non-secret runner/workstation settings remain versioned in `config/runner.toml`. Docker Compose injects `TEACHER_BROWSER_PUBLIC_URL` into runner containers, so `make auth` uses the deployment hostname without hardcoding it in TOML. The App registry and manifest live in `apps/registry/` and `apps/kali-workstation/`.

Root `requirements.txt` is deliberately a Debian/Ubuntu **system-package** manifest, not a pip file. It contains only dependencies required by benchmark runtime hosts. `requirements-golden-build.txt` adds the heavier `libguestfs-tools` and `p7zip-full` packages used only on a machine that locally builds/publishes the Kali golden. Application Python dependencies stay in Docker, and Kali guest dependencies stay in the image lock. `make build` fails before creating artifacts if a listed runtime package, a functional Python `venv`/`ensurepip`, Docker Engine, Compose, or Buildx is missing, and prints the exact `apt-get install` command for missing host packages.

## Kali golden image

Benchmark hosts do not build Kali locally. The heavy provisioning path is built once and published to Docker Hub under `aad7xppz4fd4r8emr/gpt-trace-kali-golden`. The tag is derived from the full `golden_build_input_sha256`, so a checkout automatically requests the image matching its exact guest source, lockfile, provisioning script, Kali source pin, and package set. `make build` pulls that image, copies the four verified artifacts into `/var/lib/libvirt/images/gpt-trace/`, verifies the qcow2 and package/provenance hashes, then removes the pulled Docker image so the large qcow2 is not retained twice on the benchmark server.

To publish a golden after changing any guest-image input, use a separate build-capable KVM host, authenticate Docker first, then run:

```bash
sudo make publish-kali-golden
```

That target checks `requirements.txt` plus `requirements-golden-build.txt`, performs the existing real-KVM Kali provisioning, verifies the resulting qcow2, packages `kali-base.qcow2`, `kali-base.provenance.json`, `kali-packages.txt`, and `kali-python-packages.txt` into the Docker image, and pushes the deterministic tag.

The teacher browser is the `teacher-browser` Compose service, with identity in the persistent `browser_profile` volume. It drives the ChatGPT UI only. KasmVNC now listens only inside that container on TCP 6902 with its existing HTTPS Basic Auth. A same-container HTTPS auth proxy listens on TCP 6901 and is the only browser-facing endpoint: it shows a normal HTML password form, issues a signed `Secure`/`HttpOnly`/`SameSite=Strict` session cookie, forwards authenticated HTTP and WebSocket traffic to KasmVNC, and injects the internal `kasm_user` Basic credential. This removes the dependency on inconsistent native HTTP Basic Auth dialogs in Chromium- and Firefox-derived browsers while preserving KasmVNC's internal authwall. The `teacher-browser-tunnel` Compose service still connects to `https://teacher-browser:6901`, so the remotely managed Cloudflare Tunnel hostname/origin does not change; keep `No TLS Verify` enabled because the proxy reuses the container-local self-signed certificate. Put the tunnel token in `TEACHER_BROWSER_TUNNEL_TOKEN` and the same public HTTPS URL in `.env` as `TEACHER_BROWSER_PUBLIC_URL`. Sign in to the HTML page with `TEACHER_BROWSER_PASSWORD`, then authenticate to ChatGPT separately inside CloakBrowser. The ChatGPT cookies/session remain in `browser_profile`. CDP stays host-loopback-only on port 9222 and the clipboard helper stays Docker-internal. The agent browser, shell, interactive Unix PTY and desktop all run in the same disposable Kali VM. Its workspace is `/home/kali/workspace`, its Downloads folder is `/home/kali/Downloads`, and a new attempt uses a fresh qcow2 overlay over the immutable golden disk. The runner has a read-only-mounted broker Unix socket and an admin-scoped broker token, without direct access to Docker or libvirt; the MCP controller receives a separate data-plane-only broker token.

See [workstation architecture and operations](docs/workstation.md), [tool surface](docs/tools.md), and [artifact transfer](docs/file-transfer.md). The host needs KVM/libvirt, nftables, and adequate disk space; on a VMware Ubuntu development VM, enable nested virtualization. The guest has NAT egress to public IPv4 addresses and cannot route to private control networks by default.

`make run` freezes selected task IDs and task/App/config fingerprints. Pause, resume, recovery, status, evaluation, and SFT export remain managed by the runner and storage service.

## Manual Kali lifecycle

The OpenAI Secure MCP Tunnel and the Kali VM have separate lifecycles. `make tunnels` starts/refreshes the persistent tunnel and does **not** create a VM. Tunnel readiness here means the tunnel-client process is live and has completed at least one successful OpenAI control-plane poll; `/readyz` may still report the MCP backend unavailable until a Kali runtime is attached. Benchmark entry points (`make run`, `make resume`, and `make auth`) ensure the tunnel is ready automatically.

For an operator-driven disposable Kali outside a benchmark:

```bash
make start_kali
make status_kali
# use @Kali Workstation from ChatGPT
make stop_kali
```

`start_kali` returns after the VM is ready; it does not keep a terminal process alive. Its identity is persisted atomically in the runner state volume, so `status_kali` and `stop_kali` work from a later Cockpit/SSH session. `stop_kali` resets the controller, detaches the gateway, destroys the libvirt attempt, verifies cleanup, and removes the persisted manual state. Manual Kali and Superbench ownership are mutually exclusive.

`make register_apps` is the separate interactive App-registration helper. It may create a temporary registration VM, but `make tunnels` never does.
