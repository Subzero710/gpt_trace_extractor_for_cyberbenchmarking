# GPT Trace Extractor for Cyber Benchmarking

This project runs benchmarks through the ChatGPT web UI, captures tool trajectories, and stores traces for SFT export. The teacher browser and storage/control services run in Docker. A trusted host broker creates one disposable KVM/QEMU Kali workstation per model attempt. The single local MCP App is `kali-workstation` 3.0.0.

## Workflow

```bash
make requirements  # optional explicit host preflight; make build runs it too
sudo make build
make up
make doctor
make tools
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

`doctor` checks the Ubuntu host, then creates and destroys dedicated VM smoke attempts through the runner. `build` first validates the host-only system package manifest plus Python venv and Docker Engine/Compose/Buildx, builds the host broker and trusted Docker images, verifies the MCP manifest inside the built controller image, then pulls the checksum-verified Kali golden disk prebuilt on Docker Hub. `up` starts the host broker plus persistent Docker services. `tools` registers the one App tunnel. `down` destroys project-owned VM attempts and Docker execution containers without deleting database or teacher browser profile volumes. The host broker needs root privileges for loop mounts and nftables; run its lifecycle on a dedicated Ubuntu host with KVM.

Put deployment-local values in `.env` using `.env.example`: PostgreSQL password, the independent teacher-browser KasmVNC password, `TEACHER_BROWSER_TUNNEL_TOKEN`, the non-secret `TEACHER_BROWSER_PUBLIC_URL` for the Cloudflare Kasm hostname, control plane API key, optional benchmark source token, and `APP_KALI_WORKSTATION_TUNNEL_ID`. Other non-secret runner/workstation settings remain versioned in `config/runner.toml`. Docker Compose injects `TEACHER_BROWSER_PUBLIC_URL` into runner containers, so `make auth` uses the deployment hostname without hardcoding it in TOML. The App registry and manifest live in `apps/registry/` and `apps/kali-workstation/`.

Root `requirements.txt` is deliberately a Debian/Ubuntu **system-package** manifest, not a pip file. It contains only dependencies required by benchmark runtime hosts. `requirements-golden-build.txt` adds the heavier `libguestfs-tools` and `p7zip-full` packages used only on a machine that locally builds/publishes the Kali golden. Application Python dependencies stay in Docker, and Kali guest dependencies stay in the image lock. `make build` fails before creating artifacts if a listed runtime package, a functional Python `venv`/`ensurepip`, Docker Engine, Compose, or Buildx is missing, and prints the exact `apt-get install` command for missing host packages.

## Kali golden image

Benchmark hosts do not build Kali locally. The heavy provisioning path is built once and published to Docker Hub under `aad7xppz4fd4r8emr/gpt-trace-kali-golden`. The tag is derived from the full `golden_build_input_sha256`, so a checkout automatically requests the image matching its exact guest source, lockfile, provisioning script, Kali source pin, and package set. `make build` pulls that image, copies the four verified artifacts into `/var/lib/libvirt/images/gpt-trace/`, verifies the qcow2 and package/provenance hashes, then removes the pulled Docker image so the large qcow2 is not retained twice on the benchmark server.

To publish a golden after changing any guest-image input, use a separate build-capable KVM host, authenticate Docker first, then run:

```bash
sudo make publish-kali-golden
```

That target checks `requirements.txt` plus `requirements-golden-build.txt`, performs the existing real-KVM Kali provisioning, verifies the resulting qcow2, packages `kali-base.qcow2`, `kali-base.provenance.json`, `kali-packages.txt`, and `kali-python-packages.txt` into the Docker image, and pushes the deterministic tag.

The teacher browser is the `teacher-browser` Compose service, with identity in the persistent `browser_profile` volume. It drives the ChatGPT UI only. KasmVNC listens on container TCP 6901 but is not published on the Ubuntu host. The `teacher-browser-tunnel` Compose service runs Cloudflare `cloudflared` and reaches KasmVNC directly over the shared `ui_egress` Docker network. Configure the remotely managed tunnel public hostname to route the chosen HTTPS subdomain to `https://teacher-browser:6901`; because KasmVNC uses a container-local self-signed certificate, enable Cloudflare Tunnel's origin `No TLS Verify` setting for this route. Put the tunnel token in `TEACHER_BROWSER_TUNNEL_TOKEN` and the same public HTTPS URL in `.env` as `TEACHER_BROWSER_PUBLIC_URL`. Authenticate to KasmVNC as `kasm_user` with `TEACHER_BROWSER_PASSWORD`, then authenticate to ChatGPT separately inside CloakBrowser. KasmVNC remains the infrastructure authwall; the ChatGPT cookies/session remain in `browser_profile`. CDP stays host-loopback-only on port 9222 and the clipboard helper stays Docker-internal. The agent browser, shell, interactive Unix PTY and desktop all run in the same disposable Kali VM. Its workspace is `/home/kali/workspace`, its Downloads folder is `/home/kali/Downloads`, and a new attempt uses a fresh qcow2 overlay over the immutable golden disk. The runner has a read-only-mounted broker Unix socket and an admin-scoped broker token, without direct access to Docker or libvirt; the MCP controller receives a separate data-plane-only broker token.

See [workstation architecture and operations](docs/workstation.md), [tool surface](docs/tools.md), and [artifact transfer](docs/file-transfer.md). The host needs KVM/libvirt, nftables, and adequate disk space; on a VMware Ubuntu development VM, enable nested virtualization. The guest has NAT egress to public IPv4 addresses and cannot route to private control networks by default.

`make run` freezes selected task IDs and task/App/config fingerprints. Pause, resume, recovery, status, evaluation, and SFT export remain managed by the runner and storage service.
