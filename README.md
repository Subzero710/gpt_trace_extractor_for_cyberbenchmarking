# GPT Trace Extractor for Cyber Benchmarking

This project runs benchmarks through the ChatGPT web UI, captures tool trajectories, and stores traces for SFT export. The teacher browser and storage/control services run in Docker. A trusted host broker creates one disposable KVM/QEMU Kali workstation per model attempt. The single local MCP App is `kali-workstation` 3.0.0.

## Workflow

```bash
make build
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

`doctor` checks the Ubuntu host, then creates and destroys dedicated VM smoke attempts through the runner. `build` verifies the manifest in its own Python environment, builds trusted Docker images and the host broker, and creates a checksum-verified Kali golden disk. `up` starts the host broker plus persistent Docker services. `tools` registers the one App tunnel. `down` destroys project-owned VM attempts and Docker execution containers without deleting database or teacher browser profile volumes. The host broker needs root privileges for loop mounts and nftables; run its lifecycle on a dedicated Ubuntu host with KVM.

Put secrets in `.env` using `.env.example`: PostgreSQL password, teacher browser license, control plane API key, and `APP_KALI_WORKSTATION_TUNNEL_ID`. Non-secret runner/workstation settings live in `config/runner.toml`; the App registry and manifest live in `apps/registry/` and `apps/kali-workstation/`.

The teacher browser is the `teacher-browser` Compose service, with identity in the persistent `browser_profile` volume. It drives the ChatGPT UI only. The agent browser, shell, interactive Unix PTY and desktop all run in the same disposable Kali VM. Its workspace is `/home/kali/workspace`, its Downloads folder is `/home/kali/Downloads`, and a new attempt uses a fresh qcow2 overlay over the immutable golden disk. The runner has a narrow broker Unix socket, without direct access to Docker or libvirt.

See [workstation architecture and operations](docs/workstation.md), [tool surface](docs/tools.md), and [artifact transfer](docs/file-transfer.md). The host needs KVM/libvirt, nftables, and adequate disk space; on a VMware Ubuntu development VM, enable nested virtualization. The guest has NAT egress to public IPv4 addresses and cannot route to private control networks by default.

`make run` freezes selected task IDs and task/App/config fingerprints. Pause, resume, recovery, status, evaluation, and SFT export remain managed by the runner and storage service.
