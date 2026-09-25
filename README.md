# GPT Trace Extractor for Cyber Benchmarking

This project runs benchmark tasks through the real ChatGPT web UI, captures observable tool trajectories, and stores evidence-rich traces for later dataset transformation.

## Public workflow

The public production interface is the Superbench lifecycle below.

```bash
sudo make build
sudo make up
sudo make doctor
sudo make tools
sudo make auth
sudo make superbench-fetch ADAPTER=gaia
sudo make run ADAPTER=gaia
sudo make pause
sudo make resume
sudo make status
sudo make reset-recovery TASK=<run_task_id>
sudo make export-parquet
sudo make export-sft
sudo make down
```

`build` builds project images with the dedicated BuildKit builder. `up` starts the persistent core. `doctor` runs the maximal non-ChatGPT runtime preflight. `tools` prepares the two real local MCP backends and Secure MCP Tunnels for ChatGPT App registration/verification. `auth` verifies the ChatGPT session and Apps. `run` starts a new frozen Superbench campaign. `pause` requests an immediate durable pause. `resume` continues the frozen active run. `status` reports active-run and storage state. `reset-recovery` explicitly abandons pending recovery. `down` performs strict runtime teardown without deleting persistent benchmark data.

## Configuration and secrets

`.env` is a secrets file, not a configuration file. It contains only secrets such as:

```dotenv
POSTGRES_PASSWORD=...
CLOAKBROWSER_LICENSE_KEY=...
CONTROL_PLANE_API_KEY=...
```

Stable non-secret runner configuration is versioned in `config/runner.toml`. App names, endpoints and canonical manifests are versioned under `apps/registry/` and the App directories. Provisioned non-secret tunnel IDs are supplied through the current local `.env` provisioning state.

The persistent teacher-browser identity belongs to the `browser_profile` Docker volume at `/profile/.gpt-trace-identity`. It is created once for a fresh profile and reused thereafter. It is never regenerated from `.env`.

The internal App-control token is a generated local secret at `.secrets/app_control_token`.

## Runtime architecture

Persistent services:

- `postgres`: durable run state.
- `storage`: persistence API and migrations.
- `browser`: teacher-only CloakBrowser for `chatgpt.com`.
- `workspace-gateway`: stable MCP endpoint for the active Code Workspace backend.
- `browser-gateway`: stable MCP endpoint for the active Browser backend.

`Code Workspace` and `Cloak Browser` execution containers are ephemeral. The runner creates fresh per-attempt containers and task networks, binds the stable gateways to those backends, and destroys the execution resources at terminal cleanup.

The Browser App gets a deterministic per-attempt fingerprint derived by the runner from task identity; there is no global Browser-App seed in `.env`.

## ChatGPT Apps

The versioned visible names are:

- `Code Workspace`
- `Cloak Browser`

Use `sudo make tools` for the one-time/repair registration flow. The command uses the currently provisioned tunnel IDs from local `.env` state, starts real temporary backends, starts the Dockerized Secure MCP Tunnel clients, waits for MCP initialization, and asks you to verify both Apps with `@` in ChatGPT before cleaning the temporary registration backends.

The benchmark runner uses the `@` mention path for App discovery/selection instead of relying on the `+` App picker.

## Benchmark

Benchmark definitions use stable logical App IDs such as `code-workspace` and `browser`; mutable UI labels are not benchmark identities.

Superbench is the only production benchmark execution path. `make doctor` validates local Workspace/Browser execution and isolation before ChatGPT is involved.

Production lifecycle:

```bash
sudo make superbench-fetch ADAPTER=gaia
sudo make run ADAPTER=gaia
sudo make pause
sudo make resume
sudo make status
sudo make reset-recovery TASK=<run_task_id>
```

`make run` freezes the exact selected task IDs and their adapter/task/App/config identity. LIMIT applies only when creating the run; resume uses only the frozen IDs and the same campaign. The first Ctrl+C requests a durable pause and immediately cancels the active runner coroutine; submitted work is left recoverable and `make resume` continues from the durable journal instead of resubmitting it. A second Ctrl+C remains a hard interrupt. `make pause` writes the same durable pause request from another shell; the active runner watches that state and cancels the active coroutine immediately, using the same recovery path.

Evaluator `fail` is a normal completed benchmark result and the batch continues. Every technical error stops the batch. Authentication/challenge/access incidents enter `needs_intervention`; use noVNC to resolve them and then `sudo make resume`. Rate limits, recovery errors and other infrastructure errors pause the run and expose their reason in `make status`. `make status` combines active-run state, storage state and evaluations. `make reset-recovery` abandons only the matching frozen recovery attempt and never marks that task completed.

Persistent PostgreSQL data, the teacher browser profile and provisioned local state survive `make down`.


## MCP Stack V2

`code-workspace` is an isolated Linux development runtime with sandboxed filesystem operations, persistent terminals, process/system inspection, Python/Debian package management, Git, networking, and verified workspace templates. `browser` exposes Chromium/Playwright with pages, DOM interaction, isolated contexts, storage, DevTools logs/traces, and device overrides. Benchmark tasks may select `workspace_template` from `empty`, `python`, `node`, `vulnerable-webapp`, `malware-analysis`, or `linux-forensics`.
