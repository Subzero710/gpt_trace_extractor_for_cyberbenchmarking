# GPT Trace Extractor for Cyber Benchmarking

This project runs benchmark tasks through the real ChatGPT web UI, captures observable tool trajectories, and stores evidence-rich traces for later dataset transformation.

## Public workflow

The Make interface intentionally exposes only seven lifecycle commands:

```bash
sudo make build
sudo make up
sudo make doctor
sudo make tools
sudo make auth
sudo make run
sudo make down
```

`build` builds project images with the dedicated BuildKit builder. `up` starts the persistent core. `doctor` runs the maximal non-ChatGPT runtime preflight. `tools` prepares the two real local MCP backends and Secure MCP Tunnels for ChatGPT App registration/verification. `auth` verifies the ChatGPT session and resolves Apps through `@` mentions. `run` runs/resumes the benchmark. `down` performs strict runtime teardown without deleting persistent benchmark data.

## Configuration and secrets

`.env` is a secrets file, not a configuration file. It contains only secrets such as:

```dotenv
POSTGRES_PASSWORD=...
CLOAKBROWSER_LICENSE_KEY=...
CONTROL_PLANE_API_KEY=...
```

Stable non-secret runner configuration is versioned in `config/runner.toml`. App names, endpoints and canonical manifests are versioned under `apps/registry/` and the App directories. Provisioned non-secret tunnel IDs live in ignored local state at `state/tunnels.json`.

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

Use `sudo make tools` for the one-time/repair registration flow. The command reads tunnel IDs from `state/tunnels.json`, starts real temporary backends, starts the Dockerized Secure MCP Tunnel clients, waits for MCP initialization, and asks you to verify both Apps with `@` in ChatGPT before cleaning the temporary registration backends.

The benchmark runner uses the `@` mention path for App discovery/selection instead of relying on the `+` App picker.

## Benchmark

Benchmark definitions use stable logical App IDs such as `code-workspace` and `browser`; mutable UI labels are not benchmark identities.

The current smoke benchmark is `benchmarks/benchmark.jsonl`. `make doctor` validates local Workspace/Browser execution and isolation before ChatGPT is involved.

Persistent PostgreSQL data, the teacher browser profile and provisioned local state survive `make down`.
