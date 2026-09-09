# GPT Trace Extractor for Cyber Benchmarking

This project executes benchmark tasks through the real ChatGPT web UI, captures the observable conversation and tool trajectory, and stores evidence-rich JSONL for later transformation into Qwen training data.

Qwen-style function tools are the architectural source of truth. A ChatGPT App is only a deployment and runtime grouping around one or more canonical tools; its UI label and MCP transport name are not dataset identities.

## Services and Apps

| Service | Responsibility | Persistent state |
|---|---|---|
| `postgres` | Durable run state and captures | `postgres_data` |
| `storage` | FastAPI persistence API and Alembic migrations | PostgreSQL |
| `browser` | Teacher-only CloakBrowser controlling `chatgpt.com` | `browser_profile` |
| `runner` | Sequential task, App, recovery, capture and provenance orchestration | `runner_state` |
| `app-code-workspace` | Local MCP App for shell and workspace tools | `code_workspace_data`, `code_workspace_state` |
| `app-browser` | Local MCP App with an independent CloakBrowser | `app_browser_state` |

The existing external GitHub connector is reused. It is not duplicated in Compose.

## First setup

```bash
make init
make build
make up
```

`make init` merges missing settings into `.env`, creates independent persistent fingerprint seeds for the teacher browser and Browser App, and creates `.secrets/app_control_token`. Existing values are preserved. Keep each seed with its corresponding Docker volume.

For a teacher profile created before identity markers existed, verify the configured teacher seed and run once:

```bash
make adopt-profile
```

Authenticate the teacher browser:

```bash
make auth
```

Open the noVNC URL printed by the command and log into ChatGPT manually.

## One-time ChatGPT MCP setup

Compose publishes the local MCP servers only on loopback:

- Code Workspace: `http://127.0.0.1:8011/mcp`
- Browser: `http://127.0.0.1:8012/mcp`

ChatGPT cannot reach loopback on the benchmark host. Publish each endpoint through a separately managed authenticated HTTPS gateway, then install the two MCP Apps in the ChatGPT account used by `browser`. Keep the visible names aligned with `APP_CODE_WORKSPACE_UI_NAME` and `APP_BROWSER_UI_NAME`. Do not expose either loopback port directly to the public internet; the MCP tool route can operate on active benchmark state.

The repository cannot automate ChatGPT account installation, TLS/DNS, or gateway authentication. Those are explicit deployment steps. The committed manifests at `apps/code-workspace/tool-manifest.json` and `apps/browser/tool-manifest.json` are the exact model-visible contracts to audit during registration.

For logical App `github`, configure both values before parsing any task that requests it:

```dotenv
APP_GITHUB_UI_NAME=<current visible connector name>
APP_GITHUB_MANIFEST_PATH=/data/apps/registry/external/github-tool-manifest.json
```

The external manifest must be obtained from the connector owner or implementation and must exactly describe every model-visible tool. The runner rejects an absent, malformed, or unaudited manifest; it never invents a GitHub tool surface.

## Benchmark format

Use stable logical App IDs:

```json
{"task_id":"incident_reconstruction_001","prompt":"Inspect the attached repository and correlate it with the relevant GitHub history.","attachments":["case_001/repo.zip"],"tools":[{"type":"app","id":"code-workspace","required":true},{"type":"app","id":"browser","required":true},{"type":"app","id":"github","required":true}]}
```

`name` and string shorthand remain accepted when they match a logical ID, a registry alias, or the currently configured UI name. New benchmark files should use `id` so a UI rename does not alter benchmark semantics.

Attachment paths are confined to `TASKS_ROOT`. The task fingerprint covers the exact prompt, attachment names and hashes, logical App IDs, `required` flags, App versions, and manifest SHA-256 values. Mutable UI labels are deliberately excluded.

Inspect the exact effective App and Qwen tool surface without running a task:

```bash
make inspect-tools TASK_ID=incident_reconstruction_001
```

## Run and recover

```bash
make run
```

Equivalent command:

```bash
docker compose run --rm runner run /data/benchmarks/benchmark.jsonl --resume
```

For each task the runner resolves the registry, starts the storage attempt, prepares owned local App environments, opens a fresh ChatGPT conversation, selects the configured UI Apps, submits once, validates and stores the capture with exact provenance, and resets local state.

The durable journal records App environment IDs and UI resolution. If Send may have succeeded, the runner preserves the exact Code Workspace and Browser App state and will not submit again. Recovery resumes only when task, attempt, fingerprint, App contracts, environment IDs, and conversation evidence agree. Cleanup is journaled after storage completion so a crash cannot leak state into the next task.

Only one task may be `running` in PostgreSQL. HTTP 403/429, authentication loss, model or browser drift, App infrastructure failure, storage failure, ambiguous submission, and incomplete streams stop the batch.

## Export

```bash
make status
make export
```

Each exported row includes the original captured messages, task fingerprint, exact App manifests and hashes, resolved runtime UI names, observed tool-call metadata, and runtime evidence. Raw messages are not destructively normalized. A later, separate transformer can flatten the stored manifests into Qwen function definitions.

Migration `0004` adds `runs.app_provenance`. Historical completed rows have no verifiable App contract and are intentionally rejected by export until they are explicitly regenerated or migrated from authoritative evidence.

## Tests

```bash
make test
```

`make test-unit` runs all unit suites, including manifest, registry, fingerprint, lifecycle, recovery, storage, confinement and SSRF tests. `make test-integration` launches the dedicated CloakBrowser and exercises navigation, element interaction and state reset.

See [App and tool contracts](docs/tools.md), [architecture](docs/architecture.md), and [runtime guardrails](docs/runtime-guardrails.md).
