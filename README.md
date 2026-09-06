# GPT Trace Extractor for Cyber Benchmarking

Containerized runner for executing benchmark tasks through the real ChatGPT web UI and persisting the observable conversation trajectory for JSONL export.

The runner deliberately leaves ChatGPT's own request-control flow to the real frontend. It does not recreate Sentinel, proof/challenge tokens, conduit tokens, cookies, device IDs, or browser security telemetry.

## Services

- `postgres` — durable run state and captured traces.
- `storage` — FastAPI persistence API; Alembic migrations run at startup.
- `browser` — headed CloakBrowser + persistent `/profile` + noVNC + internal X11 clipboard helper.
- `runner` — sequential Playwright orchestrator connected to the browser over CDP.

Only one benchmark task may be `running` in PostgreSQL at a time. The runner also uses a local lock and a crash journal to prevent accidental duplicate submissions.

## First setup

```bash
make init
make build
make up
```

`make init` creates/merges `.env` and generates `BROWSER_FINGERPRINT_SEED` exactly once. Keep that seed with the `browser_profile` Docker volume.

If the profile volume already existed before profile identity markers were introduced, verify that the configured seed is the one you intend to keep, then run once:

```bash
make adopt-profile
```

Do not use `BROWSER_ADOPT_EXISTING_PROFILE=true` routinely; it is only a one-time migration switch.

## Authentication

```bash
make auth
```

Open the noVNC URL printed by the command and log into ChatGPT manually. The browser profile persists the session.

`auth` and `doctor --chatgpt` refuse to touch ChatGPT if PostgreSQL reports an active benchmark task or if a crash journal is pending. Recover the benchmark first.

## Benchmark format

`benchmarks/benchmark.jsonl` contains one JSON object per line:

```json
{"task_id":"cyber_000001","prompt":"Inspect the attached repository.","attachments":["case_001/repo.zip"],"tools":[{"type":"app","name":"Github (mosaic)","required":true}]}
```

Attachment paths are confined to `TASKS_ROOT` (`/data/tasks` in Compose). The internal task fingerprint covers the exact prompt, attachment names/content hashes, and requested Apps. Reusing a `task_id` with a modified task specification is rejected instead of silently mixing datasets.

## Run

```bash
make run
```

Equivalent command:

```bash
docker compose run --rm runner run /data/benchmarks/benchmark.jsonl --resume
```

Normal lifecycle:

```text
storage start/CAS
  -> prepare existing ChatGPT page
  -> visible UI upload / Apps / prompt
  -> durable submission journal
  -> one frontend POST /backend-api/f/conversation
  -> completed SSE
  -> validated conversation snapshot
  -> storage complete
  -> clear journal
```

There is no artificial random inter-task delay. Tasks are serialized by actual completion/readiness. HTTP 403/429, authentication loss, unrecovered challenges, model/environment drift, storage failure, clipboard failure, ambiguous submission, and broken streams stop the batch.

## Crash recovery

Use `--resume` (the Make target already does). The runner never blindly resubmits a task whose Send may already have succeeded.

The durable journal has these phases:

- `starting`
- `composer_dirty`
- `submission_started`
- `conversation_known`

If a crash happened after Send and the conversation ID is known, it is recovered directly. If Send may have happened but the ID was not yet persisted, recovery only accepts the currently open `/c/<id>` when its user message matches the exact benchmark task fingerprint/prompt.

## Model and environment integrity

By default the frontend must submit:

```text
CHATGPT_EXPECTED_MODEL_SLUG=gpt-5-6-thinking
```

Change this explicitly if the intended ChatGPT model slug changes upstream. A silent model switch stops the batch.

The runner also records only a SHA-256 of its read-only browser environment baseline and stops if the environment changes during a batch. It does not patch `navigator`, `window`, `document`, timezone, language, CPU, screen, or other browser globals.

Optional CloakBrowser-native settings are `BROWSER_TIMEZONE`, `BROWSER_LOCALE`, and `BROWSER_GEOIP`. Browser healthchecks and the runner use the exact same CDP identity parameters.

## Clipboard

Prepared benchmark text is placed in the browser container's real X11 clipboard through an internal Docker-only HTTP helper and pasted with the browser keyboard path. `chatgpt.com` is not granted clipboard permissions and no `navigator.clipboard` JavaScript is injected. The clipboard is cleared after the composer is verified.

## Diagnostics

Local checks only:

```bash
make doctor
```

To additionally verify that ChatGPT is authenticated/ready:

```bash
docker compose run --rm runner doctor --chatgpt
```

## Status and export

```bash
make status
make export
```

The exported JSONL remains intentionally minimal:

```json
{"task_id":"cyber_000001","conversation_id":"...","captured_at":"...","messages":[...]}
```

Internal recovery/runtime metadata is kept in PostgreSQL and excluded from this canonical export.

## Tests

```bash
make test
```

The test suite covers stream completion, required Apps, attachment confinement, prompt preservation, model/environment checks, local lock, crash journal, storage attempt CAS/idempotence, stale mutations, duplicate conversation IDs, and task fingerprint integrity.
