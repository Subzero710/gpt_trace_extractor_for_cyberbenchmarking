# gpt_trace_extractor_for_cyberbenchmarking

Containerized ChatGPT UI benchmark runner whose final dataset is the observable
`messages[]` trajectory for each cyber task.

## Services

- `browser`: CloakBrowser + cloakserve + persistent profile + noVNC viewer.
- `runner`: JSONL benchmark loader, UI automation, ChatGPT stream observation,
  recovery, and trajectory capture.
- `storage`: FastAPI service for run state, runtime metadata, and JSONL export.
- `postgres`: durable JSONB backing store.

The exported dataset remains intentionally small and canonical:

```json
{"task_id":"cyber_000001","conversation_id":"...","captured_at":"...","messages":[...]}
```

Runtime diagnostics such as request IDs, turn exchange IDs, stream completion
markers, and tool-use metadata are stored in PostgreSQL but are not added to the
dataset export.

Visible commentary, tool calls, tool outputs, recaps, and the final answer are
preserved. Entries explicitly marked as hidden raw chain-of-thought are not
persisted.

## Completion model

The runner does not poll the conversation endpoint to detect completion.

Before clicking Send it arms a Playwright response watcher for the exact
`POST /backend-api/f/conversation` request. ChatGPT keeps that response open as
an SSE stream for the whole turn, including tool calls. The runner waits for the
HTTP response to finish, validates the observed protocol (`assistant
end_turn=true`, `message_stream_complete`, then `[DONE]`), and only then fetches
the conversation JSON once to capture `messages[]`.

See `docs/chatgpt-stream.md`.

## Start

```bash
cp .env.example .env
docker compose build
docker compose up -d postgres storage browser
```

Open the viewer:

```text
http://localhost:7900/vnc.html?autoconnect=1&resize=scale
```

Then:

```bash
docker compose run --rm runner auth
docker compose run --rm runner doctor
```

## Benchmark input

Artifacts are resolved under `TASKS_ROOT` (`/data/tasks` in Compose), not
relative to the benchmark manifest.

```jsonl
{"task_id":"cyber_000001","prompt":"Inspect the attached repository.","attachments":["cyber_000001/repo.zip"],"tools":[]}
{"task_id":"cyber_000002","prompt":"Inspect the repository and relevant GitHub state.","attachments":["cyber_000002/repo.zip"],"tools":[{"type":"app","name":"Github (mosaic)","required":true}]}
```

The shorthand form `"tools":["Github (mosaic)"]` is also accepted. Requested
Apps must already be installed/connected in the persistent ChatGPT account.
Custom tools should be exposed to ChatGPT as Apps/MCP integrations.

Run:

```bash
docker compose run --rm runner run /data/benchmarks/benchmark.jsonl --resume
```

Smoke run:

```bash
docker compose run --rm runner run /data/benchmarks/benchmark.jsonl --resume --limit 3
```

Status/export:

```bash
docker compose run --rm runner status
docker compose run --rm runner export /data/exports/dataset.jsonl
```

## Recovery

The conversation ID is persisted as soon as ChatGPT assigns `/c/<id>`.

On `--resume`, the runner opens that conversation and performs one snapshot
fetch. If it already contains a final assistant `end_turn=true`, the task is
recovered. If generation is still incomplete, the runner fails recovery rather
than creating a duplicate conversation. Re-attaching to an already-running
historical stream is intentionally not guessed until that resume protocol is
captured and tested.

## Internal protocol warning

`/backend-api/f/conversation` and the ChatGPT DOM are internal web-product
interfaces and can change. Their assumptions are isolated in `stream.py`,
`chatgpt.py`, `tools.py`, and `conversation.py`.

Do not commit HAR captures from authenticated ChatGPT sessions: they can contain
session credentials and private conversation data.
