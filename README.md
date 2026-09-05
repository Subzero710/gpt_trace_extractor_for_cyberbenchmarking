# gpt_trace_extractor_for_cyberbenchmarking

Containerized ChatGPT UI benchmark runner whose final dataset is the observable
`messages[]` trajectory for each cyber task.

## Services

- `browser`: CloakBrowser + cloakserve + persistent profile + noVNC viewer.
- `runner`: JSONL benchmark loader, UI automation, recovery, trajectory capture.
- `storage`: FastAPI service for run state and JSONL export.
- `postgres`: durable JSONB backing store.

The storage API exports records shaped as:

```json
{"task_id":"cyber_000001","conversation_id":"...","captured_at":"...","messages":[...]}
```

Visible commentary, tool calls, tool outputs, recaps, and the final answer are
preserved. Entries explicitly marked as hidden raw chain-of-thought are not
persisted.

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

Then in another terminal:

```bash
docker compose run --rm runner auth
```

Log in manually to ChatGPT in the noVNC window. Browser state lives in the
`browser_profile` volume.

Check the stack:

```bash
docker compose run --rm runner doctor
```

## Benchmark input

`benchmarks/benchmark.jsonl`:

```jsonl
{"task_id":"cyber_000001","prompt":"Inspect the attached repository.","attachments":["/data/tasks/cyber_000001/repo.zip"]}
{"task_id":"cyber_000002","prompt":"Analyze the attached PCAP.","attachments":["/data/tasks/cyber_000002/capture.pcap"]}
```

Run sequentially:

```bash
docker compose run --rm runner run /data/benchmarks/benchmark.jsonl --resume
```

Small smoke run:

```bash
docker compose run --rm runner run /data/benchmarks/benchmark.jsonl --resume --limit 3
```

Status and export:

```bash
docker compose run --rm runner status
docker compose run --rm runner export /data/exports/dataset.jsonl
```

## Recovery

The storage service tracks `running`, `failed`, and `completed` runs. As soon
as ChatGPT assigns a conversation ID it is committed to PostgreSQL. A resumed
run attempts to recover that conversation before sending the prompt again.

## Notes

CDP is bound to `127.0.0.1`; never expose it publicly. The runner does not try
to circumvent account or usage limits. Internal ChatGPT endpoints/selectors can
change, so ChatGPT-specific code is isolated in `chatgpt.py` and
`conversation.py`.
