# Runtime guardrails

The runner drives the real ChatGPT frontend inside one persistent CloakBrowser profile. It observes normal frontend network activity but does not reimplement Sentinel/challenge/conduit protocols or synthesize their tokens/payloads.

## Identity

`BROWSER_FINGERPRINT_SEED` is generated once and bound to `/profile/.gpt-trace-identity` together with optional native timezone/locale/geoip settings. A mismatch fails browser startup. Existing pre-marker profiles require explicit one-time adoption.

The CDP healthcheck and runner connection use the same identity query. Duplicate or additional identity parameters in a custom `BROWSER_CDP_URL` are rejected.

## Interaction

- Page focus is checked read-only; `bring_to_front()` is used only when needed.
- CloakBrowser's supported humanize wrapper is applied to the remote CDP Browser when enabled.
- Attachments use a real browser file chooser path, never direct hidden-input mutation.
- Benchmark text uses the browser container's X11 clipboard and Ctrl+V; no page-side clipboard permission/JavaScript is used.
- App mentions inserted by ChatGPT are validated using frontend `serialization_metadata.custom_symbol_offsets` rather than being confused with benchmark prompt text.

## Task state and duplicate prevention

PostgreSQL is authoritative for run state. Every mutation includes the expected `attempt` and `runner_id`. `completed` and `failed` attempts are immutable; only an explicit new attempt may replace a failed state. `conversation_id` is unique across tasks.

`start` is serialized in PostgreSQL and refuses a second `running` task. `runner_id` always includes a fresh per-process nonce even when `RUNNER_ID` supplies a human-readable label.

A local flock additionally prevents multiple commands sharing the same `runner_state` volume from touching ChatGPT concurrently.

## Crash journal

Before a new attempt, the runner atomically journals the task fingerprint and expected attempt. Immediately before a concrete Send click it advances to `submission_started`; after ChatGPT assigns an ID it advances to `conversation_known`.

After a crash, ambiguous submission is never retried automatically. Recovery requires a matching benchmark fingerprint, storage attempt/runner identity, and exact user prompt. Known conversation IDs are recovered without Send.

## Completion

A successful live turn requires the one frontend `POST /backend-api/f/conversation` SSE to contain:

- exactly one conversation ID;
- final assistant `end_turn=true`;
- `message_stream_complete`;
- `[DONE]`.

The frontend-submitted model and prompt are validated from the already-observed request. A naturally observed conversation snapshot is reused only if it validates; otherwise there is exactly one browser-context fallback fetch. HTTP 403/429 and malformed/incomplete snapshots are circuit breakers.

## Batch circuit breakers

The batch stops instead of advancing on:

- browser/CDP/identity failure;
- storage transport/conflict failure;
- clipboard/X11 failure;
- authentication loss;
- HTTP 403/429;
- unrecovered challenge/interstitial;
- ambiguous or duplicate submission;
- broken/incomplete SSE;
- model mismatch;
- browser environment drift;
- unrecoverable crash journal;
- accidental concurrent turn/runner.

A task-specific unavailable App or a completed turn that did not invoke a `required` App may be marked failed and, unless `--stop-on-error` is used, the sequential batch can continue from a clean new chat.
