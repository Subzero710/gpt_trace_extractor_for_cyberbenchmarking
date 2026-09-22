# Superbench

Superbench imports only original/upstream benchmark sources through `BenchmarkAdapter`. Adapters own discovery, materialization, environment validation, native evaluation and cleanup; the central runner only sees canonical tasks.

Canonical identity is deterministic from upstream provenance and adapter version. `canonical_task_id` identifies a source task while `campaign_id` identifies the teacher/configuration. One task gets one normal attempt per campaign. A completed native evaluation is terminal whether `success=true` or `success=false`; infrastructure failure is stored separately and may be retried.

Evaluation happens after the teacher trajectory and runtime provenance are captured and before App environment reset. There is no generic LLM judge. `success`, optional `reward`, and the complete native result are retained separately from `run_status`.

PostgreSQL remains authoritative. `make export` remains the complete JSONL debug export with nested messages. `make export-parquet` produces a typed canonical corpus and `make export-sft` derives successful, sanitized, provider-independent trajectories. No Qwen tokenizer or model-specific special tokens are stored; tokenization belongs to training time.

## Benchmark source fetching

Fetching is generic infrastructure. `BenchmarkAdapter.fetch()` owns adapter-specific source acquisition, while `make superbench-fetch ADAPTER=<adapter_id>` only selects an adapter and runs it in the generic egress-only fetch container. The Makefile and Compose topology contain no benchmark names, source URLs, revisions, or provider-specific credential names.

Adapters write under `/data/state/superbench/sources/<adapter_id>` through the shared `source_root` contract. A gated source can consume the generic `BENCHMARK_SOURCE_TOKEN` credential supplied to the fetch process. Normal Superbench execution stays isolated from benchmark source hosts and consumes only the pinned local cache.

## GAIA adapter smoke run

The `gaia` adapter is intentionally benchmark-specific: it pins the official GAIA repository, exact upstream revision, 2023 validation split and Level 1, exposes Browser and Code Workspace to each task, materializes referenced attachments, and evaluates with GAIA's native answer normalization. None of those constants appear in Make or Compose.

For GAIA, obtain upstream dataset access, set `BENCHMARK_SOURCE_TOKEN` to the source token for the fetch process, then run `make superbench-fetch ADAPTER=gaia`. A short run is `make superbench-run ADAPTER=gaia LIMIT=3`; inspect it with `make superbench-status ADAPTER=gaia`.

Benchmark-specific source URLs, revisions, splits, credential semantics and native evaluators belong inside adapters. Core Superbench orchestration remains benchmark-agnostic. The built-in `gaia` adapter pins GAIA 2023 Level-1 validation. InterCode-CTF remains unregistered because its CTF tasks derive from picoCTF. Third-party adapters remain available through the `gpt_trace_runner.benchmark_adapters` entry-point group.

To add a benchmark: implement `BenchmarkAdapter`, map upstream records to `CanonicalTask`, preserve upstream repository/commit/license metadata, implement native `evaluate`, add tests, and expose it through the adapter entry-point group. Core scheduler/storage/export code should not need benchmark-specific branches.

Use `dedup_group`/upstream origin to group related challenges, projects or vulnerability families; do not split near-duplicates independently. License metadata is provenance for later filtering/auditing, not legal advice.

V2 uses `/data/state/superbench/staging` for writable staging, requires `GPT_TRACE_RUNNER_BUILD_ID` for campaign identity, evaluates recovery captures through the same task evaluator hook as the happy path, and streams JSONL into bounded Parquet row groups.

Recovery is journal-first: a pending journal is reconciled against its own canonical Superbench task before completed rows are skipped or new tasks are scheduled. Stateful adapters may override `BenchmarkAdapter.recover()` to reconnect evaluator-side state without provisioning a fresh environment. A running storage row without a matching journal is treated as an explicit recovery error rather than a retryable task.

`export-sft` is fail-closed for tool-use structure: every tool call must name a declared globally stable tool, call IDs must be unique, tool results must reference prior calls exactly once, and every call must have a result. The runtime `used_tool_calls` provenance is call-level and joins ChatGPT recipients to canonical App/tool identities.
