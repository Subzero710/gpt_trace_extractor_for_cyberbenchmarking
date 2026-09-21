# Superbench

Superbench imports only original/upstream benchmark sources through `BenchmarkAdapter`. Adapters own discovery, materialization, environment validation, native evaluation and cleanup; the central runner only sees canonical tasks.

Canonical identity is deterministic from upstream provenance and adapter version. `canonical_task_id` identifies a source task while `campaign_id` identifies the teacher/configuration. One task gets one normal attempt per campaign. A completed native evaluation is terminal whether `success=true` or `success=false`; infrastructure failure is stored separately and may be retried.

Evaluation happens after the teacher trajectory and runtime provenance are captured and before App environment reset. There is no generic LLM judge. `success`, optional `reward`, and the complete native result are retained separately from `run_status`.

PostgreSQL remains authoritative. `make export` remains the complete JSONL debug export with nested messages. `make export-parquet` produces a typed canonical corpus and `make export-sft` derives successful, sanitized, provider-independent trajectories. No Qwen tokenizer or model-specific special tokens are stored; tokenization belongs to training time.

V2 intentionally ships no built-in benchmark adapter until an original upstream source with verified content provenance/license is selected. InterCode-CTF is not registered because its CTF tasks derive from picoCTF. Third-party adapters remain available through the `gpt_trace_runner.benchmark_adapters` entry-point group.

To add a benchmark: implement `BenchmarkAdapter`, map upstream records to `CanonicalTask`, preserve upstream repository/commit/license metadata, implement native `evaluate`, add tests, and expose it through the adapter entry-point group. Core scheduler/storage/export code should not need benchmark-specific branches.

SFT use contaminates those source tasks for later evaluation. Use `dedup_group`/upstream origin to group related challenges, projects or vulnerability families; do not split near-duplicates independently. License metadata is provenance for later policy/filtering, not legal advice.

V2 uses `/data/state/superbench/staging` for writable staging, requires `GPT_TRACE_RUNNER_BUILD_ID` for campaign identity, evaluates recovery captures through the same task evaluator hook as the happy path, and streams JSONL into bounded Parquet row groups.
