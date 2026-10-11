# Superbench

Superbench imports upstream benchmark sources through `BenchmarkAdapter`. Adapters own source fetching, task discovery/materialization and native evaluation; the central runner operates on `TaskSpec` objects and benchmark-independent App/runtime contracts.

A source task is identified by its adapter task ID. A stored trajectory ID is derived from the source task, adapter ID/version and teacher campaign. The campaign identity depends on the expected teacher model only. Runtime settings and the runner Git commit are retained as provenance but do not duplicate a task when a timeout or unrelated commit changes.

Native evaluation happens after the teacher trajectory/runtime provenance is captured and before App reset. `EvaluationResult` contains `verdict` (`pass`/`fail`), optional score, details and evaluator metadata. Infrastructure failure remains separate in the run status.

PostgreSQL is authoritative. `make export-parquet` is the only corpus export. The internal JSONL stream includes all rows with captured messages (SQL NULL and JSON null mean no capture), regardless of execution status or evaluation. Pass, fail and unevaluated captures are retained without a verdict filter. PostgreSQL uses one repeatable-read, read-only snapshot. The Parquet writer preserves normalized messages, tool calls/results, original captured messages, App manifests/provenance, storage/runtime/dataset metadata and evaluations. Every row is validated; duplicate trajectory IDs, invalid types or non-finite evaluation scores abort the export without replacing the previous file.

## Benchmark source fetching

Fetching is generic infrastructure. `BenchmarkAdapter.fetch()` owns adapter-specific acquisition, while `make superbench-fetch ADAPTER=<adapter_id>` only selects an adapter. Source URLs, revisions and provider-specific semantics stay inside adapters.

Each adapter writes under `/data/state/superbench/sources/<adapter_id>`. The fetch container has its own `benchmark_source_egress` network and a dedicated `benchmark_sources` volume. It does not share the teacher browser's `ui_egress` network or the general `runner_state` volume. Normal runner execution mounts benchmark sources read-only.

A gated source can consume `BENCHMARK_SOURCE_TOKEN` during fetch. Normal Superbench execution uses only the local pinned cache.

## GAIA smoke run

The built-in `gaia` adapter pins the official GAIA repository at revision `682dd723ee1e1697e00360edccf2366dc8418dd9`, using the 2023 validation Level-3 split and GAIA's native answer normalization.

The adapter exposes local MCP Apps only when the pinned GAIA task metadata or source file makes that capability relevant. It never requires an App invocation. Source files are seeded into `/workspace/attachments/` rather than uploaded directly to ChatGPT, and the agent decides whether to use the available capability.

After obtaining upstream GAIA access, set `BENCHMARK_SOURCE_TOKEN` and run:

```bash
make superbench-fetch ADAPTER=gaia
make run ADAPTER=gaia LIMIT=3
make status
```

The pinned split is validated to expose both Browser and Code Workspace across the source tasks. Ground-truth answers remain evaluator-side and are not copied into task metadata or prompts.

## Adapter contract

The [SWE-Gym Lite guide](swe-gym-lite.md) documents the unchanged pinned
230-task/11-repo/25-env contract, recipe/schema/adapter version 2, host-only shallow
task sources and setup caches, and a fresh evaluator VM over the exact recorded
immutable backing. Native grading runs base -> clean official setup -> persisted
candidate -> hidden tests -> test command. Candidate checkpoints resume only
trusted grading in a new evaluator, with no ChatGPT generation. Technical errors
preserve both runtimes for explicit recovery; native benchmark fail completes
normally. `TaskSpec.workstation_template` selects the template;
`BenchmarkTask.template_task_id` binds its logical artifact scope without changing
ordinary Kali MCP tools or the GAIA/manual `None` behavior.

To add a benchmark, implement `BenchmarkAdapter`, return `TaskSpec` values, preserve useful source provenance in task metadata, implement native `evaluate()` when an upstream oracle exists, add tests and expose the adapter through the `gpt_trace_runner.benchmark_adapters` entry-point group. Core scheduler/storage/export code should not need benchmark-specific branches.

`TaskSpec.tools` lists Apps available to the task. Availability never implies mandatory invocation: the agent alone decides whether to use a tool. Captured provenance records observed tool use. Attachments intended for Code Workspace can be materialized through `initial_workspace` instead of being uploaded to the teacher conversation.

Recovery remains journal-first. A pending journal is reconciled against its exact source task, adapter version and teacher campaign before new work is scheduled. Completed rows are immutable and are skipped only when the current pre-materialization task contract fingerprint still matches; this check includes prompt/source metadata, direct source artifacts/workspaces and current App contracts. Failed infrastructure attempts may be retried.

The single Parquet export records tool-coherence diagnostics in `validation_json`: declared/stable names, unique call IDs, preceding calls, result names, duplicate results and unanswered calls. Partial or ambiguous tool traces remain exported with their original messages; a missing result is never invented and a failed/unevaluated trajectory is never discarded. `raw_messages_json` and `app_provenance_json` preserve the exact source data alongside the typed normalized view.
