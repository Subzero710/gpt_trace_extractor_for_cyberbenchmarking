# Superbench

Superbench imports upstream benchmark sources through `BenchmarkAdapter`. Adapters own source fetching, task discovery/materialization and native evaluation; the central runner operates on `TaskSpec` objects and benchmark-independent App/runtime contracts.

A source task is identified by its adapter task ID. A stored trajectory ID is derived from the source task, adapter ID/version and teacher campaign. The campaign identity depends on the expected teacher model only. Runtime settings and the runner Git commit are retained as provenance but do not duplicate a task when a timeout or unrelated commit changes.

Native evaluation happens after the teacher trajectory/runtime provenance is captured and before App reset. `EvaluationResult` contains `verdict` (`pass`/`fail`), optional score, details and evaluator metadata. Infrastructure failure remains separate in the run status.

PostgreSQL is authoritative. `make export` emits the raw JSONL storage export. `make export-parquet` produces the canonical typed corpus. `make export-sft` derives a tool-validated training view and, by default, keeps only native `pass` trajectories; `--verdict` can explicitly select another evaluation class for analysis.

## Benchmark source fetching

Fetching is generic infrastructure. `BenchmarkAdapter.fetch()` owns adapter-specific acquisition, while `make superbench-fetch ADAPTER=<adapter_id>` only selects an adapter. Source URLs, revisions and provider-specific semantics stay inside adapters.

Each adapter writes under `/data/state/superbench/sources/<adapter_id>`. The fetch container has its own `benchmark_source_egress` network and a dedicated `benchmark_sources` volume. It does not share the teacher browser's `ui_egress` network or the general `runner_state` volume. Normal runner execution mounts benchmark sources read-only.

A gated source can consume `BENCHMARK_SOURCE_TOKEN` during fetch. Normal Superbench execution uses only the local pinned cache.

## GAIA smoke run

The built-in `gaia` adapter pins the official GAIA repository at revision `682dd723ee1e1697e00360edccf2366dc8418dd9`, using the 2023 validation Level-1 split and GAIA's native answer normalization.

The adapter is deliberately configured to exercise both local MCP Apps across a short run. Tasks without a source file require Browser research. Tasks with a source file require Code Workspace; those files are seeded only into `/workspace/attachments/` rather than uploaded directly to ChatGPT. `LIMIT` selection prioritizes tasks that add uncovered required Apps before filling the remainder.

After obtaining upstream GAIA access, set `BENCHMARK_SOURCE_TOKEN` and run:

```bash
make superbench-fetch ADAPTER=gaia
make superbench-run ADAPTER=gaia LIMIT=3
make superbench-status ADAPTER=gaia
```

The pinned split is validated to contain tasks requiring both Browser and Code Workspace. Ground-truth answers remain evaluator-side and are not copied into task metadata or prompts.

## Adapter contract

To add a benchmark, implement `BenchmarkAdapter`, return `TaskSpec` values, preserve useful source provenance in task metadata, implement native `evaluate()` when an upstream oracle exists, add tests and expose the adapter through the `gpt_trace_runner.benchmark_adapters` entry-point group. Core scheduler/storage/export code should not need benchmark-specific branches.

`TaskSpec.tools` lists Apps available to the task. `TaskSpec.required_tools` is the subset that must actually be invoked; the captured ChatGPT conversation is checked against that requirement. Attachments intended for Code Workspace can be materialized through `initial_workspace` instead of being uploaded to the teacher conversation.

Recovery remains journal-first. A pending journal is reconciled against its exact source task, adapter version and teacher campaign before new work is scheduled. Completed rows are immutable; failed infrastructure attempts may be retried.

`export-sft` is fail-closed for tool-use structure: tool calls must name declared stable tools, call IDs must be unique, tool results must reference prior calls exactly once, and every call must have a result.
