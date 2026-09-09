# Runtime guardrails

Benchmark prompts, repositories, pages and downloads are hostile inputs. The main isolation boundary for local Apps is a fresh execution container per task attempt.

## Teacher browser

The persistent `browser` service is reserved for automating the ChatGPT UI. Its profile is never mounted into benchmark Browser containers.

## Stable gateways

`workspace-gateway` and `browser-gateway` are persistent only so ChatGPT can use stable MCP URLs. They contain no task state. The runner binds each gateway to one exact backend using an internal bearer token and task/attempt/environment/fingerprint identity. A conflicting binding is rejected.

The gateways have no Docker socket. Backend URLs must match the deterministic internal container-name format. Model-facing MCP requests are proxied without forwarding the external `Host` header. Backend control calls use a per-environment token derived by the runner.

## Workspace container

For every attempt requesting `code-workspace`, the runner creates a new container. It has:

- no Docker socket or sensitive host bind mounts;
- no PostgreSQL/storage credentials or teacher profile;
- an internal-only task network and no internet route;
- bounded memory, CPU, PIDs, file descriptors and tmpfs;
- a read-only image root with writable `/workspace`, `/state` and `/tmp`;
- shell commands executed as the sandbox UID with a minimal environment;
- process-group termination on command timeout.

The initial workspace is copied into the new container, not bind-mounted. Tool paths reject absolute paths, traversal and symlinks. At terminal cleanup the whole container is removed with `force=true&v=true`, so all remaining processes and mutable filesystem state disappear.

## Browser container

For every attempt requesting `browser`, the runner creates a new CloakBrowser container. Browser profile/state/tmp data live only in that container's writable tmpfs. The container joins:

1. the internal task network used to reach its gateway; and
2. a unique non-internal egress network used only by that Browser attempt.

It never shares the teacher profile, Workspace filesystem or Docker socket. URL policy blocks non-web schemes, credentials, loopback, link-local, private, reserved and metadata-network targets unless an explicit controlled-test allowlist is configured.

At terminal cleanup the Browser container and both task-specific networks are removed. No cookie/localStorage/download/profile reset is relied on as the inter-task isolation mechanism.

## Recovery

If Send may have happened, containers are deliberately preserved. Recovery must find the same deterministic container and network identities and validate their labels. Missing resources cause `RecoveryIncomplete`/App infrastructure failure; the runner never creates fresh replacements for an already-submitted conversation.

`RequiredToolNotUsed` during recovery terminalizes the storage row as failed, unbinds gateways, destroys the exact attempt runtime and clears the journal.

## Provenance

The runtime records the configured image reference and Docker's resolved image ID for each backend. This allows the project to use moving image tags during normal collection while still knowing which image actually generated a trajectory.

## Batch circuit breakers

Browser/CDP failure, storage conflict, authentication loss, HTTP 403/429, ambiguous submission, model drift, invalid manifests, gateway conflicts, Docker runtime identity mismatch and incomplete recovery stop the batch. A new task does not start while cleanup identity is uncertain.
