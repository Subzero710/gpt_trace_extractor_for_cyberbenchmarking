# Runtime guardrails

Benchmark prompts, repositories, pages and downloads are hostile inputs. A run advances only when storage, ChatGPT and every requested local App agree on one task identity.

## Teacher browser integrity

The `browser` service remains dedicated to the ChatGPT UI and persistent `/profile`. `BROWSER_FINGERPRINT_SEED` is generated once and bound to the profile together with optional native timezone, locale and geo-IP settings. Healthcheck and runner CDP URLs must carry the exact same identity parameters.

The runner observes the normal frontend and does not synthesize Sentinel, challenge, conduit, cookie, device or security telemetry. It uses the real file chooser, X11 clipboard and visible Apps menu. The submitted model, prompt, timezone and browser environment are checked against observed evidence.

## Local App control

The runner and local Apps share a root-only Docker secret over separate internal control networks. `prepare`, `resume`, `reset` and state inspection require its bearer value. Host-published MCP ports do not publish this secret.

The ports bind only to `127.0.0.1`. A deployment that connects ChatGPT must place an authenticated HTTPS gateway in front of `/mcp`; direct public exposure is prohibited. Account installation, gateway authentication and TLS are outside repository control and must be completed explicitly.

The MCP transport also enforces an exact Host allowlist through `APP_CODE_WORKSPACE_ALLOWED_HOSTS` and `APP_BROWSER_ALLOWED_HOSTS`. Add the authenticated gateway's forwarded Host value deliberately when deploying it; do not use wildcards.

Every stateful operation carries:

- task ID;
- deterministic attempt-specific environment ID;
- task fingerprint.

An App refuses data owned by another identity. Reset never blindly deletes unowned state.

## Code Workspace isolation

- No host bind mount, Docker socket, PostgreSQL credential, teacher profile or egress network.
- A named volume contains only the active task workspace; a separate named volume holds root-owned identity state.
- Tool paths reject absolute paths, traversal and symlinks.
- Commands run as an unprivileged UID with a minimal environment, process/descriptor/file limits, a wall timeout and process-group cleanup.
- MCP output, file reads, attachment transfer and written files have explicit byte limits.
- Compose drops all capabilities, then restores only those required for root to prepare the unprivileged workspace and terminate descendants.
- The root-only control token is unreadable by benchmark commands.

The container has an internal control network so the runner can reach it, but no route to the internet.

## Browser App isolation

- Its CloakBrowser process, fingerprint seed, profile and state volume are distinct from the teacher browser.
- It shares neither a Docker network nor a volume with PostgreSQL, storage, Code Workspace or the teacher browser.
- Only its dedicated egress network reaches the public internet.
- URL credentials and non-HTTP navigation are rejected; private, loopback, link-local, multicast, reserved, unspecified and metadata-network targets are blocked after DNS resolution.
- Tabs, cookies, local storage, history and downloads are deleted by identity-matched reset before the next task.
- Screenshots and downloads are bounded and returned with integrity metadata.

An explicit private-host allowlist exists for controlled test fixtures. Production configuration should keep it empty unless a benchmark owner has documented the target and isolation impact.

## Duplicate prevention and recovery

PostgreSQL serializes `start` and permits only one `running` task. Every mutation uses attempt and runner identity. Completed and failed attempts are immutable; conversation IDs are unique.

The local journal is fsynced at these phases:

| Phase | Recovery rule |
|---|---|
| `starting` | Reset any partially prepared state; fail a matching running attempt. |
| `apps_prepared` | Reset the exact environments; no Send occurred. |
| `composer_dirty` | Reset the exact environments; no Send occurred. |
| `submission_started` | Preserve environments; recover only uniquely evidenced current conversation. |
| `conversation_known` | Preserve environments; recover the recorded conversation ID. |
| `cleanup_pending` | Storage is complete; reset the exact environments before clearing the journal. |

Recovery verifies benchmark fingerprint, storage provenance, attempt, runner, environment IDs, UI resolution and exact prompt evidence. It never re-submits an ambiguous Send and never substitutes a fresh App environment for a submitted conversation.

## Completion and provenance

A live turn requires exactly one observed frontend conversation POST and a complete SSE with a single conversation ID, final assistant `end_turn=true`, stream completion and `[DONE]`. The final authenticated conversation snapshot must match the exact benchmark prompt, expected model and required App invocations.

Storage completion requires App provenance, including full manifests and hashes. Export refuses completed historical rows without that evidence. Raw messages remain unchanged; observed tool-call metadata is additive runtime evidence.

## Batch circuit breakers

The batch stops on browser/CDP/identity failure, storage transport or conflict, clipboard failure, authentication loss, HTTP 403/429, unresolved challenge, ambiguous submission, broken stream, model mismatch, browser drift, invalid registry or manifest, local App ownership/health/control failure, or unrecoverable journal state.

A task-specific unavailable App or completed turn that did not invoke a required App may be recorded as failed only after its local state is reset. The next task never starts while cleanup is uncertain.
