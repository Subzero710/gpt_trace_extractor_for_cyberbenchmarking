# Apps and canonical tools

ChatGPT App and canonical model tool are different concepts:

- A ChatGPT App is a runtime grouping used to install and select capabilities in the teacher UI.
- A canonical tool is a stable function contract recorded for the trajectory and later supplied to Qwen.
- Qwen is the source of truth for names and schemas. Container, MCP transport, connector and UI naming remain provenance or deployment metadata.

## Registry

`apps/registry/apps.json` defines these initial logical Apps:

| ID | Ownership | Default UI name | Canonical tools |
|---|---|---|---|
| `code-workspace` | local MCP | `Code Workspace` | `exec_command`, `read_file`, `write_file`, `apply_patch`, `list_directory`, `search_files` |
| `browser` | local MCP | `Browser` | `search`, `navigate`, `read_page`, `click`, `type`, `press`, `wait`, `screenshot`, `download`, `tabs` |
| `github` | external connector | configuration required | exact externally supplied manifest |

Every entry records ownership, resolution settings, version, manifest path, endpoint metadata and attachment behavior. Committed local entries also lock the expected manifest SHA-256.

## Benchmark selection

Prefer stable IDs:

```json
{
  "task_id": "incident_reconstruction_001",
  "prompt": "Inspect the repository and corroborate the incident timeline.",
  "attachments": ["incident_reconstruction_001/repo.zip"],
  "tools": [
    {"type": "app", "id": "code-workspace", "required": true},
    {"type": "app", "id": "browser", "required": true},
    {"type": "app", "id": "github", "required": true}
  ]
}
```

For compatibility, `{"type":"app","name":"browser"}`, `{"type":"app","name":"Browser"}`, and string shorthand `"browser"` resolve through the registry. A mutable display name remains valid only while it equals the configured name. Unknown and duplicate logical Apps fail during benchmark loading, before ChatGPT is touched.

`required` defaults to `false`. For a required App, the completed raw conversation must contain a matching `metadata.invoked_resource.app_name`; selection alone is not sufficient.

## Code Workspace contract

All paths are relative to the owned task workspace. Absolute paths, `..`, symlink traversal and symlink targets are rejected.

| Tool | Stable behavior |
|---|---|
| `exec_command` | Runs `/bin/bash` in a confined relative directory; returns bounded stdout/stderr, exit code and timeout state; kills the whole process group at return. |
| `read_file` | Reads bounded UTF-8 text and returns size and SHA-256. |
| `write_file` | Atomically creates/replaces UTF-8 text, optionally checking the previous SHA-256. |
| `apply_patch` | Applies ordered exact replacements only when the file hash and occurrence counts match. |
| `list_directory` | Returns typed entries in deterministic path order. |
| `search_files` | Performs literal UTF-8 content search with deterministic file/line/column ordering. |

Attachments are integrity-checked and copied to `attachments/<basename>` during `prepare`. A workspace is usable only while its persisted task ID, attempt-derived environment ID and task fingerprint match.

## Browser contract

The Browser App owns a dedicated CloakBrowser process and profile. `read_page` assigns ephemeral element references such as `e1`; interaction tools reject stale or ambiguous references.

| Tool | Stable behavior |
|---|---|
| `search` | Navigates the isolated browser to the configured search provider and returns ordered public links. |
| `navigate` | Opens an allowed HTTP(S) URL in the active tab. |
| `read_page` | Returns bounded visible text plus deterministic references for visible interactive elements. |
| `click`, `type`, `press` | Interact through a current element reference or bounded key set. |
| `wait` | Waits for a bounded duration or exact visible text. |
| `screenshot` | Returns a bounded PNG as base64 with size and SHA-256. |
| `download` | Returns one bounded download as base64 with filename, size and SHA-256. |
| `tabs` | Lists, opens, selects or closes tabs in the task context. |

Navigation and subresources reject non-web schemes, URL credentials, localhost, link-local, private, reserved and metadata-network addresses. DNS answers are checked. `APP_BROWSER_ALLOWED_PRIVATE_HOSTS` is an explicit exact-host exception intended only for controlled integration fixtures.

## External GitHub connector

The logical identity is always `github`. Change its UI label without editing benchmark tasks:

```dotenv
APP_GITHUB_UI_NAME=<new visible name>
APP_GITHUB_MANIFEST_PATH=/data/apps/registry/external/github-tool-manifest.json
```

The file must be an authoritative manifest with exactly this outer shape:

```json
{"app_id":"github","version":"2.1.0","tools":[{"name":"authoritative_tool_name","description":"Exact model-visible description.","inputSchema":{"type":"object","properties":{}}}]}
```

The example shows structure only; do not use it as an operational manifest. Obtain the exact version, descriptions and schemas from the installed connector owner or source. The runner computes its SHA-256 at load time and stores the complete validated manifest. A missing manifest is a hard error.

## Inspect and flatten

```bash
docker compose run --rm --no-deps runner \
  inspect-tools /data/benchmarks/benchmark.jsonl \
  --task-id incident_reconstruction_001
```

The command prints the task fingerprint, resolved App provenance, and Qwen-compatible function definitions:

```json
{
  "type": "function",
  "function": {
    "name": "exec_command",
    "description": "Execute one shell command in the active task workspace and return bounded stdout, stderr, exit status, and timeout state.",
    "parameters": {"type": "object", "properties": {"command": {"type": "string", "minLength": 1}}, "required": ["command"]}
  }
}
```

The live output contains the complete committed schema. When names collide across Apps, the Qwen view uses `<normalized_app_id>__<tool_name>` for all members of that collision and emits `tool_identity` records mapping each function back to its canonical pair and manifest hash.

## Add or change a local App

1. Use one dedicated container and one MCP server for one coherent capability bundle.
2. Define precise Qwen-oriented tools in the App's `contracts.py` and generate the matching `tool-manifest.json`.
3. Change the semantic version for a model-visible semantic or schema change.
4. Canonicalize JSON with sorted keys and compact separators, calculate SHA-256, and update the registry's `version` and `manifest_sha256`.
5. Add an isolated control endpoint implementing identity-matched `prepare`, `resume` and `reset` if the App owns task state.
6. Add Compose isolation, healthchecks, unit tests, lifecycle/recovery tests and a real integration test.
7. Register the MCP endpoint in the ChatGPT account through an authenticated HTTPS gateway, then set its configurable UI name.

Never create source-agent-specific Apps for equivalent capabilities. Source trace normalization is a separate dataset transformation concern.
