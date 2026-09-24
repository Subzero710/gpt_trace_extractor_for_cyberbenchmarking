# Apps and canonical tools

ChatGPT App and canonical model tool are different concepts:

- A ChatGPT App is a runtime grouping used to install and select capabilities in the teacher UI.
- A canonical tool is a stable function contract recorded for the trajectory and later exposed through provider-independent dataset views.
- The versioned App manifest is the source of truth for names and schemas. Container, MCP transport, connector and UI naming remain provenance or deployment metadata.
- Dataset-level function names are globally stable as `<normalized_app_id>__<tool_name>`; the original `(app_id, tool_name)` pair remains in provenance.

## Registry

`apps/registry/apps.json` defines these initial logical Apps:

| ID | Ownership | Default UI name | Canonical tools |
|---|---|---|---|
| `code-workspace` | local MCP | `Code Workspace` | 43 tools; authoritative list is `apps/code-workspace/tool-manifest.json` |
| `browser` | local MCP | `Cloak Browser` | 42 tools; authoritative list is `apps/browser/tool-manifest.json` |
| `github` | external connector | configuration required | exact externally supplied manifest |

Every entry records ownership, resolution settings, version, manifest path, endpoint metadata and attachment behavior. Committed local entries also lock the expected manifest SHA-256.

## Benchmark selection

Superbench adapters declare logical App IDs directly through `TaskSpec.tools` and `TaskSpec.required_tools`. Runtime resolution is ID-only; mutable ChatGPT display names are deployment metadata and never benchmark identities.

For example, an adapter task that requires both local Apps uses:

```python
TaskSpec(
    task_id="incident_reconstruction_001",
    prompt="Inspect the repository and corroborate the incident timeline.",
    tools=("code-workspace", "browser"),
    required_tools=("code-workspace", "browser"),
)
```

Unknown logical App IDs fail when the Superbench task is materialized, before ChatGPT is touched. Required Apps must appear in the captured tool provenance; selection alone is not sufficient.

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
| `export_file` | Streams one regular workspace file to the per-attempt File Relay and returns an opaque `file_id` plus integrity metadata. |
| `import_file` | Fetches one relay `file_id`, verifies size/SHA-256, and atomically materializes it at a workspace-relative path. |

For each attempt the runner creates a fresh Workspace container. Adapter-materialized `initial_workspace` content is copied to `/workspace` before the gateway is bound; direct task attachments are copied under `/workspace/attachments/<basename>`. Benchmark source volumes are never mounted into the execution container. The container is destroyed at terminal cleanup.

## Browser contract

Every Browser attempt owns a newly created CloakBrowser container and profile. `read_page` assigns ephemeral element references such as `e1`; interaction tools reject stale or ambiguous references. The entire Browser container is destroyed at terminal cleanup.

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
| `upload_file` | Uploads direct `content_base64` in Browser-only attempts or consumes a relay `file_id` for cross-App transfer. |
| `download_file` | Uses the File Relay automatically when configured; otherwise returns bounded direct base64 content for Browser-only attempts. |

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

## Add or change a local App

1. Use one coherent capability bundle and a stable MCP gateway when the backend must be ephemeral per attempt.
2. Define precise provider-neutral tools in the App's `contracts.py` and generate the matching `tool-manifest.json`.
3. Change the semantic version for a model-visible semantic or schema change.
4. Canonicalize JSON with sorted keys and compact separators, calculate SHA-256, and update the registry's `version` and `manifest_sha256`.
5. Add an isolated control endpoint implementing identity-matched `prepare`, `resume` and `reset` if the App owns task state.
6. Add Compose isolation, healthchecks, unit tests, lifecycle/recovery tests and a real integration test.
7. Register the MCP endpoint in the ChatGPT account through an authenticated HTTPS gateway, then set its configurable UI name.

Never create source-agent-specific Apps for equivalent capabilities. Source trace normalization is a separate dataset transformation concern.


## MCP Stack V2 tools

Code Workspace: exec_command, read_file, write_file, apply_patch, list_directory, search_files, workspace_delete_file, workspace_delete_directory, workspace_move, workspace_copy, workspace_create_directory, workspace_stat, workspace_tree, workspace_find, create_terminal, send_terminal_input, read_terminal_output, close_terminal, list_processes, get_process, kill_process, get_system_info, get_environment, set_environment, get_current_directory, create_python_venv, install_python_packages, run_python_script, install_system_package, git_clone, git_status, git_diff, git_log, git_branch, git_checkout, git_commit, http_request, download_url, dns_lookup, check_port, workspace_template, export_file, import_file

Browser: search, navigate, read_page, click, type, press, wait, screenshot, download, tabs, go_back, go_forward, reload, new_page, close_page, switch_page, hover, drag, select_option, upload_file, download_file, inspect_dom, query_selector, get_html, get_attribute, evaluate_javascript, get_cookies, set_cookie, clear_cookies, export_storage_state, import_storage_state, create_context, destroy_context, get_console_logs, get_network_logs, get_request_details, get_response_body, performance_trace, set_user_agent, set_viewport, set_timezone, set_geolocation
