# Model tools

The only local MCP App is `kali-workstation` 3.0.0 (`Kali Workstation`). Its authoritative tool contract is `apps/kali-workstation/tool-manifest.json`, generated from `kali_workstation.contracts`. A mismatch prevents the controller from starting. The registry stores the canonical SHA-256 and exposes one gateway and one tunnel. The external GitHub connector remains separate.

General tools: `exec_command`, `create_terminal`, `send_terminal_input`, `read_terminal_output`, `close_terminal`, `resize_terminal`, `observe_screen`, `computer_input`, `import_file`, `export_file`.

Browser tools: `navigate`, `new_page`, `list_pages`, `close_page`, `switch_page`, `go_back`, `go_forward`, `reload`, `click`, `type_text`, `press`, `hover`, `drag`, `select_option`, `query_selector`, `inspect_dom`, `get_html`, `get_attribute`, `evaluate_javascript`, `get_cookies`, `set_cookie`, `clear_cookies`, `get_console_logs`, `get_network_logs`, `get_request_details`, `get_response_body`, `upload_file`, `download_file`.

Context creation/destruction, storage-state import/export, user-agent, viewport, timezone and geolocation settings are control-plane provisioning, so they are absent from the model manifest. The historical `search`, `read_page`, `tabs`, `wait`, `screenshot` and `download` shortcuts are absent; `observe_screen` serves desktop screenshots. Linux operations are performed with `exec_command` and ordinary guest programs.
