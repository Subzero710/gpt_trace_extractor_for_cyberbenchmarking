# Benchmark tools

A benchmark task may request ChatGPT Apps:

```json
{
  "task_id": "cyber_0001",
  "prompt": "Inspect the repository and relevant GitHub state.",
  "attachments": ["cyber_0001/repo.zip"],
  "tools": [
    {
      "type": "app",
      "name": "Github (mosaic)",
      "required": true
    }
  ]
}
```

String shorthand is accepted:

```json
"tools": ["Github (mosaic)"]
```

The runner invokes each requested App through ChatGPT's `@mention` UI before
typing the prompt. The App must already be installed/connected for the account
stored in the persistent browser profile.

`required` defaults to `false`. If it is `true`, the final conversation snapshot
must contain a tool message whose `metadata.invoked_resource.app_name` matches
the requested App, otherwise the task fails.

This is intentionally not arbitrary function-schema injection. For custom cyber
tools, expose the tool to ChatGPT as an installed App/MCP integration and use
its ChatGPT-visible name in `tools`.
