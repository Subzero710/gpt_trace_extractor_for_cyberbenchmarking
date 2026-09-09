# App registry

`apps.json` maps stable logical App IDs to runtime UI names, endpoints and exact
canonical tool manifests. Local manifests are committed beside each App and
their SHA-256 values are locked in the registry.

The `github` entry is external. Before a GitHub task can be parsed, set
`APP_GITHUB_UI_NAME` to the connector name currently visible in ChatGPT and set
`APP_GITHUB_MANIFEST_PATH` to an audited canonical manifest exported from that
connector. The manifest must have `app_id: "github"`, a semantic version, and
the exact `name`, `description`, and `inputSchema` of every model-visible tool.
The runner refuses a GitHub task if either value is absent or invalid.
