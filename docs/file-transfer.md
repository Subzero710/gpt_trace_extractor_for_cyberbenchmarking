# Ephemeral file transfer

Browser and Code Workspace remain separate filesystem security domains. They do
not share a writable volume and neither runtime can mount or inspect the other
runtime's files. Binary payloads do not transit MCP JSON or the model context.

For attempts containing both local Apps, the runner creates an ephemeral File
Relay plus two internal transfer networks:

```
workspace -- relay-workspace-net --+
                                    | File Relay
browser   -- relay-browser-net -----+
```

The relay is not an MCP server. The model sees only `export_file`,
`import_file`, `upload_file`, and `download_file`; tool results contain an
opaque non-secret `file_id`, size, SHA-256 and display metadata.

The relay is push/pull only. It has no Docker socket, host mount, runtime
filesystem mount, or Internet-facing network. Its root filesystem is read-only
and `/data` is a bounded `nosuid,nodev,noexec` tmpfs. It runs non-root with all
Linux capabilities dropped and `no-new-privileges`.

Each attempt receives distinct HMAC-derived runtime credentials. A credential
authorizes only its task/attempt/app identity. Object ACLs additionally require
the caller to be the target App. File IDs are random identifiers, never bearer
credentials, and there is deliberately no list/search endpoint.

Uploads are streamed into `<file_id>.partial`, hashed, size-checked, fsynced and
atomically renamed to `<file_id>.blob` before becoming READY. Downloads remain
retryable after interruption. Consumers materialize into a local temporary
file, verify size/SHA-256, atomically commit locally, then ACK. ACK removes the
relay payload. TTL and attempt teardown provide additional cleanup.

The relay treats all content as opaque bytes. Filenames and media types are
untrusted display metadata and are never used as relay paths. Archives, PDFs,
images and executables are not parsed or executed.

Configured limits cover per-file bytes, total attempt bytes, object count,
concurrent uploads/downloads, TTL and filename length. Docker additionally
bounds memory, CPU and PIDs.

The legacy Browser base64 upload/download contract remains available only when
explicitly requested. Relay-backed transfer is the normal path when the relay
is configured.

This mechanism protects filesystem and transport boundaries; it is not a DLP
or policy engine. If an authorized agent deliberately copies readable secret
material into an exported file, the relay cannot infer that the bytes should
not be transferred.

Recovery uses deterministic container/network names and Docker labels. Relay
secrets are derived again from the runner control secret and are not persisted
in runtime metadata. Destroying an attempt removes runtime containers, relay
container, transfer networks and the relay tmpfs.
