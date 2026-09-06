# ChatGPT turn stream

This document records only protocol behavior observed in the local HAR captures
used while building the runner. It is an internal ChatGPT web-product protocol,
not a public API contract.

## Request

A submitted ChatGPT turn produced:

```text
POST /backend-api/f/conversation
Accept: text/event-stream
Content-Type response: text/event-stream
```

`/backend-api/f/conversation/prepare` is a different request and must not be
treated as the turn stream.

## Observed lifecycle

The normal turn HAR showed this shape:

```text
resume_conversation_token
input_message
assistant work
assistant final
patch: /message/status -> finished_successfully
patch: /message/end_turn -> true
message_marker: last_token / last
server_ste_metadata
message_stream_complete
conversation_detail_metadata
[DONE]
```

The tool-call HAR showed that commentary, tool calls, tool results, reasoning
recap, and final answer all remained inside the same long-lived
`POST /backend-api/f/conversation` response.

Intermediate assistant messages may be:

```text
status=finished_successfully
end_turn=false
```

Therefore `finished_successfully` is not a terminal-turn signal.

## Runner terminal condition

The response itself must finish successfully and its body must contain all of:

1. a final assistant message whose delta reaches `end_turn=true`;
2. `message_stream_complete`;
3. terminal SSE `data: [DONE]`.

`last_token` is recorded as diagnostics but is not required.

After those conditions are satisfied, the runner performs one authenticated
conversation snapshot fetch and verifies that the persisted final assistant
message also has `end_turn=true`.

## Runtime metadata

The parser may retain non-content diagnostics such as:

- `conversation_id`;
- `request_id`;
- `turn_exchange_id`;
- `tool_invoked`;
- `tool_name`;
- stream start/completion timestamps;
- HTTP status/content-type;
- event count.

The raw SSE body is not stored by default.

## Recovery

A runner restart cannot re-attach to an HTTP response that already existed in a
previous process. Recovery therefore performs one conversation snapshot. An
already-finished conversation can be recovered; an incomplete one is not
silently duplicated.

A future resume implementation should only be added after capturing and testing
the actual reload-during-generation protocol.
