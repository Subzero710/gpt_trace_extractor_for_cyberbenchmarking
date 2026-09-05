# Architecture

```text
benchmark.jsonl + artifacts
          |
          v
     +---------+        CDP        +------------------+
     | runner  | ----------------> | browser          |
     |         |                   | CloakBrowser     |
     +----+----+                   | persistent state |
          |                        +--------+---------+
          |                                 |
          |                                 v
          |                            ChatGPT UI
          |                                 |
          |      conversation JSON          |
          +---------------------------------+
          |
          | HTTP: run state + messages[]
          v
    +-------------+       SQL        +------------+
    | storage API | ----------------> | PostgreSQL |
    +-------------+                   +------------+
```

Boundaries:
- browser owns Chromium/CloakBrowser and profile state only;
- runner owns benchmark orchestration and ChatGPT UI automation only;
- storage owns durability, recovery state, and dataset export only;
- postgres is never accessed directly by runner.

The conversation ID is persisted immediately after prompt submission. On
`--resume`, a non-completed task with an existing conversation ID is recovered
before a new conversation is created.
