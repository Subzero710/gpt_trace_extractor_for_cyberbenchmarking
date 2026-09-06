# Architecture

```text
benchmark.jsonl + artifacts + requested Apps
                    |
                    v
               +---------+
               | runner  |
               +----+----+
                    |
          CDP       |      HTTP
       +------------+------------+
       |                         |
       v                         v
+--------------+          +-------------+
| browser      |          | storage API |
| CloakBrowser |          +------+------+
| profile      |                 |
+------+-------+                 | SQL
       |                         v
       v                   +------------+
   ChatGPT UI              | PostgreSQL |
       |                   +------------+
       |
       | POST /backend-api/f/conversation
       | long-lived SSE for one turn
       v
 runner waits on response completion
       |
       | one authenticated snapshot fetch
       v
 /backend-api/conversations/<id>
       |
       v
 messages[] -> storage
```

Boundaries:

- browser owns Chromium/CloakBrowser and persistent ChatGPT state;
- runner owns benchmark parsing, App selection, uploads, stream observation,
  orchestration, and snapshot capture;
- storage owns durable run state, runtime metadata, and dataset export;
- PostgreSQL is never accessed directly by runner.

`messages[]` is the canonical dataset payload. Network-stream information is
operational metadata only.
