# Runtime guardrails

The runner drives the real ChatGPT web frontend through one persistent browser
profile. It does not reproduce Sentinel, conversation-preparation, or security
tokens itself.

Normal task lifecycle:

1. wait until the existing ChatGPT frontend is READY;
2. use visible New chat / attachment / Apps UI controls;
3. paste the prepared benchmark prompt through Chromium's clipboard path;
4. arm the `/backend-api/f/conversation` response observer before Send;
5. wait for the one long-lived SSE response to complete;
6. reuse a conversation snapshot already requested by the frontend when one is
   available, otherwise make one browser-context fallback fetch;
7. persist and only then advance to the next task.

Batch circuit breakers stop all later tasks on authentication loss, rate limits,
access denials, failed/interminable interstitials, ambiguous submissions, broken
conversation streams, storage failures, or accidental concurrent turns. A
transient page/interstitial is allowed to resolve by the browser/site without
reloads or repeated submits.

`BROWSER_FINGERPRINT_SEED` is generated once per installation and stored in the
ignored `.env`. Browser healthchecks and runner CDP connections use that same
seed; it is never rotated per task.
