# Continuous integration

The workflow at `.github/workflows/ci.yml` runs on push, pull request, merge
queue and manual dispatch. No credentials, deployment, cloud browser, KVM,
production storage or self-hosted runner is needed for the default CI.

## Quality checks

- `validate`: syntax checks for tracked Python, JSON, TOML and YAML files, excluding
  intentional fixture data and immutable `upstream` snapshots. It checks grammar,
  not particular environment values, package numbers, host paths or benchmark
  sample counts.
- `distributed`: existing offline behavioral tests for acquisition, verification,
  recovery and transport. No live KVM or benchmark download is run.
- `services`: reads `apps/*/pyproject.toml` and test files at workflow execution
  time, creates an independent environment for each testable Python app and
  installs its declared `test` extra. A new app with tests is picked up without
  changing a CI matrix. Each app gets its own environment because dependencies
  can legitimately differ between services.
- `docker`: builds every discovered `apps/*/Dockerfile`, even when the app has
  no Python test suite. A successful build does **not** claim runtime integration.
- `browser`: tests the browser proxy's HTTP/WebSocket behavior with in-process
  aiohttp fixtures, not a live browser instance.
- `gate`: fails if any required job fails, is canceled, or is unexpectedly skipped.
  The stable check name `CI gate` is intended for a branch ruleset.
- `codeql`: runs Python code scanning on eligible public repositories (not
  untrusted fork PRs); private repositories need GitHub Code Security enabled
  before configuring an equivalent security job.

The `CI` workflow does not pretend that mocked checks prove Docker deployments,
PostgreSQL migrations against a live DB, KVM isolation, or end-to-end integration
with ChatGPT. Those require separate controlled integration environments.

## Branch protection

In GitHub: Settings → Rules → Rulesets → New branch ruleset. Target the protected
branch, require pull requests and require the status check `CI gate`. Consider
requiring CodeQL when its check is supported and enabled for the repository.
Ruleset creation is a separate repository administration action; it is **not**
performed by a CI workflow and this change does not claim it is enabled.

The default CI uses GitHub-hosted ephemeral runners with read-only repository
permissions. Do not register Fossil as a general-purpose GitHub Actions runner
for untrusted pull requests. If real KVM integration is later added, isolate its
runner, restrict workflow sources, and require approval via a protected GitHub
environment.
