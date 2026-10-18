# HookScope v2 roadmap

One checkbox = one commit: a self-contained slice with its tests, lint-clean, green CI.
Items tagged **[owner]** need something only the repo owner can do (an account, a repo setting);
skip them until the tag is cleared. Work in phase order; within a phase, top to bottom.

## Schedule (about 4 commits a day, shared with integration-cookbook)

| Dates | HookScope phases |
|---|---|
| Oct 12 – Oct 25 | PD Portfolio demo (pulled forward), P1 Foundations, P2 Failure explainer, P3 CLI |
| Oct 26 – Nov 8 | P4 Rules and delivery, P5 Durable queue |
| Nov 9 – Nov 22 | P6 Storage, P7 Auth and secrets, P8 Observability |
| Nov 23 – Dec 6 | P9 More providers, P10 Packaging, docs, deploy |
| Dec 7 – Dec 25 | Buffer: anything blocked, skipped, or worth redoing |

Finishing early is fine. Never add an item just to keep a streak.

## PD Portfolio demo (4)
A self-contained page for the owner's portfolio site (static, uploaded to S3), in `docs/demo/`.
No backend: signatures are computed in the browser with Web Crypto.
- [x] PD.01 `docs/demo/` page shell matching the portfolio's look (tokens, light/dark, nav-compatible), provider picker and sample payloads for all 7 providers
- [x] PD.02 In-browser signing for each provider (GitHub, Stripe, Shopify, Slack, Twilio, Svix, generic), checked against the providers' published vectors in a test
- [x] PD.03 Verify panel: valid/invalid result, "tamper with the body" and "wrong secret" buttons, Stripe/Slack timestamp tolerance
- [x] PD.04 Handover: single-file build, upload notes, snippets for the portfolio's playground card and nav entry

## P1 Foundations and API quality (14)
- [x] P1.01 `config.py`: one `Settings` object parsed from env (secrets, retention, body limit, password, rules path, db path); report all invalid values together at startup
- [x] P1.02 Pydantic response models for events, forwards and dead letters; typed OpenAPI schemas
- [x] P1.03 OpenAPI metadata: tags, summaries, descriptions, examples; `/docs` behind the password
- [x] P1.04 Cursor pagination for `GET /api/events` (`before_id`; the `next` cursor is the `X-Next-Cursor` header so the body stays a list)
- [x] P1.05 Dashboard "older events" paging on top of the cursor
- [x] P1.06 Event permalink page `/events/{id}` (shareable detail view)
- [x] P1.07 "Copy as curl": rebuild the original request from a stored event
- [x] P1.08 Request-ID middleware: accept or generate `X-Request-ID`, return it, store it on the event
- [x] P1.09 Structured JSON logs (`HOOKSCOPE_LOG_FORMAT=json`) carrying the request id
- [x] P1.10 `/readyz` (database writable) alongside the cheap `/healthz`
- [x] P1.11 SQLite WAL mode and busy timeout; test concurrent writers
- [x] P1.12 One error shape (`{"error": {"code", "message"}}`) across the API, with tests
- [ ] P1.13 Input hardening: caps on header count and size, strict `source` path characters
- [ ] P1.14 Provider registry: each provider as one object (verifier, event type, event id, samples); replaces the scattered `if source ==` branches

## P2 Signature failure explainer (12)
- [ ] P2.01 `diagnostics` module: `Diagnosis(cause, message, fix)`, run only for `invalid` / `unsigned` events
- [ ] P2.02 Detector: headers from the wrong provider (GitHub header sent to `/hooks/stripe`)
- [ ] P2.03 Detector: body was re-encoded (compact vs pretty JSON, key order, trailing newline, CRLF, BOM) by re-verifying variants
- [ ] P2.04 Detector: secret has stray whitespace, a newline or quotes
- [ ] P2.05 Detector: timestamp skew in seconds (clock drift vs replay) for Stripe, Slack, Svix
- [ ] P2.06 Detector: Twilio URL mismatch (http/https, trailing slash, port, query order); say which URL was signed
- [ ] P2.07 Detector: `whsec_` prefix / base64 secret misuse (Stripe, Svix)
- [ ] P2.08 Detector: wrong scheme (sha1 vs sha256, hex vs base64)
- [ ] P2.09 Persist the diagnosis on the event (migration) and return it in the API
- [ ] P2.10 Dashboard "Why did this fail?" panel with the one-line fix
- [ ] P2.11 Metric `hookscope_signature_failures_total{source,cause}`
- [ ] P2.12 Troubleshooting guide generated from the detector registry; a test keeps the doc in sync

## P3 Command-line tool (10)
- [ ] P3.01 `python -m hookscope serve` (uvicorn wrapper; flags override env)
- [ ] P3.02 `hookscope send <provider>` replaces `scripts/send_test_webhook.py`; all providers; scenarios: good, bad secret, tampered body, stale timestamp
- [ ] P3.03 `hookscope tail`: follow events with `--source`, `--verification`, `--json`
- [ ] P3.04 `hookscope replay <id> --to URL`
- [ ] P3.05 `hookscope verify`: check a saved request offline (provider, secret, body file, headers) and print the diagnosis
- [ ] P3.06 `hookscope config`: effective settings with secrets masked
- [ ] P3.07 `hookscope purge` (calls the API)
- [ ] P3.08 `hookscope export` to NDJSON
- [ ] P3.09 `hookscope import` from NDJSON; round-trip test
- [ ] P3.10 `[project]` metadata and console script in `pyproject.toml`; build the wheel in CI

## P4 Rules and delivery features (22)
- [ ] P4.01 Rule `where` conditions: JSONPath predicates (equals, in, gt/lt, exists)
- [ ] P4.02 `where` in the dashboard preview: show which rules would match an event
- [ ] P4.03 Rules table in SQLite; loader merges read-only file rules with stored rules
- [ ] P4.04 `GET` / `POST /api/rules` with validation (reuse `parse_rules`)
- [ ] P4.05 `PUT` / `DELETE /api/rules/{name}`
- [ ] P4.06 Rule `enabled` flag (pause without deleting)
- [ ] P4.07 Rule change history (who, when, before/after)
- [ ] P4.08 Dashboard: rules list page
- [ ] P4.09 Dashboard: add/edit rule form with live validation
- [ ] P4.10 Dashboard: "test rule on this event" dry run showing the exact request that would be sent
- [ ] P4.11 Import/export rules as JSON (API and UI)
- [ ] P4.12 Per-rule custom headers with `${env:NAME}` references (outbound auth to the target)
- [ ] P4.13 Per-rule timeout override
- [ ] P4.14 Outbound signing: sign forwards with an HMAC so the target can verify them
- [ ] P4.15 Provider event-id extraction stored on the event (Stripe `id`, GitHub delivery GUID, Shopify webhook id, Svix id)
- [ ] P4.16 Duplicate detection: mark duplicates, do not forward them again; `duplicate_of` in the API
- [ ] P4.17 Dashboard badge and filter for duplicates
- [ ] P4.18 Stable `X-HookScope-Event-Id` on every forward attempt (idempotency key for the target)
- [ ] P4.19 Per-target circuit breaker (open after N failures, half-open probe)
- [ ] P4.20 Circuit state in the dashboard and metrics
- [ ] P4.21 Per-rule rate limit / max concurrency (token bucket)
- [ ] P4.22 Rule `priority` and `stop` (stop matching after this rule)

## P5 Durable delivery queue (12)
- [ ] P5.01 ADR: why background tasks are not enough (lost on crash) and the at-least-once design
- [ ] P5.02 `deliveries` table: event, rule, attempt, state, `next_attempt_at`
- [ ] P5.03 Enqueue deliveries in the same transaction as the event insert
- [ ] P5.04 Worker loop claiming due jobs with a lease / visibility timeout
- [ ] P5.05 Schedule retries via `next_attempt_at` instead of sleeping in the worker
- [ ] P5.06 Startup recovery of pending and leased jobs; crash-simulation test
- [ ] P5.07 Graceful shutdown: finish or release in-flight jobs
- [ ] P5.08 Backpressure: bounded in-flight work; metric `hookscope_queue_depth`
- [ ] P5.09 Dead-letter state stored in the queue; dashboard and API read from it
- [ ] P5.10 Manual re-send enqueues a job
- [ ] P5.11 Job expiry (maximum age) with a recorded reason
- [ ] P5.12 Soak-test script and results in the docs

## P6 Storage (12)
- [ ] P6.01 Versioned migrations (`schema_version`); port the existing ad-hoc `_migrate`
- [ ] P6.02 `Storage` protocol; SQLite implements it, fully typed
- [ ] P6.03 Contract test suite that runs against any storage
- [ ] P6.04 Postgres storage: pool and schema (optional `psycopg` extra)
- [ ] P6.05 Postgres: events, forwards and deliveries
- [ ] P6.06 Postgres: search (`ILIKE`), indexes, purge
- [ ] P6.07 `HOOKSCOPE_DATABASE_URL` selection with startup validation
- [ ] P6.08 `docker-compose` with Postgres and HookScope
- [ ] P6.09 CI job with a Postgres service running the contract suite
- [ ] P6.10 `hookscope migrate` SQLite to Postgres
- [ ] P6.11 Backup and restore guide; `hookscope backup` for SQLite (online backup API)
- [ ] P6.12 Perf comparison doc: 200k events, SQLite vs Postgres

## P7 Auth and secrets (13)
- [ ] P7.01 API tokens table (hashed), create and revoke
- [ ] P7.02 Token scopes `read`, `replay`, `admin`, enforced per route
- [ ] P7.03 `hookscope token create | list | revoke`
- [ ] P7.04 Read-only dashboard role (no replay or purge controls)
- [ ] P7.05 Login page with a signed session cookie (Basic stays for scripts)
- [ ] P7.06 CSRF protection for dashboard actions
- [ ] P7.07 Login rate limiting with backoff
- [ ] P7.08 Logout and session expiry settings
- [ ] P7.09 Admin audit log (replay, purge, rule and token changes): table, API, dashboard page
- [ ] P7.10 Several secrets per source (current + previous); report which one matched
- [ ] P7.11 Rotation API/CLI with an overlap window and a metric for which secret verified
- [ ] P7.12 `*_FILE` env convention for Docker/Kubernetes secrets
- [ ] P7.13 Threat-model doc (assets, trust boundaries, mitigations) and `SECURITY.md`

## P8 Observability and performance (10)
- [ ] P8.01 Latency histograms: receive handler and forwards by rule
- [ ] P8.02 Counters: 413 rejects, auth failures, purged events, duplicates, retries
- [ ] P8.03 Grafana dashboard JSON with a screenshot in the docs
- [ ] P8.04 Compose profile: Prometheus and Grafana preconfigured
- [ ] P8.05 Prometheus alert rules (signature-failure spike, dead letters, queue depth)
- [ ] P8.06 Optional OpenTelemetry tracing (extra): spans for receive, verify, forward
- [ ] P8.07 k6 load test for signed `/hooks` traffic; results in the docs
- [ ] P8.08 Fix the top findings from the load test, with before/after numbers
- [ ] P8.09 Profile the verification path; change only what the profile shows
- [ ] P8.10 SLO doc: targets and which metrics measure them

## P9 More providers (8)
- [ ] P9.01 HubSpot v3 (`X-HubSpot-Signature-v3`: method + URI + body + timestamp)
- [ ] P9.02 Linear (`Linear-Signature`, timestamp window)
- [ ] P9.03 Zendesk (`X-Zendesk-Webhook-Signature` with timestamp)
- [ ] P9.04 Mailgun (signature inside the body)
- [ ] P9.05 SendGrid signed events (ECDSA; optional `cryptography` extra)
- [ ] P9.06 Discord interactions (Ed25519)
- [ ] P9.07 "Add a provider" contributor guide with a test template
- [ ] P9.08 Provider matrix doc: header, algorithm, replay protection, event type, event id

Each provider is checked against the vendor's published example before it is committed.

## P10 Packaging, docs, CI, deploy (18)
- [ ] P10.01 `CHANGELOG.md`, versioning policy, release workflow on tags
- [ ] P10.02 Publish the Docker image to GHCR on tag **[owner: set package visibility to public after the first push]**
- [ ] P10.03 Multi-arch image (amd64, arm64)
- [ ] P10.04 Dependabot config and a `pip-audit` job
- [ ] P10.05 CodeQL workflow
- [ ] P10.06 Coverage report with a threshold gate
- [ ] P10.07 `mypy` in CI, starting with `store` and `signatures`
- [ ] P10.08 `pre-commit` config, `CONTRIBUTING.md`, issue and PR templates
- [ ] P10.09 Kubernetes manifests (kustomize base + overlay), validated with `kubeconform` in CI
- [ ] P10.10 Helm chart with `helm lint` in CI
- [ ] P10.11 Terraform module for AWS (ECS Fargate, ALB, EFS), checked with `terraform validate` in CI (never applied)
- [ ] P10.12 Terraform example, cost note and teardown instructions
- [ ] P10.13 MkDocs site skeleton, built in CI **[owner: set Pages source to "GitHub Actions"]**
- [ ] P10.14 Docs: architecture and request lifecycle with diagrams
- [ ] P10.15 ADRs: SQLite default, durable queue, header redaction, Basic auth, provider registry
- [ ] P10.16 Operations runbook: each alert, what it means, what to do
- [ ] P10.17 Interactive demo page (covers every provider) in `docs/` **[owner: Pages setting]**
- [ ] P10.18 README restructure: quick start, links to docs, demo, cookbook

## Out of scope
A hosted public instance (needs the owner's account), PyPI publishing, anything that runs `terraform apply`.
