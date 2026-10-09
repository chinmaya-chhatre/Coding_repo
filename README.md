# HookScope

![CI](https://github.com/chinmaya-chhatre/Coding_repo/actions/workflows/ci.yml/badge.svg)

**Capture, verify and inspect incoming webhooks.** HookScope is a small self-hosted
tool for debugging webhook integrations: point a provider (GitHub, Stripe, or
anything that signs with HMAC) at it, and see every delivery with its headers,
payload and whether the signature checked out.

It came out of a very common integration problem: *"the webhook isn't working"*
usually means one of a wrong secret, a proxy re-encoding the body, clock skew, or
a replayed request. HookScope makes each of those visible.

## Features

- `POST /hooks/{source}` receiver for `github`, `stripe`, `shopify`, `slack`, `twilio`, `svix` and `generic` signed webhooks
- Signature verification with constant-time comparison
  - GitHub `X-Hub-Signature-256`
  - Stripe `Stripe-Signature` including timestamp tolerance (replay protection)
  - Shopify `X-Shopify-Hmac-Sha256` (base64 digest)
  - Slack `X-Slack-Signature` with `X-Slack-Request-Timestamp` tolerance; the Events API
    `url_verification` handshake is answered automatically
  - Twilio `X-Twilio-Signature` (HMAC-SHA1 of the request URL plus sorted form parameters,
    or the `bodySHA256` query parameter for JSON bodies)
  - Svix / [Standard Webhooks](https://www.standardwebhooks.com/) `svix-signature` or
    `webhook-signature` (`v1,<base64>` of `id.timestamp.body`, timestamp tolerance, multiple
    signatures for secret rotation)
  - Generic `X-Signature`
- Rejected deliveries return `401` **but are still stored**, so you can see why they failed
- Web dashboard with per-source tabs, text search, date-range and signature-status filters, pretty-printed JSON and one-click replay
- Prometheus metrics at `GET /metrics`: deliveries by source and verification result,
  forward attempts by rule and outcome, and the dead-letter count
- JSON API: `GET /api/events`, `GET /api/events/{id}`. `/api/events` filters with `source`,
  `verification`, `q` (case-insensitive text in the body or headers) and `since` / `until`
  (ISO dates or datetimes, UTC unless an offset is given; a date-only `until` covers the whole day)
- Replay any captured event to another URL with its original headers, so signatures still verify
- Forwarding rules: fan accepted events out to one or more URLs by source and event type,
  with every attempt recorded (`GET /api/events/{id}/forwards`) and shown in the dashboard
- Forward retries: re-send failed forwards with exponential backoff, honouring `Retry-After`
- Dead letters: forwards that exhausted their retries (or failed permanently) are listed in the
  dashboard and `GET /api/dead-letters`, with one-click re-send
- Slack forwarding: post a readable event summary (repo, sender, PR, Stripe amount...) to a
  Slack incoming webhook
- Payload transforms: reshape a provider payload into your own schema with JSONPath mappings
  (including wildcards, `..` recursive descent and `[?(...)]` filters) before forwarding it
- Transform preview: try a rule's transform (or an ad-hoc one) against any stored event,
  from the dashboard or with `POST /api/events/{id}/transform-preview`
- SQLite storage, Docker image, CI on every push

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

export HOOKSCOPE_SECRET_GITHUB=dev-secret
uvicorn hookscope.main:app --reload
```

In another terminal, send a signed sample event, then open http://localhost:8000:

```bash
python scripts/send_test_webhook.py github                 # 202, valid
python scripts/send_test_webhook.py github --secret wrong  # 401, signature mismatch
```

### Replaying an event

Re-send a captured delivery to a local dev server or staging endpoint, without
asking the provider to send it again:

```bash
curl -X POST http://localhost:8000/api/events/1/replay \
  -H 'Content-Type: application/json' \
  -d '{"target_url": "http://localhost:3000/webhooks/github"}'
```

You can also replay from the dashboard: expand an event, enter a target URL and
click **Replay**. The last target URL is remembered in your browser.

The body and original headers (including the signature) are forwarded, plus an
`X-HookScope-Replay: <event id>` header so the target can tell replays apart. The
response reports the target's status code, latency and the start of its response
body; `502` means the target could not be reached at all.

> HookScope sends replays to whatever URL you give it, so only expose the API on
> networks you trust.

### Forwarding rules

Fan accepted deliveries out to other services automatically. Put rules in a JSON
file and point `HOOKSCOPE_RULES` at it:

```json
{
  "rules": [
    {"name": "billing", "source": "stripe", "event_types": ["invoice.paid"],
     "target_url": "https://billing.internal/webhooks/stripe"},
    {"name": "ci", "source": "github", "event_types": ["push", "pull_request"],
     "target_url": "http://localhost:3000/github"},
    {"name": "audit", "target_url": "https://audit.internal/hooks"}
  ]
}
```

- `source` and `event_types` are optional; leaving one out matches everything.
- The event type is GitHub's `X-GitHub-Event` header, Shopify's `X-Shopify-Topic` header
  (e.g. `orders/create`), the inner `event.type` of Slack `event_callback` payloads
  (e.g. `app_mention`), or the JSON body's `type` field for Stripe, Svix and generic sources.
- Only accepted events (`valid` or `no_secret`) are forwarded; rejected deliveries never are.
- Forwarding runs after HookScope has answered the provider, so a slow target never
  delays the delivery. The receive response lists the matched rules in `forwarded_to`.
- Each forward carries the original body and headers plus `X-HookScope-Forward: <rule name>`.
  Results (status code, latency, error) are available from `GET /api/events/{id}/forwards`,
  and `GET /api/rules` shows the loaded rules.
- The dashboard lists each event's forward attempts (rule, target, status, latency) and
  flags events with failed forwards in the event summary.

An invalid rules file stops HookScope at startup with a message naming the bad rule.

#### Retrying failed forwards

By default each forward is attempted once. Give a rule a `retry` policy to re-send
transient failures with exponential backoff:

```json
{"name": "ci", "source": "github", "target_url": "http://localhost:3000/github",
 "retry": {"attempts": 4, "backoff_seconds": 2, "max_backoff_seconds": 60}}
```

- Retried: no response at all (connection refused, timeout), `408`, `425`, `429` and `5xx`.
  Successes and other `4xx` responses are final.
- The wait after attempt *n* is `backoff_seconds × 2^(n-1)` (2 s, 4 s, 8 s above), raised to
  the target's `Retry-After` (seconds or an HTTP date) when it sends one, and capped at
  `max_backoff_seconds`.
- `attempts` is 1–10; `backoff_seconds` defaults to 1 and `max_backoff_seconds` to 60
  (at most 3600). `"retry": 3` is short for `{"attempts": 3}`.
- Every attempt is stored with its `attempt` number, in the forwards API and the dashboard.
  All matched rules get their first attempt immediately; a rule that is backing off does
  not delay the others.
- Retries run inside the HookScope process, so pending retries are lost on restart.

#### Dead letters and re-sending

A forward becomes a *dead letter* when its latest attempt failed and nothing will retry it:
the retries are used up, the target answered with a permanent error (a non-retryable `4xx`),
or the rule is no longer in the rules file. A forward that is still backing off is not
listed. The dashboard shows them in a **Dead letters** section at the top, and the API lists
them too:

```bash
curl http://localhost:8000/api/dead-letters
curl -X POST http://localhost:8000/api/events/1/forwards/ci/resend
```

Re-send forwards the stored event once more through the same rule (same transform or Slack
format, current target URL) and records it as the next attempt. If it succeeds the entry
leaves the list; if not, it stays with the new result. Re-send answers `200` with the
target's outcome (`ok`, `status_code`, ...), `502` when the target can't be reached, and
`404` for an unknown event or rule, or one the rule never forwarded. Entries whose rule has
been removed are listed but can't be re-sent.

#### Sending events to Slack

Add `"format": "slack"` to a rule and use a Slack
[incoming webhook](https://api.slack.com/messaging/webhooks) URL as the target:

```json
{"name": "gh-to-slack", "source": "github", "event_types": ["pull_request", "push"],
 "format": "slack", "target_url": "https://hooks.slack.com/services/T000/B000/XXXX"}
```

Instead of the raw payload, HookScope posts a short message with the source, event type
and event id, the fields you usually look for first (GitHub repository, sender, action,
ref, PR/issue number and title, commit count; Stripe object id, amount, status and test
mode; `id`/`type` for generic payloads), and the verification status and rule name.
The provider's headers, including its signature, are not sent to Slack. The default
`"format": "raw"` keeps the original forwarding behaviour.

#### Transforming payloads

Add a `transform` to a rule to forward your own JSON document instead of the provider's
payload. Each key maps to a JSONPath expression over the event body, an `@` reference to
event metadata, or a nested object:

```json
{"name": "orders", "source": "stripe", "event_types": ["checkout.session.completed"],
 "target_url": "https://orders.internal/events",
 "transform": {
   "order_id": "$.data.object.id",
   "amount": "$.data.object.amount_total",
   "items": "$.data.object.line_items.data[*].price.id",
   "meta": {"source": "@source", "type": "@event_type", "hookscope_id": "@event_id"}
 }}
```

- Supported JSONPath: `$`, `.key`, `['key']`, `[n]` (negative counts from the end), the
  wildcards `[*]` / `.*`, and recursive descent `..` (`$..id` finds every `id` at any depth;
  `$..[0]` and `$..*` work too), and filters `[?(...)]`. A path with a wildcard, `..` or a
  filter returns a list of every match; any other path returns one value, or `null` when
  nothing matches (or the body isn't JSON).
- Filters keep the list elements (or object values) that match a condition, where `@` is
  the element: `$.commits[?(@.author.name == 'octocat')].id`, `$..[?(@.amount > 1000)]`,
  `$.labels[?(@ == 'bug')]`. Compare `@` paths (`.key`, `['key']`, `[n]`) with each other or
  with strings, numbers, `true`, `false` and `null` using `==` `!=` `<` `<=` `>` `>=`; a bare
  `@.key` tests that the field exists; combine conditions with `&&`, `||`, `!` and
  parentheses. Types are kept apart (`true` isn't `1`, `"3"` isn't `3`), `<`/`>` only compare
  two numbers or two strings, and a missing field equals nothing, so `@.x != 1` also keeps
  elements without `x`.
- Metadata references: `@source`, `@event_type`, `@event_id`, `@received_at`, `@verification`.
- The transformed document is sent as `application/json` with `X-HookScope-Forward`. The
  provider's headers are dropped, since its signature would not match the new body.
- A transform can't be combined with `"format": "slack"`. Invalid paths stop HookScope at
  startup with a message naming the rule.

To check a mapping before relying on it, preview it against an event HookScope has
already captured. Send either the name of a loaded rule or an ad-hoc `transform`:

```bash
curl -X POST http://localhost:8000/api/events/1/transform-preview \
  -H 'Content-Type: application/json' -d '{"rule": "orders"}'

curl -X POST http://localhost:8000/api/events/1/transform-preview \
  -H 'Content-Type: application/json' \
  -d '{"transform": {"order_id": "$.data.object.id", "type": "@event_type"}}'
```

The response holds the `output` document that would be forwarded, the event's
`event_type`, and for a rule, `matches`: whether that rule would actually forward this
event (source, event type and verification status). Nothing is sent anywhere. An invalid
mapping or a rule without a transform returns `422`; an unknown event or rule, `404`.

The dashboard has the same preview under each event: pick a rule to preview its transform
(its mapping is shown so you can see what it does), or write a mapping as JSON. Editing a
rule's mapping switches to an ad-hoc preview, so you can start from a rule and try changes
before putting them in the rules file.

### Metrics

`GET /metrics` serves Prometheus text format, with no extra dependencies:

| Metric | Type | Labels |
|---|---|---|
| `hookscope_deliveries_total` | counter | `source`, `verification` (`valid`, `invalid`, `unsigned`, `no_secret`) |
| `hookscope_forward_attempts_total` | counter | `rule`, `outcome` (`success` = 2xx, else `failure`) |
| `hookscope_dead_letters` | gauge | none |
| `hookscope_info` | gauge | `version` |

Counts are read from SQLite on each scrape, so they survive restarts. Every known
source/status pair is exported even at 0, so rates and alerts work from the start:

```yaml
scrape_configs:
  - job_name: hookscope
    static_configs:
      - targets: ["localhost:8000"]
```

For example, alert when signatures start failing:
`sum by (source) (rate(hookscope_deliveries_total{verification="invalid"}[5m])) > 0`.

### Docker

```bash
docker build -t hookscope .
docker run -p 8000:8000 -e HOOKSCOPE_SECRET_GITHUB=dev-secret -v hookscope-data:/data hookscope
```

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| `HOOKSCOPE_DB` | SQLite file path | `hookscope.db` |
| `HOOKSCOPE_SECRET_GITHUB` | GitHub webhook secret | unset |
| `HOOKSCOPE_SECRET_STRIPE` | Stripe endpoint signing secret (`whsec_...`) | unset |
| `HOOKSCOPE_SECRET_SHOPIFY` | Shopify app client secret (signs webhooks) | unset |
| `HOOKSCOPE_SECRET_SLACK` | Slack app signing secret | unset |
| `HOOKSCOPE_SECRET_TWILIO` | Twilio account auth token | unset |
| `HOOKSCOPE_SECRET_SVIX` | Svix / Standard Webhooks endpoint secret (`whsec_...`) | unset |
| `HOOKSCOPE_SECRET_GENERIC` | Shared secret for `X-Signature` | unset |
| `HOOKSCOPE_RULES` | Path to a JSON file of forwarding rules | unset (no forwarding) |
| `HOOKSCOPE_RETENTION_DAYS` | Delete events older than this many days (decimals allowed) | unset (keep forever) |
| `HOOKSCOPE_MAX_EVENTS` | Keep only the newest N events | unset (no cap) |
| `HOOKSCOPE_PURGE_INTERVAL_SECONDS` | Minimum time between automatic purges | `300` |

A source without a secret accepts every delivery and marks it `no_secret`.

Retention runs in the background after incoming deliveries, at most once per purge
interval, and removes expired events together with their forward attempts. A burst can
briefly exceed `HOOKSCOPE_MAX_EVENTS` until the next purge; set the interval to `0` to
enforce the limits after every delivery. Invalid values stop the app at startup.

Twilio signs the exact public URL it calls, so behind a reverse proxy or TLS terminator
run uvicorn with `--proxy-headers --forwarded-allow-ips='*'` (or your proxy's IP) so the
scheme and host HookScope sees match what Twilio signed.

## Architecture

```
provider ──POST /hooks/{source}──▶ FastAPI ──▶ signatures.verify() ──▶ EventStore (SQLite)
                                                                         │
                          browser ◀── dashboard / JSON API ◀─────────────┘
```

- `hookscope/signatures.py` — one pure function per provider, easy to unit test
- `hookscope/store.py` — thin SQLite wrapper
- `hookscope/metrics.py` — Prometheus text exposition built from stored counts
- `hookscope/replay.py` — re-sends a stored event with its original headers
- `hookscope/rules.py` — forwarding rules: parsing, matching and sending
- `hookscope/slack.py` — turns an event into a Slack message for `"format": "slack"` rules
- `hookscope/transform.py` — JSONPath subset and `transform` mappings for forwarding rules
- `hookscope/main.py` — app factory (`create_app`) so tests inject a temp DB and secrets

## Running tests

```bash
ruff check . && pytest -q
```

## Roadmap

- [x] Replay an event to a target URL (with original headers)
- [x] Replay button in the dashboard
- [x] Forward/fan-out rules by source and event type (JSON rules file, attempts recorded)
- [x] Forward attempts shown in the dashboard
- [x] Forwarding follow-up: Slack message formatting
- [x] Payload transforms (JSONPath mapping between provider and internal schema)
- [x] Transform preview API (`POST /api/events/{id}/transform-preview`)
- [x] JSONPath recursive descent (`..`) in transforms
- [x] Transform preview in the dashboard
- [x] Transforms follow-up: JSONPath filter expressions (`[?(...)]`)
- [x] Retry failed forwards with exponential backoff (per-rule `retry` policy, `Retry-After`)
- [x] Dead-letter view: forwards that exhausted their retries, with one-click re-send
- [x] More providers: Shopify, Slack (with URL verification), Twilio, Svix / Standard Webhooks
- [x] Search and date-range filters (dashboard form and `GET /api/events` parameters)
- [x] Prometheus `/metrics` (deliveries by source and verification status, forwards, dead letters)
- [ ] Retention policy / auto-purge (age and count limits purge automatically; manual purge endpoint next)
- [ ] Deploy guide (Fly.io / Render) with a public demo

## License

MIT
