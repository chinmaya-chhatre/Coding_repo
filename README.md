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

- `POST /hooks/{source}` receiver for `github`, `stripe` and `generic` HMAC-SHA256
- Signature verification with constant-time comparison
  - GitHub `X-Hub-Signature-256`
  - Stripe `Stripe-Signature` including timestamp tolerance (replay protection)
  - Generic `X-Signature`
- Rejected deliveries return `401` **but are still stored**, so you can see why they failed
- Web dashboard with per-source filtering, pretty-printed JSON and one-click replay
- JSON API: `GET /api/events`, `GET /api/events/{id}`
- Replay any captured event to another URL with its original headers, so signatures still verify
- Forwarding rules: fan accepted events out to one or more URLs by source and event type,
  with every attempt recorded (`GET /api/events/{id}/forwards`) and shown in the dashboard
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
- The event type is GitHub's `X-GitHub-Event` header, or the JSON body's `type` field
  for Stripe and generic sources.
- Only accepted events (`valid` or `no_secret`) are forwarded; rejected deliveries never are.
- Forwarding runs after HookScope has answered the provider, so a slow target never
  delays the delivery. The receive response lists the matched rules in `forwarded_to`.
- Each forward carries the original body and headers plus `X-HookScope-Forward: <rule name>`.
  Results (status code, latency, error) are available from `GET /api/events/{id}/forwards`,
  and `GET /api/rules` shows the loaded rules.
- The dashboard lists each event's forward attempts (rule, target, status, latency) and
  flags events with failed forwards in the event summary.

An invalid rules file stops HookScope at startup with a message naming the bad rule.

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
| `HOOKSCOPE_SECRET_GENERIC` | Shared secret for `X-Signature` | unset |
| `HOOKSCOPE_RULES` | Path to a JSON file of forwarding rules | unset (no forwarding) |

A source without a secret accepts every delivery and marks it `no_secret`.

## Architecture

```
provider ──POST /hooks/{source}──▶ FastAPI ──▶ signatures.verify() ──▶ EventStore (SQLite)
                                                                         │
                          browser ◀── dashboard / JSON API ◀─────────────┘
```

- `hookscope/signatures.py` — one pure function per provider, easy to unit test
- `hookscope/store.py` — thin SQLite wrapper
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
- [ ] Retry with exponential backoff + dead-letter view
- [ ] More providers: Shopify, Slack, Twilio, Svix
- [ ] Search and date-range filters in the dashboard
- [ ] Prometheus `/metrics` (deliveries by source and verification status)
- [ ] Retention policy / auto-purge
- [ ] Deploy guide (Fly.io / Render) with a public demo

## License

MIT
