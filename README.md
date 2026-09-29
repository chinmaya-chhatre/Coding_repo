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
- [ ] Payload transforms (JSONPath mapping between provider and internal schema)
- [ ] Retry with exponential backoff + dead-letter view
- [ ] More providers: Shopify, Slack, Twilio, Svix
- [ ] Search and date-range filters in the dashboard
- [ ] Prometheus `/metrics` (deliveries by source and verification status)
- [ ] Retention policy / auto-purge
- [ ] Deploy guide (Fly.io / Render) with a public demo

## License

MIT
