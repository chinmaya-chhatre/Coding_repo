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
- Web dashboard with per-source filtering and pretty-printed JSON
- JSON API: `GET /api/events`, `GET /api/events/{id}`
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

A source without a secret accepts every delivery and marks it `no_secret`.

## Architecture

```
provider ──POST /hooks/{source}──▶ FastAPI ──▶ signatures.verify() ──▶ EventStore (SQLite)
                                                                         │
                          browser ◀── dashboard / JSON API ◀─────────────┘
```

- `hookscope/signatures.py` — one pure function per provider, easy to unit test
- `hookscope/store.py` — thin SQLite wrapper
- `hookscope/main.py` — app factory (`create_app`) so tests inject a temp DB and secrets

## Running tests

```bash
ruff check . && pytest -q
```

## Roadmap

- [ ] Replay an event to a target URL (with original headers)
- [ ] Forward/fan-out rules (e.g. send `invoice.paid` to Slack)
- [ ] Payload transforms (JSONPath mapping between provider and internal schema)
- [ ] Retry with exponential backoff + dead-letter view
- [ ] More providers: Shopify, Slack, Twilio, Svix
- [ ] Search and date-range filters in the dashboard
- [ ] Prometheus `/metrics` (deliveries by source and verification status)
- [ ] Retention policy / auto-purge
- [ ] Deploy guide (Fly.io / Render) with a public demo

## License

MIT
