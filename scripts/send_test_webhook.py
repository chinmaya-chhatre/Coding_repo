"""Send a correctly signed sample webhook to a running HookScope instance.

Usage:
    HOOKSCOPE_SECRET_GITHUB=dev-secret python scripts/send_test_webhook.py github
    python scripts/send_test_webhook.py stripe --url http://localhost:8000
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import time
import urllib.request

SAMPLES = {
    "github": {"action": "opened", "pull_request": {"number": 42, "title": "Add retry logic"}},
    "stripe": {"id": "evt_test_123", "type": "invoice.paid", "data": {"object": {"amount_paid": 4900}}},
    "generic": {"event": "user.signup", "user": {"id": 7, "plan": "pro"}},
}


def sign(source: str, body: bytes, secret: str) -> dict[str, str]:
    def digest(payload: bytes) -> str:
        return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    if source == "github":
        return {"X-Hub-Signature-256": f"sha256={digest(body)}", "X-GitHub-Event": "pull_request"}
    if source == "stripe":
        ts = str(int(time.time()))
        return {"Stripe-Signature": f"t={ts},v1={digest(ts.encode() + b'.' + body)}"}
    return {"X-Signature": digest(body)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", nargs="?", default="github", choices=sorted(SAMPLES))
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--secret", help="defaults to HOOKSCOPE_SECRET_<SOURCE> or 'dev-secret'")
    args = parser.parse_args()

    secret = args.secret or os.environ.get(f"HOOKSCOPE_SECRET_{args.source.upper()}", "dev-secret")
    body = json.dumps(SAMPLES[args.source]).encode()
    headers = {"Content-Type": "application/json", **sign(args.source, body, secret)}
    request = urllib.request.Request(f"{args.url}/hooks/{args.source}", data=body, headers=headers)
    try:
        with urllib.request.urlopen(request) as response:
            print(response.status, response.read().decode())
    except urllib.error.HTTPError as err:
        print(err.code, err.read().decode())


if __name__ == "__main__":
    main()
