"""Send a correctly signed sample webhook to a running HookScope instance.

Usage:
    HOOKSCOPE_SECRET_GITHUB=dev-secret python scripts/send_test_webhook.py github
    python scripts/send_test_webhook.py stripe --url http://localhost:8000
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse
import urllib.request

SAMPLES = {
    "github": {"action": "opened", "pull_request": {"number": 42, "title": "Add retry logic"}},
    "stripe": {"id": "evt_test_123", "type": "invoice.paid", "data": {"object": {"amount_paid": 4900}}},
    "shopify": {"id": 820982911946154508, "email": "jon@example.com", "total_price": "49.00"},
    "slack": {"type": "event_callback", "event": {"type": "app_mention", "text": "<@U123> deploy status?"}},
    "twilio": {"MessageSid": "SM123", "From": "+15551230000", "To": "+15559870000", "Body": "STATUS"},
    "svix": {"type": "invoice.paid", "data": {"id": "inv_42", "amount": 4900}},
    "generic": {"event": "user.signup", "user": {"id": 7, "plan": "pro"}},
}


def sign(source: str, body: bytes, secret: str, url: str = "") -> dict[str, str]:
    def digest(payload: bytes) -> str:
        return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    if source == "github":
        return {"X-Hub-Signature-256": f"sha256={digest(body)}", "X-GitHub-Event": "pull_request"}
    if source == "stripe":
        ts = str(int(time.time()))
        return {"Stripe-Signature": f"t={ts},v1={digest(ts.encode() + b'.' + body)}"}
    if source == "shopify":
        raw = hmac.new(secret.encode(), body, hashlib.sha256).digest()
        return {"X-Shopify-Hmac-Sha256": base64.b64encode(raw).decode(), "X-Shopify-Topic": "orders/create"}
    if source == "slack":
        ts = str(int(time.time()))
        signature = digest(b"v0:" + ts.encode() + b":" + body)
        return {"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": f"v0={signature}"}
    if source == "twilio":
        params = urllib.parse.parse_qsl(body.decode())
        payload = (url + "".join(key + value for key, value in sorted(params))).encode()
        raw = hmac.new(secret.encode(), payload, hashlib.sha1).digest()
        return {"X-Twilio-Signature": base64.b64encode(raw).decode()}
    if source == "svix":
        key = base64.b64decode(secret.removeprefix("whsec_"))
        msg_id, ts = f"msg_{int(time.time() * 1000)}", str(int(time.time()))
        raw = hmac.new(key, f"{msg_id}.{ts}.".encode() + body, hashlib.sha256).digest()
        signature = base64.b64encode(raw).decode()
        return {"svix-id": msg_id, "svix-timestamp": ts, "svix-signature": f"v1,{signature}"}
    return {"X-Signature": digest(body)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", nargs="?", default="github", choices=sorted(SAMPLES))
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--secret", help="defaults to HOOKSCOPE_SECRET_<SOURCE> or 'dev-secret'")
    args = parser.parse_args()

    # Svix secrets are base64 keys with a whsec_ prefix; "dev-secret" is not valid base64.
    default = "whsec_ZGV2LXNlY3JldC1kZXYtc2VjcmV0" if args.source == "svix" else "dev-secret"
    secret = args.secret or os.environ.get(f"HOOKSCOPE_SECRET_{args.source.upper()}", default)
    target = f"{args.url}/hooks/{args.source}"
    if args.source == "twilio":
        # Twilio posts form-encoded parameters and signs them together with the URL.
        body = urllib.parse.urlencode(SAMPLES[args.source]).encode()
        content_type = "application/x-www-form-urlencoded"
    else:
        body = json.dumps(SAMPLES[args.source]).encode()
        content_type = "application/json"
    headers = {"Content-Type": content_type, **sign(args.source, body, secret, target)}
    request = urllib.request.Request(target, data=body, headers=headers)
    try:
        with urllib.request.urlopen(request) as response:
            print(response.status, response.read().decode())
    except urllib.error.HTTPError as err:
        print(err.code, err.read().decode())


if __name__ == "__main__":
    main()
