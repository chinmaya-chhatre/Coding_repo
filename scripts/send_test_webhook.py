"""Send a correctly signed sample webhook to a running HookScope instance.

Usage:
    HOOKSCOPE_SECRET_GITHUB=dev-secret python scripts/send_test_webhook.py github
    python scripts/send_test_webhook.py stripe --url http://localhost:8000

The sample and its signature come from ``hookscope.samples``, the same code behind
``POST /api/providers/<name>/test``.
"""

from __future__ import annotations

import argparse
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hookscope.providers import PROVIDERS  # noqa: E402
from hookscope.samples import build_sample  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", nargs="?", default="github", choices=sorted(PROVIDERS))
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--secret", help="defaults to HOOKSCOPE_SECRET_<SOURCE> or 'dev-secret'")
    args = parser.parse_args()

    # Svix secrets are base64 keys with a whsec_ prefix; "dev-secret" is not valid base64.
    default = "whsec_ZGV2LXNlY3JldC1kZXYtc2VjcmV0" if args.source == "svix" else "dev-secret"
    secret = args.secret or os.environ.get(f"HOOKSCOPE_SECRET_{args.source.upper()}", default)
    target = f"{args.url}/hooks/{args.source}"
    sample = build_sample(args.source, secret, url=target)
    request = urllib.request.Request(target, data=sample.body, headers=sample.headers)
    try:
        with urllib.request.urlopen(request) as response:
            print(response.status, response.read().decode())
    except urllib.error.HTTPError as err:
        print(err.code, err.read().decode())


if __name__ == "__main__":
    main()
