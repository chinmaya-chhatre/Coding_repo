"""docs/demo/signing.js (Web Crypto, runs in the browser) against published vectors and HookScope itself."""

import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from hookscope import signatures

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None, reason="Node.js is needed to run the demo's signing code"
)

DEMO = Path(__file__).parent.parent / "docs" / "demo"
PAGE = (DEMO / "index.html").read_text(encoding="utf-8")


def sign_all(jobs: list[dict]) -> list[dict]:
    """Run each job through signing.js in Node: [{provider, options}] -> [{headers, signedString}]."""
    script = """
    const s = require(process.argv[1]);
    const jobs = JSON.parse(process.argv[2]);
    Promise.all(jobs.map(j => s.sign(j.provider, j.options)))
      .then(r => console.log(JSON.stringify(r)), e => { console.error(e.message); process.exit(1); });
    """
    out = subprocess.run(
        ["node", "-e", script, str(DEMO / "signing.js"), json.dumps(jobs)],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(out.stdout)


def sign_one(provider: str, **options) -> dict:
    return sign_all([{"provider": provider, "options": options}])[0]


# Published examples: GitHub, Slack, Twilio and Svix documentation.
def test_github_docs_vector():
    result = sign_one("github", body="Hello, World!", secret="It's a Secret to Everybody")
    assert result["headers"] == {
        "X-Hub-Signature-256": "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
    }


def test_slack_docs_vector():
    body = (
        "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V"
        "&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text="
        "&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN"
        "&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c"
    )
    result = sign_one("slack", body=body, secret="8f742231b10e8888abcd99yyyzzz85a5", timestamp=1531420618)
    assert result["headers"]["X-Slack-Signature"] == (
        "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503"
    )
    assert result["headers"]["X-Slack-Request-Timestamp"] == "1531420618"


def test_twilio_docs_vector_ignores_parameter_order():
    url = "https://mycompany.com/myapp.php?foo=1&bar=2"
    forward = (
        "CallSid=CA1234567890ABCDE&Caller=%2B12349013030&Digits=1234&From=%2B12349013030&To=%2B18005551212"
    )
    reverse = (
        "To=%2B18005551212&From=%2B12349013030&Digits=1234&Caller=%2B12349013030&CallSid=CA1234567890ABCDE"
    )
    for body in (forward, reverse):
        result = sign_one("twilio", body=body, secret="12345", url=url)
        assert result["headers"] == {"X-Twilio-Signature": "0/KCTR6DLpKmkAf8muzZqo1nDgQ="}


def test_svix_docs_vector():
    result = sign_one(
        "svix",
        body='{"test": 2432232314}',
        secret="whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",
        msgId="msg_p5jXN8AQM9LWM0D4loKWxJek",
        timestamp=1614265330,
    )
    assert result["headers"]["svix-signature"] == "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="


def test_svix_standard_webhooks_prefix():
    result = sign_one(
        "svix", body="{}", secret="whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw", timestamp=1, prefix="webhook"
    )
    assert set(result["headers"]) == {"webhook-id", "webhook-timestamp", "webhook-signature"}


def test_unknown_provider_is_rejected():
    with pytest.raises(subprocess.CalledProcessError):
        sign_one("nope", body="x", secret="y")


# Every provider card on the page, signed by signing.js, must pass HookScope's real verifier.
def _providers() -> list[dict]:
    import re

    block = re.search(r'<script type="application/json" id="providers">(.*?)</script>', PAGE, re.S).group(1)
    return json.loads(block)


def test_every_demo_provider_verifies_in_hookscope():
    providers = _providers()
    now = int(time.time())
    jobs = [
        {
            "provider": p["id"],
            "options": {"body": p["body"], "secret": p["secret"], "url": p.get("url", ""), "timestamp": now},
        }
        for p in providers
    ]
    for provider, signed in zip(providers, sign_all(jobs), strict=True):
        headers = {"Content-Type": provider["contentType"], **provider["extraHeaders"], **signed["headers"]}
        result = signatures.verify(
            provider["id"],
            provider["body"].encode(),
            headers,
            provider["secret"],
            url=provider.get("url", ""),
        )
        assert result.status == "valid", f"{provider['id']}: {result.reason}"


def test_changing_a_byte_makes_hookscope_reject_the_signature():
    for provider in _providers():
        tampered = provider["body"] + " "
        if provider["id"] == "twilio":
            tampered = provider["body"] + "&Extra=1"
        signed = sign_one(
            provider["id"], body=provider["body"], secret=provider["secret"], url=provider.get("url", "")
        )
        result = signatures.verify(
            provider["id"],
            tampered.encode(),
            signed["headers"],
            provider["secret"],
            url=provider.get("url", ""),
        )
        assert result.status == "invalid", provider["id"]
