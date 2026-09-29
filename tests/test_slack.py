import json

import pytest

from hookscope.rules import FORWARD_HEADER, ForwardRule, parse_rules
from hookscope.slack import escape, format_amount, slack_message
from tests.test_replay import Recorder
from tests.test_rules import _make_client, _post_github


def _event(source: str, body: str, headers: dict | None = None) -> dict:
    return {
        "id": 7,
        "source": source,
        "headers": headers or {},
        "body": body,
        "verification": "valid",
        "received_at": "2026-09-29T12:00:00+00:00",
    }


def _section_text(message: dict) -> str:
    return message["blocks"][0]["text"]["text"]


def test_github_pull_request_summary():
    body = json.dumps(
        {
            "action": "opened",
            "repository": {"full_name": "acme/api"},
            "sender": {"login": "octocat"},
            "pull_request": {"number": 42, "title": "Fix <script> & retries"},
        }
    )
    message = slack_message(_event("github", body), "ci-slack", "pull_request")

    assert message["text"] == "github pull_request (event #7)"
    text = _section_text(message)
    assert text.splitlines()[0] == "*github* `pull_request` · event #7"
    assert "*Repository:* acme/api" in text
    assert "*Sender:* octocat" in text
    assert "*Action:* opened" in text
    assert "*Pull request:* #42 Fix &lt;script&gt; &amp; retries" in text
    context = message["blocks"][1]["elements"][0]["text"]
    assert context == "valid · received 2026-09-29T12:00:00+00:00 · rule `ci-slack`"


def test_github_push_summary():
    body = json.dumps({"ref": "refs/heads/main", "commits": [{}, {}, {}], "repository": {"full_name": "a/b"}})
    text = _section_text(slack_message(_event("github", body), "r", "push"))
    assert "*Ref:* refs/heads/main" in text
    assert "*Commits:* 3" in text


def test_stripe_summary_formats_amount_and_test_mode():
    body = json.dumps(
        {
            "type": "invoice.paid",
            "livemode": False,
            "data": {"object": {"id": "in_123", "amount_paid": 123456, "currency": "usd", "status": "paid"}},
        }
    )
    text = _section_text(slack_message(_event("stripe", body), "billing", "invoice.paid"))
    assert "*Object:* in_123" in text
    assert "*Amount:* 1,234.56 USD" in text
    assert "*Status:* paid" in text
    assert "*Mode:* test" in text


@pytest.mark.parametrize(
    ("amount", "currency", "expected"),
    [(500, "eur", "5.00 EUR"), (1500, "JPY", "1,500 JPY"), (0, "usd", "0.00 USD")],
)
def test_format_amount(amount, currency, expected):
    assert format_amount(amount, currency) == expected


def test_generic_and_non_json_bodies():
    generic = slack_message(_event("generic", '{"id": "evt_1", "type": "order.created", "x": 1}'), "r", None)
    assert generic["text"] == "generic (event #7)"
    assert _section_text(generic).splitlines()[1:] == ["*Id:* evt_1", "*Type:* order.created"]

    raw = slack_message(_event("generic", "plain text"), "r", None)
    assert _section_text(raw).splitlines()[1:] == ["*Body:* not JSON"]
    assert _section_text(slack_message(_event("generic", "[1, 2]"), "r", None)) == "*generic* · event #7"


def test_long_values_are_clipped():
    body = json.dumps({"repository": {"full_name": "x" * 500}})
    line = _section_text(slack_message(_event("github", body), "r", "push")).splitlines()[1]
    assert line.endswith("…")
    assert len(line) < 200


def test_escape():
    assert escape("a<b>&c") == "a&lt;b&gt;&amp;c"


def test_parse_rules_reads_format():
    [rule] = parse_rules([{"name": "s", "target_url": "https://hooks.slack.test/x", "format": "slack"}])
    assert rule.format == "slack"


def test_slack_rule_posts_summary_without_provider_headers(tmp_path):
    recorder = Recorder(status_code=200)
    rule = ForwardRule("ci-slack", "https://hooks.slack.test/T0/B0/x", source="github", format="slack")
    client = _make_client(tmp_path, recorder, [rule])

    body = b'{"ref": "refs/heads/main", "repository": {"full_name": "a/b"}}'
    resp = _post_github(client, "push", body=body)

    assert resp.json()["forwarded_to"] == ["ci-slack"]
    [sent] = recorder.requests
    assert sent.headers["content-type"] == "application/json"
    assert sent.headers[FORWARD_HEADER] == "ci-slack"
    assert "x-hub-signature-256" not in sent.headers
    assert "x-github-event" not in sent.headers
    payload = json.loads(sent.content)
    assert payload["text"] == f"github push (event #{resp.json()['id']})"
    assert "*Repository:* a/b" in _section_text(payload)

    [forward] = client.get(f"/api/events/{resp.json()['id']}/forwards").json()
    assert (forward["rule"], forward["status_code"]) == ("ci-slack", 200)
