import json

import httpx
import pytest
from fastapi.testclient import TestClient

from hookscope import cli
from hookscope.main import create_app
from hookscope.samples import build_sample
from hookscope.store import EventStore

SECRET = "sample-secret"


class Target:
    """What the replayed event is sent to, as seen by HookScope's own HTTP client."""

    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.answer = lambda request: httpx.Response(200, text="got it")

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.answer(request)


@pytest.fixture(autouse=True)
def no_password(monkeypatch):
    monkeypatch.delenv("HOOKSCOPE_ADMIN_PASSWORD", raising=False)


@pytest.fixture
def target():
    return Target()


def build(tmp_path, target, password=None):
    app = create_app(
        store=EventStore(str(tmp_path / "replay.db")),
        secrets={"github": SECRET},
        http_client=httpx.Client(transport=httpx.MockTransport(target)),
        admin_password=password,
    )
    return TestClient(app)


@pytest.fixture
def server(tmp_path, target):
    client = build(tmp_path, target)
    sample = build_sample("github", SECRET, url="https://h.example/hooks/github")
    assert client.post("/hooks/github", content=sample.body, headers=sample.headers).status_code == 202
    return client


def route(client):
    def send_request(url, body, headers):
        response = client.post(url.removeprefix("http://hookscope.test"), content=body, headers=headers)
        return response.status_code, response.text

    return send_request


def replay(client, *argv):
    args = cli.build_parser().parse_args(["replay", "--url", "http://hookscope.test", *argv])
    return cli.replay(args, send_request=route(client))


def test_a_stored_event_is_sent_to_the_target(server, target, capsys):
    assert replay(server, "1", "--to", "https://target.test/hook") == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "replayed event #1 to https://target.test/hook"
    assert out[1].startswith("HTTP 200 in ") and out[2] == "got it"
    [request] = target.requests
    assert str(request.url) == "https://target.test/hook" and request.method == "POST"


def test_the_original_signature_headers_go_along(server, target):
    replay(server, "1", "--to", "https://target.test/hook")
    [request] = target.requests
    assert request.headers["x-hub-signature-256"].startswith("sha256=")
    assert request.headers["x-hookscope-replay"] == "1"


def test_a_target_error_status_is_exit_one_and_shown(server, target, capsys):
    target.answer = lambda request: httpx.Response(500, text="boom")
    assert replay(server, "1", "--to", "https://target.test/hook") == 1
    out = capsys.readouterr().out
    assert "HTTP 500" in out and "boom" in out


def test_an_unreachable_target_is_exit_one_with_the_reason(server, target, capsys):
    def refuse(request):
        raise httpx.ConnectError("refused")

    target.answer = refuse
    assert replay(server, "1", "--to", "https://target.test/hook") == 1
    assert "no response: " in capsys.readouterr().out


def test_json_prints_the_answer_of_the_api(server, capsys):
    assert replay(server, "1", "--to", "https://target.test/hook", "--json") == 0
    answer = json.loads(capsys.readouterr().out)
    assert answer["status_code"] == 200 and answer["ok"] is True and answer["target_url"].endswith("/hook")


def test_an_unknown_event_is_exit_two_with_hookscopes_message(server, capsys):
    assert replay(server, "99", "--to", "https://target.test/hook") == 2
    assert "hookscope: event not found" in capsys.readouterr().err


def test_a_bad_target_url_is_exit_two_and_nothing_is_sent(server, target, capsys):
    assert replay(server, "1", "--to", "ftp://target.test") == 2
    assert "absolute http(s) URL" in capsys.readouterr().err and target.requests == []


def test_a_password_protected_server_asks_for_the_password(tmp_path, target, capsys):
    client = build(tmp_path, target, password="hunter2")
    assert replay(client, "1", "--to", "https://target.test/hook") == 2
    assert "HOOKSCOPE_ADMIN_PASSWORD" in capsys.readouterr().err


def test_the_password_from_the_environment_is_used(tmp_path, target, monkeypatch, capsys):
    client = build(tmp_path, target, password="hunter2")
    sample = build_sample("github", SECRET, url="https://h.example/hooks/github")
    client.post("/hooks/github", content=sample.body, headers=sample.headers)
    monkeypatch.setenv("HOOKSCOPE_ADMIN_PASSWORD", "hunter2")
    assert replay(client, "1", "--to", "https://target.test/hook") == 0


def test_an_unreachable_hookscope_is_exit_two(capsys):
    args = cli.build_parser().parse_args(["replay", "1", "--to", "https://t.test"])
    assert cli.replay(args, send_request=lambda *a: (None, "connection refused")) == 2
    assert "could not reach http://127.0.0.1:8000: connection refused" in capsys.readouterr().err


def test_a_reply_that_is_not_json_is_reported_not_crashed(capsys):
    args = cli.build_parser().parse_args(["replay", "1", "--to", "https://t.test"])
    assert cli.replay(args, send_request=lambda *a: (502, "<html>Bad gateway</html>")) == 2
    assert "Bad gateway" in capsys.readouterr().err


def test_the_request_goes_to_the_right_endpoint_as_json():
    seen = {}

    def capture(url, body, headers):
        seen.update(url=url, body=json.loads(body), headers=headers)
        return 404, '{"error": {"code": "event_not_found", "message": "event not found"}}'

    args = cli.build_parser().parse_args(["replay", "7", "--to", "https://t.test", "--url", "http://h:1/"])
    cli.replay(args, send_request=capture)
    assert seen["url"] == "http://h:1/api/events/7/replay"
    assert (
        seen["body"] == {"target_url": "https://t.test"}
        and seen["headers"]["Content-Type"] == "application/json"
    )


@pytest.mark.parametrize("argv", [["replay"], ["replay", "abc", "--to", "https://t.test"], ["replay", "1"]])
def test_the_arguments_are_checked(argv):
    with pytest.raises(SystemExit) as stop:
        cli.build_parser().parse_args(argv)
    assert stop.value.code == 2


def test_the_command_is_wired_into_main(capsys):
    # Nothing listens on port 9, so this goes through main() and the real network layer and fails cleanly.
    assert cli.main(["replay", "1", "--to", "https://t.test", "--url", "http://127.0.0.1:9"]) == 2
    assert "could not reach" in capsys.readouterr().err
