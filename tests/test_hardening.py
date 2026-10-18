import pytest
from fastapi.testclient import TestClient

from hookscope.config import ConfigError, Settings
from hookscope.main import MAX_ID, SOURCE_PATTERN, create_app
from hookscope.store import EventStore


@pytest.fixture
def store(tmp_path):
    store = EventStore(str(tmp_path / "hard.db"))
    for i in range(5):
        store.add(source="generic", headers={}, body=f'{{"n": {i}}}', verification="valid", reason="")
    return store


@pytest.fixture
def client(store):
    return TestClient(create_app(store=store, secrets={}), raise_server_exceptions=False)


def error_code(response):
    return response.json()["error"]["code"]


# ------------------------------------------------------------------------ header limits


def post_with_headers(client, count=0, value_size=0, name="x-pad"):
    headers = {f"{name}-{i}": "v" * value_size for i in range(count)}
    return client.post("/hooks/generic", content=b"{}", headers=headers)


def test_normal_requests_are_unaffected(client):
    assert post_with_headers(client, count=20, value_size=100).status_code == 202


def test_too_many_headers_are_refused_with_431(store):
    client = TestClient(create_app(store=store, secrets={}, max_headers=15))
    assert post_with_headers(client, count=2).status_code == 202
    response = post_with_headers(client, count=30)
    assert response.status_code == 431 and error_code(response) == "headers_too_large"
    assert "too many headers" in response.json()["error"]["message"]


def test_oversized_headers_are_refused_with_431(store):
    client = TestClient(create_app(store=store, secrets={}, max_header_bytes=2000))
    assert post_with_headers(client, count=1, value_size=100).status_code == 202
    response = post_with_headers(client, count=1, value_size=5000)
    assert response.status_code == 431 and "bytes" in response.json()["error"]["message"]


def test_a_refused_request_stores_nothing(store):
    client = TestClient(create_app(store=store, secrets={}, max_headers=15))
    before = store.count()
    assert post_with_headers(client, count=30).status_code == 431
    assert store.count() == before


def test_the_header_check_runs_before_the_body_is_read(store):
    client = TestClient(create_app(store=store, secrets={}, max_headers=15, max_body_bytes=10))
    response = client.post("/hooks/generic", content=b"x" * 100, headers={f"h{i}": "v" for i in range(30)})
    assert response.status_code == 431  # not 413: the headers were judged first


def test_the_limits_come_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("HOOKSCOPE_DB", str(tmp_path / "env.db"))
    monkeypatch.setenv("HOOKSCOPE_MAX_HEADERS", "15")
    client = TestClient(create_app(secrets={}))
    assert post_with_headers(client, count=2).status_code == 202
    assert post_with_headers(client, count=30).status_code == 431


def test_header_settings_defaults_and_validation():
    default = Settings.from_env({})
    assert (default.max_headers, default.max_header_bytes) == (100, 32 * 1024)
    assert Settings.from_env({"HOOKSCOPE_MAX_HEADERS": "7"}).max_headers == 7
    with pytest.raises(ConfigError) as error:
        Settings.from_env({"HOOKSCOPE_MAX_HEADERS": "0", "HOOKSCOPE_MAX_HEADER_BYTES": "lots"})
    assert len(error.value.errors) == 2


# ------------------------------------------------------------------------ source names


@pytest.mark.parametrize("name", ["github", "stripe", "x-y_z0", "a" * 32])
def test_well_formed_source_names_match(name):
    assert SOURCE_PATTERN.fullmatch(name)


@pytest.mark.parametrize("name", ["", "GitHub", "1abc", "-x", "a b", "a\nb", "a" * 33, "../x", "x;y", "é"])
def test_malformed_source_names_do_not(name):
    assert not SOURCE_PATTERN.fullmatch(name)


@pytest.mark.parametrize(
    "raw", ["bad%0Asource", "%1B%5B31mred", "a%20b", "x" * 500, "GitHub"]
)
def test_odd_sources_are_refused_without_being_echoed_raw(client, raw):
    response = client.post(f"/hooks/{raw}", content=b"{}")
    assert response.status_code == 404 and error_code(response) == "unknown_source"
    message = response.json()["error"]["message"]
    assert "\n" not in message and "\x1b" not in message
    assert len(message) < 200, "a long name must be clipped, not reflected"


def test_known_sources_still_work(client):
    assert client.post("/hooks/generic", content=b"{}").status_code == 202


# -------------------------------------------------------------------- numbers and text


@pytest.mark.parametrize(
    "path",
    [
        f"/api/events/{MAX_ID + 1}",
        "/api/events/99999999999999999999",
        "/api/events/0",
        "/api/events/-1",
        f"/api/events/{MAX_ID + 1}/forwards",
        f"/api/events/{MAX_ID + 1}/curl",
        f"/events/{MAX_ID + 1}",
        f"/api/events?before_id={MAX_ID + 1}",
        "/api/events?before_id=-5",
        "/?before_id=99999999999999999999",
    ],
)
def test_out_of_range_ids_are_422_not_a_crash(client, path):
    response = client.get(path)
    assert response.status_code == 422, (path, response.status_code)
    assert error_code(response) == "validation_error"


def test_the_largest_valid_id_is_simply_not_found(client):
    assert client.get(f"/api/events/{MAX_ID}").status_code == 404


@pytest.mark.parametrize(
    "path", ["/api/events?limit=-1", "/api/events?limit=0", "/api/dead-letters?limit=-3"]
)
def test_a_non_positive_limit_is_refused_instead_of_returning_everything(client, path):
    response = client.get(path)
    assert response.status_code == 422
    assert response.json()["error"]["details"][0]["field"] == "query.limit"


def test_a_huge_limit_is_still_capped_not_refused(client):
    assert len(client.get("/api/events?limit=99999").json()) == 5


def test_overlong_filters_are_refused(client):
    assert client.get("/api/events?q=" + "a" * 200).status_code == 200
    for query in ("q=" + "a" * 201, "source=" + "a" * 65, "since=" + "2" * 65, "verification=" + "v" * 65):
        assert client.get(f"/api/events?{query}").status_code == 422, query
        assert client.get(f"/?{query}").status_code == 422, query


def test_the_dashboard_still_pages_and_filters(client):
    assert client.get("/?q=n&before_id=4").status_code == 200


def test_openapi_documents_the_constraints(client):
    spec = client.get("/openapi.json").json()
    limit = next(p for p in spec["paths"]["/api/events"]["get"]["parameters"] if p["name"] == "limit")
    assert limit["schema"]["minimum"] == 1
    event_id = spec["paths"]["/api/events/{event_id}"]["get"]["parameters"][0]
    assert event_id["schema"]["minimum"] == 1 and event_id["schema"]["maximum"] == MAX_ID
