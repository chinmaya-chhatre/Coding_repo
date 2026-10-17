import sqlite3
import threading
import time

import pytest
from fastapi.testclient import TestClient

from hookscope.config import ConfigError, Settings
from hookscope.main import create_app
from hookscope.store import DEFAULT_BUSY_TIMEOUT_MS, EventStore


def add(store: EventStore, n: int = 0) -> int:
    return store.add(
        source="generic", headers={"x": str(n)}, body=f'{{"n": {n}}}', verification="valid", reason=""
    )


# ------------------------------------------------------------------------------ the mode


def test_wal_is_the_default_and_is_stored_in_the_file(tmp_path):
    path = str(tmp_path / "wal.db")
    store = EventStore(path)
    assert store.journal_mode == "wal"
    with sqlite3.connect(path) as conn:  # a fresh connection sees it: it lives in the database file
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_the_classic_journal_can_be_chosen(tmp_path):
    store = EventStore(str(tmp_path / "delete.db"), journal_mode="delete")
    assert store.journal_mode == "delete"


def test_an_existing_rollback_journal_database_is_converted(tmp_path):
    path = str(tmp_path / "old.db")
    add(EventStore(path, journal_mode="delete"))
    store = EventStore(path)  # reopened with the default
    assert store.journal_mode == "wal" and store.count() == 1


def test_connections_use_the_configured_busy_timeout(tmp_path):
    store = EventStore(str(tmp_path / "t.db"), busy_timeout_ms=1234)
    with store._connect() as conn:
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 1234
        assert conn.execute("PRAGMA synchronous").fetchone()[0] == 1  # NORMAL, safe with a WAL
    assert EventStore(str(tmp_path / "t.db")).busy_timeout_ms == DEFAULT_BUSY_TIMEOUT_MS


def test_synchronous_stays_default_without_wal(tmp_path):
    store = EventStore(str(tmp_path / "d.db"), journal_mode="delete")
    with store._connect() as conn:
        assert conn.execute("PRAGMA synchronous").fetchone()[0] == 2  # FULL


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [({"journal_mode": "memory"}, "journal_mode"), ({"busy_timeout_ms": 0}, "busy_timeout")],
)
def test_invalid_arguments_are_refused(tmp_path, kwargs, message):
    with pytest.raises(ValueError, match=message):
        EventStore(str(tmp_path / "x.db"), **kwargs)


# --------------------------------------------------------------------------- concurrency


def test_many_writers_at_once_all_succeed(tmp_path):
    store = EventStore(str(tmp_path / "writers.db"))
    errors: list[Exception] = []

    def worker(offset: int) -> None:
        try:
            for i in range(25):
                add(store, offset * 100 + i)
        except Exception as exc:  # noqa: BLE001 - the test reports any failure
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert store.count() == 200
    assert len({event["id"] for event in store.list(limit=500)}) == 200


def test_writers_and_readers_run_together(tmp_path):
    store = EventStore(str(tmp_path / "mixed.db"))
    stop = threading.Event()
    errors: list[Exception] = []
    reads: list[int] = []

    def reader() -> None:
        while not stop.is_set():
            try:
                reads.append(len(store.list(limit=50)))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    readers = [threading.Thread(target=reader) for _ in range(3)]
    for thread in readers:
        thread.start()
    try:
        for i in range(100):
            add(store, i)
    finally:
        stop.set()
        for thread in readers:
            thread.join()
    assert errors == [] and store.count() == 100 and reads


def hold_a_read_open(path: str) -> sqlite3.Connection:
    """A reader in the middle of a query, as a slow dashboard page load would be."""
    reader = sqlite3.connect(path, isolation_level=None)
    reader.execute("BEGIN")
    reader.execute("SELECT COUNT(*) FROM events").fetchone()  # takes the read snapshot
    return reader


def test_a_slow_reader_does_not_block_a_writer_under_wal(tmp_path):
    store = EventStore(str(tmp_path / "wal-read.db"), busy_timeout_ms=200)
    add(store)
    reader = hold_a_read_open(store.path)
    try:
        started = time.monotonic()
        add(store, 1)  # would fail with "database is locked" after 0.2 s without a WAL
        assert time.monotonic() - started < 0.15
    finally:
        reader.execute("ROLLBACK")
        reader.close()
    assert store.count() == 2


def test_the_classic_journal_does_block_in_the_same_situation(tmp_path):
    """The contrast that explains why WAL is the default."""
    store = EventStore(str(tmp_path / "delete-read.db"), journal_mode="delete", busy_timeout_ms=200)
    add(store)
    reader = hold_a_read_open(store.path)
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            add(store, 1)
    finally:
        reader.execute("ROLLBACK")
        reader.close()


def test_a_writer_waits_for_its_turn_instead_of_failing(tmp_path):
    store = EventStore(str(tmp_path / "wait.db"), busy_timeout_ms=3000)
    holder = sqlite3.connect(
        store.path, isolation_level=None, check_same_thread=False
    )  # committed by a timer
    holder.execute("BEGIN IMMEDIATE")  # another writer mid-transaction
    threading.Timer(0.3, lambda: holder.execute("COMMIT")).start()
    started = time.monotonic()
    add(store)  # blocks until the holder commits, then succeeds
    assert 0.25 < time.monotonic() - started < 2.5
    holder.close()
    assert store.count() == 1


def test_a_writer_gives_up_after_the_busy_timeout(tmp_path):
    store = EventStore(str(tmp_path / "giveup.db"), busy_timeout_ms=200)
    holder = sqlite3.connect(store.path, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        started = time.monotonic()
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            add(store)
        assert 0.15 < time.monotonic() - started < 1.5
    finally:
        holder.execute("ROLLBACK")
        holder.close()


# -------------------------------------------------------------------------------- settings


def test_settings_defaults_and_values():
    default = Settings.from_env({})
    assert (default.db_journal_mode, default.db_busy_timeout_ms) == ("wal", 5000)
    custom = Settings.from_env(
        {"HOOKSCOPE_DB_JOURNAL_MODE": " DELETE ", "HOOKSCOPE_DB_BUSY_TIMEOUT_MS": "250"}
    )
    assert (custom.db_journal_mode, custom.db_busy_timeout_ms) == ("delete", 250)


def test_invalid_database_settings_are_reported_together():
    with pytest.raises(ConfigError) as error:
        Settings.from_env({"HOOKSCOPE_DB_JOURNAL_MODE": "fast", "HOOKSCOPE_DB_BUSY_TIMEOUT_MS": "soon"})
    assert len(error.value.errors) == 2


def test_the_app_builds_its_store_from_the_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("HOOKSCOPE_DB", str(tmp_path / "app.db"))
    monkeypatch.setenv("HOOKSCOPE_DB_JOURNAL_MODE", "delete")
    client = TestClient(create_app(secrets={}))
    assert client.post("/hooks/generic", content=b"{}").status_code == 202
    with sqlite3.connect(tmp_path / "app.db") as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "delete"


def test_the_default_app_runs_in_wal(tmp_path, monkeypatch):
    monkeypatch.setenv("HOOKSCOPE_DB", str(tmp_path / "default.db"))
    client = TestClient(create_app(secrets={}))
    assert client.post("/hooks/generic", content=b"{}").status_code == 202
    with sqlite3.connect(tmp_path / "default.db") as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_readyz_still_works_under_wal(tmp_path):
    store = EventStore(str(tmp_path / "ready.db"))
    assert TestClient(create_app(store=store, secrets={})).get("/readyz").status_code == 200
