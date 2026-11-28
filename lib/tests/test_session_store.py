from datetime import datetime, timedelta, timezone

import pytest

import session_store


def user(**overrides) -> dict:
    record = {
        "name": "Ada",
        "username": "ada@example.com",
        "oid": "oid-1",
        "tid": "tid-1",
        "roles": ["App.Reader", "", None, 1, "App.Admin"],
        "login_hint": "ada@example.com",
    }
    record.update(overrides)
    return record


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(session_store, "DB_PATH", tmp_path / "sessions.db")
    session_store.initialize_database()
    return session_store


def test_with_role_list_keeps_only_nonempty_strings():
    original = user(roles=["App.Reader", "", None, "App.Admin", 2])

    normalized = session_store.with_role_list(original)

    assert normalized["roles"] == ["App.Reader", "App.Admin"]
    assert normalized["oid"] == "oid-1"
    assert original["roles"] == ["App.Reader", "", None, "App.Admin", 2]


@pytest.mark.parametrize("roles", [None, "App.Admin", 5, {"role": "App.Admin"}])
def test_with_role_list_replaces_non_lists(roles):
    assert session_store.with_role_list(user(roles=roles))["roles"] == []


def test_with_role_list_defaults_missing_roles():
    record = user()
    del record["roles"]

    assert session_store.with_role_list(record)["roles"] == []


def test_create_session_stores_normalized_user_for_one_hour(store):
    before = datetime.now(timezone.utc)
    session_id = store.create_session(user())
    after = datetime.now(timezone.utc)

    loaded = store.get_session(session_id)

    assert isinstance(session_id, str) and session_id
    assert loaded["username"] == "ada@example.com"
    assert loaded["oid"] == "oid-1"
    assert loaded["roles"] == ["App.Reader", "App.Admin"]
    with store.get_connection() as conn:
        row = conn.execute(
            "SELECT expires_at FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
    expires_at = datetime.fromisoformat(row["expires_at"])
    assert before + timedelta(hours=1) <= expires_at <= after + timedelta(hours=1)


def test_create_session_ids_are_unique(store):
    first = store.create_session(user())
    second = store.create_session(user(oid="oid-2"))

    assert first != second
    assert store.get_session(second)["oid"] == "oid-2"


def test_touch_session_extends_live_expiry_by_one_hour(store):
    session_id = store.create_session(user())
    other_id = store.create_session(user(oid="other"))
    created_at = "2026-06-01T00:00:00+00:00"
    original_expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    with store.get_connection() as conn:
        conn.execute(
            "UPDATE sessions SET created_at = ?, expires_at = ? WHERE session_id = ?",
            (created_at, original_expiry, session_id),
        )
        conn.execute(
            "UPDATE sessions SET created_at = ?, expires_at = ? WHERE session_id = ?",
            (created_at, original_expiry, other_id),
        )

    before = datetime.now(timezone.utc)
    store.touch_session(session_id)
    store.touch_session("missing")
    after = datetime.now(timezone.utc)

    with store.get_connection() as conn:
        rows = conn.execute("SELECT session_id, created_at, expires_at FROM sessions").fetchall()
    by_id = {row["session_id"]: row for row in rows}
    expires_at = datetime.fromisoformat(by_id[session_id]["expires_at"])
    assert before + timedelta(hours=1) <= expires_at <= after + timedelta(hours=1)
    assert by_id[session_id]["created_at"] == created_at
    assert by_id[other_id]["created_at"] == created_at
    assert by_id[other_id]["expires_at"] == original_expiry


def test_touch_session_leaves_expired_row_unchanged(store):
    session_id = store.create_session(user())
    expired = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    with store.get_connection() as conn:
        conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE session_id = ?",
            (expired, session_id),
        )

    store.touch_session(session_id)

    with store.get_connection() as conn:
        row = conn.execute(
            "SELECT expires_at FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
    assert row["expires_at"] == expired


def test_get_session_returns_none_for_unknown_id(store):
    assert store.get_session("missing") is None


def test_get_session_deletes_expired_row(store):
    session_id = store.create_session(user())
    expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with store.get_connection() as conn:
        conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE session_id = ?",
            (expired, session_id),
        )

    assert store.get_session(session_id) is None
    with store.get_connection() as conn:
        row = conn.execute(
            "SELECT session_id FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
    assert row is None


def test_delete_session_removes_only_the_named_row(store):
    kept = store.create_session(user(oid="kept"))
    removed = store.create_session(user(oid="removed"))

    store.delete_session(removed)
    store.delete_session("missing")

    assert store.get_session(removed) is None
    assert store.get_session(kept)["oid"] == "kept"


def test_delete_session_row_returns_cookie_value(store):
    session_id = store.create_session(user())
    with store.get_connection() as conn:
        row_id = conn.execute(
            "SELECT rowid FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()["rowid"]

    assert store.delete_session_row(row_id) == session_id
    assert store.get_session(session_id) is None
    assert store.delete_session_row(row_id) is None


def test_list_sessions_orders_newest_first_and_marks_current(store):
    older = store.create_session(user(oid="older"))
    newer = store.create_session(user(oid="newer"))
    with store.get_connection() as conn:
        conn.execute(
            "UPDATE sessions SET created_at = ? WHERE session_id = ?",
            ("2026-01-01T00:00:00+00:00", older),
        )
        conn.execute(
            "UPDATE sessions SET created_at = ? WHERE session_id = ?",
            ("2026-06-01T00:00:00+00:00", newer),
        )

    listed = store.list_sessions(newer)

    assert [row["user"]["oid"] for row in listed] == ["newer", "older"]
    assert [row["is_current"] for row in listed] == [True, False]
    assert listed[0]["created_at"] == datetime.fromisoformat("2026-06-01T00:00:00+00:00")
    assert listed[0]["expires_at"] > listed[0]["created_at"]


def test_list_and_create_drop_expired_sessions(store):
    expired_id = store.create_session(user(oid="expired"))
    live_id = store.create_session(user(oid="live"))
    expired = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    with store.get_connection() as conn:
        conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE session_id = ?",
            (expired, expired_id),
        )

    assert [row["user"]["oid"] for row in store.list_sessions(live_id)] == ["live"]

    store.create_session(user(oid="created-after"))
    with store.get_connection() as conn:
        remaining = conn.execute("SELECT user_oid FROM sessions ORDER BY user_oid").fetchall()
    assert [row["user_oid"] for row in remaining] == ["created-after", "live"]
