import json
import hashlib
import secrets
import sqlite3

from datetime import datetime, timedelta, timezone
from pathlib import Path


DB_PATH = Path(__file__).resolve().parent / "sessions.db"


CREATE_SESSIONS_TABLE = """
    CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        user_oid TEXT NOT NULL,
        user_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
    )
"""

CREATE_SESSIONS_USER_OID_INDEX = """
    CREATE INDEX IF NOT EXISTS idx_sessions_user_oid
    ON sessions(user_oid)
"""


def hash_session_id(session_id: str) -> str:
    """Return the SHA-256 hash of a session ID."""
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def get_connection() -> sqlite3.Connection:
    """Open a SQLite connection to the session database."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database() -> None:
    """Create the sessions table and its index when they do not exist."""
    with get_connection() as conn:
        conn.execute(CREATE_SESSIONS_TABLE)
        conn.execute(CREATE_SESSIONS_USER_OID_INDEX)


def with_role_list(user: dict) -> dict:
    """Return a copy whose roles value is always a list of strings."""
    roles = user.get("roles")
    if isinstance(roles, list):
        roles = [role for role in roles if isinstance(role, str) and role]
    else:
        roles = []
    return {**user, "roles": roles}


def delete_expired_sessions(conn) -> None:
    """Delete sessions whose expiry time has passed."""

    q = "DELETE FROM sessions WHERE expires_at <= ?"
    params = (datetime.now(timezone.utc).isoformat(),)
    conn.execute(q, params)


def create_session(user: dict) -> str:
    """Store a user for one hour and return the new session id."""

    user = with_role_list(user)
    session_id = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=1)
    q = """
        INSERT INTO sessions
            (session_id, user_oid, user_json, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?)
        """

    params = (
        hash_session_id(session_id),
        user["oid"],
        json.dumps(user),
        now.isoformat(),
        expires_at.isoformat(),
    )

    with get_connection() as conn:
        delete_expired_sessions(conn)
        conn.execute(q, params)

    return session_id


def touch_session(session_id: str) -> None:
    """Extend a live session so it expires one hour from now."""
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=1)
    q = """
        UPDATE sessions
        SET expires_at = ?
        WHERE session_id = ? AND expires_at > ?
        """
    params = (expires_at.isoformat(), hash_session_id(session_id), now.isoformat())
    with get_connection() as conn:
        conn.execute(q, params)


def get_session(session_id: str | None) -> dict | None:
    """Return the user for a session id, or None when it is missing or expired."""
    if not session_id:
        return None

    params = (hash_session_id(session_id),)
    with get_connection() as conn:
        q = "SELECT user_json, expires_at FROM sessions WHERE session_id = ?"
        row = conn.execute(q, params).fetchone()

        if row is None:
            return None

        expires_at = datetime.fromisoformat(row["expires_at"])

        if datetime.now(timezone.utc) >= expires_at:
            q = "DELETE FROM sessions WHERE session_id = ?"
            conn.execute(q, params)
            return None

        return with_role_list(json.loads(row["user_json"]))


def delete_session(session_id: str) -> None:
    """Delete the session with this id."""
    with get_connection() as conn:
        q = "DELETE FROM sessions WHERE session_id = ?"
        params = (hash_session_id(session_id),)
        conn.execute(q, params)


def delete_session_row(row_id: int) -> str | None:
    """Delete one row by its SQLite row id. Return the stored session hash if a row was removed."""

    params = (row_id,)
    with get_connection() as conn:
        q = "SELECT session_id FROM sessions WHERE rowid = ?"
        row = conn.execute(q, params).fetchone()
        if row is None:
            return None
        q = "DELETE FROM sessions WHERE rowid = ?"
        conn.execute(q, params)
        return row["session_id"]


def list_sessions(current_session_id: str | None = None) -> list[dict]:
    """Return active sessions, newest first, marking the caller's session."""

    current_hash = hash_session_id(current_session_id) if current_session_id else None
    q = """
        SELECT rowid, session_id, user_json, created_at, expires_at
        FROM sessions
        ORDER BY created_at DESC
        """
    with get_connection() as conn:
        delete_expired_sessions(conn)

        rows = conn.execute(q).fetchall()

        return [
            {
                "id": row["rowid"],
                "is_current": row["session_id"] == current_hash,
                "user": with_role_list(json.loads(row["user_json"])),
                "created_at": datetime.fromisoformat(row["created_at"]),
                "expires_at": datetime.fromisoformat(row["expires_at"]),
            }
            for row in rows
        ]
