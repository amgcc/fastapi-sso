import json
import secrets
import sqlite3

from datetime import datetime, timedelta, timezone
from pathlib import Path


DB_PATH = Path(__file__).resolve().parent / "sessions.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_oid TEXT NOT NULL,
                user_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_sessions_user_oid
            ON sessions(user_oid)
        """
        )


def with_role_list(user: dict) -> dict:
    """Return a copy whose roles value is always a list of strings."""
    roles = user.get("roles")
    if isinstance(roles, list):
        roles = [role for role in roles if isinstance(role, str) and role]
    else:
        roles = []
    return {**user, "roles": roles}


def create_session(user: dict) -> str:
    user = with_role_list(user)
    session_id = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=1)

    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO sessions
                (session_id, user_oid, user_json, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                session_id,
                user["oid"],
                json.dumps(user),
                now.isoformat(),
                expires_at.isoformat(),
            ),
        )

    return session_id


def get_session(session_id: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT user_json, expires_at FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()

        if row is None:
            return None

        expires_at = datetime.fromisoformat(row["expires_at"])

        if datetime.now(timezone.utc) >= expires_at:
            conn.execute(
                "DELETE FROM sessions WHERE session_id = ?",
                (session_id,),
            )
            return None

        return with_role_list(json.loads(row["user_json"]))


def delete_session(session_id: str) -> None:
    with get_connection() as conn:
        conn.execute(
            "DELETE FROM sessions WHERE session_id = ?",
            (session_id,),
        )


def list_sessions() -> list[dict]:
    now = datetime.now(timezone.utc).isoformat()

    with get_connection() as conn:
        conn.execute(
            "DELETE FROM sessions WHERE expires_at <= ?",
            (now,),
        )

        rows = conn.execute(
            """
            SELECT session_id, user_json, created_at, expires_at
            FROM sessions
            ORDER BY created_at DESC
            """
        ).fetchall()

        return [
            {
                "session_id": row["session_id"],
                "user": with_role_list(json.loads(row["user_json"])),
                "created_at": datetime.fromisoformat(row["created_at"]),
                "expires_at": datetime.fromisoformat(row["expires_at"]),
            }
            for row in rows
        ]


def delete_user_sessions(oid: str) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            "DELETE FROM sessions WHERE user_oid = ?",
            (oid,),
        )
        return cursor.rowcount


initialize_database()
