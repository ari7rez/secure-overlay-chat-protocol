import sqlite3
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).resolve().parents[2] / "data" / "server.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users(
            user TEXT PRIMARY KEY,
            pubkey_pem TEXT NOT NULL,
            first_seen INTEGER,
            last_seen INTEGER
        );
    """)
    conn.commit()
    return conn


def upsert_user(user: str, pubkey_pem: str, ts: int):
    with get_conn() as c:
        c.execute("""
            INSERT INTO users(user, pubkey_pem, first_seen, last_seen)
            VALUES(?,?,?,?)
            ON CONFLICT(user) DO UPDATE SET pubkey_pem=excluded.pubkey_pem, last_seen=excluded.last_seen
        """, (user, pubkey_pem, ts, ts))
        c.commit()


def get_user_pubkey(user: str) -> Optional[str]:
    with get_conn() as c:
        row = c.execute(
            "SELECT pubkey_pem FROM users WHERE user=?", (user,)).fetchone()
        return row[0] if row else None
