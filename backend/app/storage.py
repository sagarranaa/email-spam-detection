from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from .config import DATABASE_PATH


def _connect() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    with _connect() as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                subject TEXT NOT NULL,
                sender TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                result_json TEXT NOT NULL
            )
            """
        )


def save_scan(result: dict[str, Any]) -> dict[str, Any]:
    with _connect() as connection:
        cursor = connection.execute(
            """INSERT INTO scans (created_at, subject, sender, risk_level, risk_score, result_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                result["created_at"],
                result["subject"],
                result["sender"],
                result["risk_level"],
                result["risk_score"],
                json.dumps(result, ensure_ascii=False),
            ),
        )
        result["id"] = cursor.lastrowid
    return result


def list_scans(limit: int = 20) -> list[dict[str, Any]]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT id, created_at, subject, sender, risk_level, risk_score, result_json "
            "FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        {
            "id": row["id"],
            "created_at": row["created_at"],
            "subject": row["subject"],
            "sender": row["sender"],
            "risk_level": row["risk_level"],
            "risk_score": row["risk_score"],
            "result": json.loads(row["result_json"]),
        }
        for row in rows
    ]


def get_scan(scan_id: int) -> dict[str, Any] | None:
    with _connect() as connection:
        row = connection.execute(
            "SELECT id, result_json FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    if row is None:
        return None
    result = json.loads(row["result_json"])
    result["id"] = row["id"]
    return result


def delete_scan(scan_id: int) -> bool:
    with _connect() as connection:
        cursor = connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    return cursor.rowcount > 0


def get_stats() -> dict[str, int]:
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    with _connect() as connection:
        totals = connection.execute(
            "SELECT risk_level, COUNT(*) AS total FROM scans GROUP BY risk_level"
        ).fetchall()
        last_24_hours = connection.execute(
            "SELECT COUNT(*) FROM scans WHERE created_at >= ?", (since,)
        ).fetchone()[0]
    counts = {row["risk_level"]: row["total"] for row in totals}
    return {
        "total": sum(counts.values()),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "last_24_hours": last_24_hours,
    }
