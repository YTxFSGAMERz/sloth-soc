"""Baseline state tracking using local SQLite.

Maintains historical known source IPs, known user-to-IP pairings, and hourly rates.
Enforces the safety rule: baselines are only updated from earlier days, never from today's input.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


class StateStore:
    """Manages historical baselines in a lightweight SQLite database."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self) -> None:
        with self.conn:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS known_ips (
                    ip TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    total_events INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS known_user_ips (
                    user TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    PRIMARY KEY (user, ip)
                );

                CREATE TABLE IF NOT EXISTS hourly_baselines (
                    hour INTEGER PRIMARY KEY,
                    sample_days INTEGER DEFAULT 0,
                    sum_fail INTEGER DEFAULT 0,
                    sum_404 INTEGER DEFAULT 0
                );
            """)

    def is_known_ip(self, ip: str) -> bool:
        """Check if an IP address has been observed in previous baseline days."""
        cur = self.conn.execute("SELECT 1 FROM known_ips WHERE ip = ?", (ip,))
        return cur.fetchone() is not None

    def is_known_user_ip(self, user: str, ip: str) -> bool:
        """Check if a user has previously authenticated from this IP."""
        cur = self.conn.execute(
            "SELECT 1 FROM known_user_ips WHERE user = ? AND ip = ?", (user, ip)
        )
        return cur.fetchone() is not None

    def record_ip(self, ip: str, date_str: str) -> None:
        """Record an observed IP in the historical baseline."""
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO known_ips (ip, first_seen, last_seen, total_events)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(ip) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    total_events = total_events + 1
                """,
                (ip, date_str, date_str),
            )

    def record_user_ip(self, user: str, ip: str, date_str: str) -> None:
        """Record an authorized user-to-IP binding in baseline."""
        if not user or not ip:
            return
        with self.conn:
            self.conn.execute(
                """
                INSERT OR IGNORE INTO known_user_ips (user, ip, first_seen)
                VALUES (?, ?, ?)
                """,
                (user, ip, date_str),
            )

    def update_hourly_baseline(self, hour: int, fail_count: int, count_404: int) -> None:
        """Update running hourly baseline statistics."""
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO hourly_baselines (hour, sample_days, sum_fail, sum_404)
                VALUES (?, 1, ?, ?)
                ON CONFLICT(hour) DO UPDATE SET
                    sample_days = sample_days + 1,
                    sum_fail = sum_fail + excluded.sum_fail,
                    sum_404 = sum_404 + excluded.sum_404
                """,
                (hour, fail_count, count_404),
            )

    def get_hourly_rate(self, hour: int) -> dict[str, float]:
        """Retrieve mean baseline rates for a given hour."""
        cur = self.conn.execute(
            "SELECT sample_days, sum_fail, sum_404 FROM hourly_baselines WHERE hour = ?",
            (hour,),
        )
        row = cur.fetchone()
        if not row or row["sample_days"] == 0:
            return {"mean_fail": 0.5, "mean_404": 0.5}

        days = row["sample_days"]
        return {
            "mean_fail": max(0.1, row["sum_fail"] / days),
            "mean_404": max(0.1, row["sum_404"] / days),
        }

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> StateStore:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
