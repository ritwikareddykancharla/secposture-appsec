"""Append-only SQLite WAL Audit Ledger with SHA-256 cryptographic hash chaining."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

GENESIS_HASH = "GENESIS_SECPOSTURE_SQLITE_0000"


class SQLiteAuditLedger:
    """Thread-safe append-only SQLite WAL ledger linking every security event with SHA-256."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        base_dir = Path("/tmp/secposture-runtime")
        base_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path or (base_dir / "secposture_audit.db")
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_events (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT NOT NULL UNIQUE,
                        timestamp_utc TEXT NOT NULL,
                        category TEXT NOT NULL,
                        target_id TEXT NOT NULL,
                        verdict TEXT NOT NULL,
                        duration_ms REAL NOT NULL,
                        details_json TEXT NOT NULL,
                        prev_hash TEXT NOT NULL,
                        sha256_hash TEXT NOT NULL
                    )
                    """
                )
                conn.commit()
            finally:
                conn.close()

    @staticmethod
    def _compute_digest(
        event_id: str,
        timestamp_utc: str,
        category: str,
        target_id: str,
        verdict: str,
        duration_ms: float,
        details_json: str,
        prev_hash: str,
    ) -> str:
        canonical = json.dumps(
            {
                "event_id": event_id,
                "timestamp_utc": timestamp_utc,
                "category": category,
                "target_id": target_id,
                "verdict": verdict,
                "duration_ms": round(float(duration_ms), 3),
                "details": json.loads(details_json),
                "prev_hash": prev_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def append_event(
        self,
        category: str,
        target_id: str,
        verdict: str,
        duration_ms: float,
        details: Dict[str, Any],
    ) -> Dict[str, Any]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT seq, sha256_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                next_seq = (int(row["seq"]) + 1) if row else 1
                prev_hash = str(row["sha256_hash"]) if row else GENESIS_HASH
                event_id = f"SP-AUD-{next_seq:05d}"
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                details_json = json.dumps(details, sort_keys=True, separators=(",", ":"), default=str)
                digest = self._compute_digest(
                    event_id=event_id,
                    timestamp_utc=ts,
                    category=category,
                    target_id=target_id,
                    verdict=verdict,
                    duration_ms=round(float(duration_ms), 3),
                    details_json=details_json,
                    prev_hash=prev_hash,
                )
                conn.execute(
                    """
                    INSERT INTO audit_events (
                        event_id, timestamp_utc, category, target_id, verdict,
                        duration_ms, details_json, prev_hash, sha256_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        ts,
                        category,
                        target_id,
                        verdict,
                        round(float(duration_ms), 3),
                        details_json,
                        prev_hash,
                        digest,
                    ),
                )
                conn.commit()
                return {
                    "event_id": event_id,
                    "timestamp_utc": ts,
                    "category": category,
                    "target_id": target_id,
                    "verdict": verdict,
                    "duration_ms": round(float(duration_ms), 3),
                    "prev_hash": prev_hash,
                    "sha256_hash": digest,
                }
            finally:
                conn.close()

    def list_recent(self, limit: int = 25) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM audit_events ORDER BY seq DESC LIMIT ?", (int(limit),)
                ).fetchall()
                return [
                    {
                        "seq": int(r["seq"]),
                        "event_id": str(r["event_id"]),
                        "timestamp_utc": str(r["timestamp_utc"]),
                        "category": str(r["category"]),
                        "target_id": str(r["target_id"]),
                        "verdict": str(r["verdict"]),
                        "duration_ms": float(r["duration_ms"]),
                        "details": json.loads(r["details_json"]),
                        "prev_hash": str(r["prev_hash"]),
                        "sha256_hash": str(r["sha256_hash"]),
                    }
                    for r in rows
                ]
            finally:
                conn.close()

    def verify_chain_integrity(self) -> Dict[str, Any]:
        t0 = time.perf_counter()
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute("SELECT * FROM audit_events ORDER BY seq ASC").fetchall()
                expected_prev = GENESIS_HASH
                for r in rows:
                    if str(r["prev_hash"]) != expected_prev:
                        return {
                            "valid": False,
                            "checked_rows": len(rows),
                            "broken_at_event_id": str(r["event_id"]),
                            "reason": "prev_hash mismatch",
                            "verify_ms": round((time.perf_counter() - t0) * 1000.0, 3),
                        }
                    recomputed = self._compute_digest(
                        event_id=str(r["event_id"]),
                        timestamp_utc=str(r["timestamp_utc"]),
                        category=str(r["category"]),
                        target_id=str(r["target_id"]),
                        verdict=str(r["verdict"]),
                        duration_ms=float(r["duration_ms"]),
                        details_json=str(r["details_json"]),
                        prev_hash=str(r["prev_hash"]),
                    )
                    if recomputed != str(r["sha256_hash"]):
                        return {
                            "valid": False,
                            "checked_rows": len(rows),
                            "broken_at_event_id": str(r["event_id"]),
                            "reason": "sha256_hash payload mismatch",
                            "verify_ms": round((time.perf_counter() - t0) * 1000.0, 3),
                        }
                    expected_prev = recomputed
                return {
                    "valid": True,
                    "checked_rows": len(rows),
                    "head_hash": expected_prev,
                    "verify_ms": round((time.perf_counter() - t0) * 1000.0, 3),
                }
            finally:
                conn.close()

    def reset(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM audit_events")
                conn.execute("DELETE FROM sqlite_sequence WHERE name='audit_events'")
                conn.commit()
            finally:
                conn.close()
