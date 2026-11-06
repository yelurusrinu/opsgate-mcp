from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    tool TEXT NOT NULL,
    args TEXT NOT NULL,
    args_hash TEXT NOT NULL,
    created_at REAL NOT NULL,
    status TEXT NOT NULL,
    decided_by TEXT,
    decided_at REAL,
    used_at REAL
);
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    tool TEXT NOT NULL,
    args TEXT NOT NULL,
    decision TEXT NOT NULL,
    outcome TEXT NOT NULL,
    approval_id TEXT,
    detail TEXT,
    duration_ms INTEGER
);
"""


def args_hash(tool: str, args: dict[str, Any]) -> str:
    canonical = json.dumps({"tool": tool, "args": args}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class Approval:
    id: str
    tool: str
    args: dict[str, Any]
    args_hash: str
    created_at: float
    status: str
    decided_by: str | None
    decided_at: float | None
    used_at: float | None


class Store:
    def __init__(self, path: Path | str):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def _row(self, r) -> Approval | None:
        if r is None:
            return None
        d = dict(r)
        d["args"] = json.loads(d["args"])
        return Approval(**d)

    def request(self, tool: str, args: dict[str, Any], now: float | None = None) -> Approval:
        aid = secrets.token_hex(4)
        self.db.execute("INSERT INTO approvals VALUES (?,?,?,?,?, 'pending', NULL, NULL, NULL)",
                        (aid, tool, json.dumps(args, sort_keys=True), args_hash(tool, args), now or time.time()))
        return self.get(aid)

    def get(self, aid: str) -> Approval | None:
        return self._row(self.db.execute("SELECT * FROM approvals WHERE id=?", (aid,)).fetchone())

    def pending(self) -> list[Approval]:
        return [self._row(r) for r in self.db.execute(
            "SELECT * FROM approvals WHERE status='pending' ORDER BY created_at")]

    def decide(self, aid: str, approve: bool, who: str, now: float | None = None) -> Approval:
        cur = self.db.execute("UPDATE approvals SET status=?, decided_by=?, decided_at=? "
                              "WHERE id=? AND status='pending'",
                              ("approved" if approve else "denied", who, now or time.time(), aid))
        if cur.rowcount != 1:
            raise ValueError(f"approval {aid} is not pending")
        return self.get(aid)

    def consume(self, aid: str, now: float | None = None) -> bool:
        """Single use: the UPDATE only matches once, so a replayed id can't run twice."""
        cur = self.db.execute("UPDATE approvals SET status='used', used_at=? WHERE id=? AND status='approved'",
                              (now or time.time(), aid))
        return cur.rowcount == 1

    def expire(self, aid: str) -> None:
        self.db.execute("UPDATE approvals SET status='expired' WHERE id=? AND status IN ('pending','approved')", (aid,))

    def log(self, tool: str, args: dict[str, Any], decision: str, outcome: str,
            approval_id: str | None = None, detail: str | None = None, duration_ms: int | None = None) -> None:
        self.db.execute("INSERT INTO audit (ts, tool, args, decision, outcome, approval_id, detail, duration_ms) "
                        "VALUES (?,?,?,?,?,?,?,?)",
                        (time.time(), tool, json.dumps(args, sort_keys=True), decision, outcome,
                         approval_id, detail, duration_ms))

    def audit(self, limit: int = 50) -> list[dict]:
        return [dict(r) for r in self.db.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (limit,))]
