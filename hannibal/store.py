"""Persistence: a SQLite task queue and a findings store with graph export.

The task queue is why wraiths can run in parallel safely: workers claim tasks
with an atomic UPDATE, so no two threads ever run the same command. The findings
table doubles as a provenance graph — each finding can point at a parent target
(port -> host, service -> port), which we export as Mermaid or Graphviz so you
can *see* which clue led to which.
"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
from typing import List, Optional

from .types import CommandSpec, Task, Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    round INTEGER, binary TEXT, args TEXT, targets TEXT, rationale TEXT,
    status TEXT DEFAULT 'pending', result TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT, target TEXT, summary TEXT, data TEXT,
    source_task INTEGER, parent_target TEXT, suspicious INTEGER DEFAULT 0, ts REAL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_findings ON findings(kind, target);
"""


class Store:
    def __init__(self, path: str):
        # one connection, guarded by a lock — simplest correct option for the
        # modest concurrency here (a handful of worker threads)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # -- tasks --------------------------------------------------------------
    def add_task(self, round_: int, spec: CommandSpec) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO tasks(round,binary,args,targets,rationale) "
                "VALUES(?,?,?,?,?)",
                (round_, spec.binary, json.dumps(spec.args),
                 json.dumps(spec.targets), spec.rationale),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def claim_task(self) -> Optional[Task]:
        """Atomically take one pending task. Returns None if queue is empty."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM tasks WHERE status='pending' ORDER BY id LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            self._conn.execute("UPDATE tasks SET status='running' WHERE id=?",
                               (row["id"],))
            self._conn.commit()
            spec = CommandSpec(row["binary"], json.loads(row["args"]),
                               json.loads(row["targets"]), row["rationale"])
            return Task(row["id"], row["round"], spec, "running")

    def finish_task(self, task_id: int, status: str, result: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE tasks SET status=?, result=? WHERE id=?",
                               (status, result[:8000], task_id))
            self._conn.commit()

    # -- findings -----------------------------------------------------------
    def add_finding(self, f: Finding) -> int:
        """Insert a finding, deduped by (kind, target).

        Re-running the same scan is routine in recon, so a blind INSERT would
        pile up identical rows and inflate every count and graph node. Instead
        we upsert on the (kind, target) identity: a repeat sighting refreshes
        the summary/data and keeps the earliest timestamp, and `suspicious` is
        sticky (once a source tripped the injection scanner it stays flagged).

        A richer `service` finding also supersedes the bare `port` finding for
        the same endpoint, so one open port is one node, not two.
        """
        with self._lock:
            if f.kind == "service":
                self._conn.execute(
                    "DELETE FROM findings WHERE kind='port' AND target=?",
                    (f.target,))
            cur = self._conn.execute(
                "INSERT INTO findings(kind,target,summary,data,source_task,"
                "parent_target,suspicious,ts) VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(kind,target) DO UPDATE SET "
                "summary=excluded.summary, data=excluded.data, "
                "parent_target=COALESCE(excluded.parent_target,parent_target), "
                "suspicious=MAX(findings.suspicious,excluded.suspicious)",
                (f.kind, f.target, f.summary, json.dumps(f.data),
                 f.source_task, f.parent_target, int(f.suspicious), f.ts),
            )
            self._conn.commit()
            # lastrowid is 0 on a pure UPDATE; look the row id back up
            if cur.lastrowid:
                return int(cur.lastrowid)
            row = self._conn.execute(
                "SELECT id FROM findings WHERE kind=? AND target=?",
                (f.kind, f.target)).fetchone()
            return int(row["id"]) if row else 0

    def all_findings(self) -> List[Finding]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM findings ORDER BY id").fetchall()
        out = []
        for r in rows:
            out.append(Finding(
                r["kind"], r["target"], r["summary"], json.loads(r["data"]),
                r["source_task"], r["parent_target"], bool(r["suspicious"]), r["ts"],
            ))
        return out

    def counts(self) -> dict:
        with self._lock:
            rows = self._conn.execute(
                "SELECT kind, COUNT(*) c FROM findings GROUP BY kind").fetchall()
        return {r["kind"]: r["c"] for r in rows}

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# -- graph export -----------------------------------------------------------
def _node_id(kind: str, target: str) -> str:
    """Deterministic node id from a finding's identity.

    Keying on (kind, target) — not the row index — is what makes the provenance
    graph readable: every clue about one endpoint lands on the *same* node, and
    a child's `parent_target` resolves to its parent's node id instead of a
    dangling synthetic one.
    """
    return "f_" + re.sub(r"\W", "_", f"{kind}:{target}")


def to_mermaid(findings: List[Finding]) -> str:
    lines = ["graph TD"]
    emitted = set()

    def emit(kind: str, target: str, label: str, suspicious: bool = False) -> str:
        nid = _node_id(kind, target)
        if nid not in emitted:
            emitted.add(nid)
            safe = label.replace('"', "'")[:48]
            lines.append(f'  {nid}["{safe}"]')
            if suspicious:
                lines.append(f"  class {nid} suspicious;")
        return nid

    # nodes for every finding, then edges from each finding's parent host
    for f in findings:
        emit(f.kind, f.target, f"{f.kind}: {f.target}", f.suspicious)
    for f in findings:
        if not f.parent_target:
            continue
        # the parent is a host; emit() reuses its node if one already exists
        pid = emit("host", f.parent_target, f"host: {f.parent_target}")
        lines.append(f"  {pid} --> {_node_id(f.kind, f.target)}")
    lines.append("  classDef suspicious fill:#511,stroke:#f55,color:#fff;")
    return "\n".join(lines)
