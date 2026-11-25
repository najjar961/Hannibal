"""Persistent, cross-run continuous monitoring with new-finding alerts.

``watch`` loops the campaign and diffs against an *in-memory* set, so it only
knows what changed inside a single invocation — restart it and it re-reports
everything from scratch. A monitoring service has to do three more things:
survive restarts, remember what it has seen across many runs over days, and
*notify* when something genuinely new shows up.

``monitor`` adds exactly that, on top of the same campaign engine:

  * a persistent baseline — a tiny SQLite file (stdlib) keyed by a stable
    per-finding fingerprint, tracking first-seen / last-seen and how many runs
    each finding has survived;
  * a diff that labels the current run's findings NEW (never seen), ONGOING
    (seen before) or RESOLVED (seen before, gone now);
  * pluggable alert sinks — console, a JSON-lines file for SIEM ingestion, and
    a generic webhook (Slack / Discord / Teams / anything) — fired only on
    change, never on steady state.

Everything is stdlib-only, like the rest of Hannibal: sqlite3 for state,
urllib for the webhook. Nothing new to install.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
import urllib.request
from dataclasses import dataclass, field, replace
from typing import Callable, Dict, List, Optional

from .config import RunConfig
from .orchestrator import Orchestrator
from .store import Store
from .types import Finding


# ---------------------------------------------------------------------------
# fingerprinting — what makes two sightings "the same finding"
# ---------------------------------------------------------------------------
def _discriminator(f: Finding) -> str:
    """Extra identity beyond (kind, target) for findings that need it.

    Two different vulnerabilities can live on one endpoint, so a vuln is
    identified by its template as well. Everything else is uniquely a thing at
    a target (one host, one open port, one service, one web root).
    """
    if f.kind == "vuln":
        return str(f.data.get("template") or f.data.get("id")
                   or f.data.get("path") or "")
    return ""


def finding_fingerprint(f: Finding) -> str:
    """A stable id for a finding across re-scans.

    Deterministic and content-addressed, so the same weakness seen tomorrow
    maps to the same row — that is what lets the monitor tell a genuinely new
    finding from one it has already alerted on.
    """
    raw = "|".join([f.kind, f.target, _discriminator(f)])
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def _severity(f: Finding) -> str:
    return str(f.data.get("severity", "")) if f.kind == "vuln" else ""


# ---------------------------------------------------------------------------
# alerts
# ---------------------------------------------------------------------------
@dataclass
class Alert:
    """A single change worth notifying about."""
    change: str          # "new" | "resolved"
    fingerprint: str
    kind: str
    target: str
    summary: str
    severity: str
    run: int
    ts: float

    def as_dict(self) -> Dict:
        return {
            "change": self.change, "fingerprint": self.fingerprint,
            "kind": self.kind, "target": self.target, "summary": self.summary,
            "severity": self.severity, "run": self.run, "ts": self.ts,
            "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.ts)),
        }

    def text(self) -> str:
        sev = f" [{self.severity.upper()}]" if self.severity else ""
        verb = "NEW" if self.change == "new" else "RESOLVED"
        return f"{verb}{sev} {self.kind}: {self.target} — {self.summary}"


class AlertSink:
    """A destination for alerts. Subclasses override emit()."""

    def emit(self, alert: Alert) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - optional
        pass


class ConsoleSink(AlertSink):
    def __init__(self, log: Callable[[str], None] = print):
        self._log = log

    def emit(self, alert: Alert) -> None:
        mark = "✓" if alert.change == "resolved" else "⚠"
        self._log(f"  {mark} {alert.text()}")


class JsonlSink(AlertSink):
    """Append one JSON object per alert — ready for a SIEM to tail."""

    def __init__(self, path: str):
        self.path = path
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)

    def emit(self, alert: Alert) -> None:
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(alert.as_dict()) + "\n")


class WebhookSink(AlertSink):
    """POST each alert to a webhook (Slack / Discord / Teams / generic).

    The payload carries both a ``text`` field (what Slack and Discord render)
    and the full structured alert, so one sink feeds a chat channel and a
    machine consumer alike. A webhook that is down must never take the monitor
    down with it, so delivery failures are swallowed and reported, not raised.
    """

    def __init__(self, url: str, timeout: float = 10.0,
                 opener: Optional[Callable] = None,
                 log: Callable[[str], None] = print):
        self.url = url
        self.timeout = timeout
        self._opener = opener or urllib.request.urlopen
        self._log = log

    def emit(self, alert: Alert) -> None:
        payload = dict(alert.as_dict())
        payload["text"] = "Hannibal: " + alert.text()
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.url, data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            self._opener(req, timeout=self.timeout)
        except Exception as e:  # pragma: no cover - network failure path
            self._log(f"  ! webhook delivery failed: {type(e).__name__}: {e}")


class MultiSink(AlertSink):
    def __init__(self, sinks: List[AlertSink]):
        self.sinks = list(sinks)

    def emit(self, alert: Alert) -> None:
        for s in self.sinks:
            s.emit(alert)

    def close(self) -> None:
        for s in self.sinks:
            s.close()


# ---------------------------------------------------------------------------
# the persistent baseline — the thing `watch` was missing
# ---------------------------------------------------------------------------
_STATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings_seen (
    fingerprint TEXT PRIMARY KEY,
    kind TEXT, target TEXT, summary TEXT, severity TEXT,
    first_seen REAL, last_seen REAL,
    first_run INTEGER, last_run INTEGER,
    runs_seen INTEGER DEFAULT 1,
    status TEXT DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS runs (
    run INTEGER PRIMARY KEY,
    ts REAL, total INTEGER, new INTEGER, resolved INTEGER
);
"""


@dataclass
class ChangeSet:
    """The classification of one run's findings against the baseline."""
    run: int
    new: List[Finding] = field(default_factory=list)
    ongoing: List[Finding] = field(default_factory=list)
    resolved: List[Dict] = field(default_factory=list)   # stored rows, now gone


class MonitorState:
    """A durable record of every finding ever seen, keyed by fingerprint.

    This is the whole point of ``monitor`` over ``watch``: the baseline lives on
    disk, so a brand-new process resumes exactly where the last one stopped and
    only genuinely new findings alert.
    """

    def __init__(self, path: str):
        self.path = path
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        self._conn = sqlite3.connect(path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_STATE_SCHEMA)
        self._conn.commit()

    def next_run(self) -> int:
        row = self._conn.execute("SELECT MAX(run) m FROM runs").fetchone()
        return int(row["m"] or 0) + 1

    def run_count(self) -> int:
        return int(self._conn.execute(
            "SELECT COUNT(*) c FROM runs").fetchone()["c"])

    def diff(self, findings: List[Finding], run: int) -> ChangeSet:
        """Classify current findings against what is persisted.

        NEW = never seen, or seen before and since resolved (it came back).
        ONGOING = already active in the baseline.
        RESOLVED = active in the baseline but absent from this run.
        """
        known: Dict[str, str] = {}
        for r in self._conn.execute(
                "SELECT fingerprint, status FROM findings_seen").fetchall():
            known[r["fingerprint"]] = r["status"]

        cs = ChangeSet(run=run)
        current: set = set()
        for f in findings:
            fp = finding_fingerprint(f)
            current.add(fp)
            if fp not in known or known[fp] == "resolved":
                cs.new.append(f)
            else:
                cs.ongoing.append(f)

        for r in self._conn.execute(
                "SELECT * FROM findings_seen WHERE status='active'").fetchall():
            if r["fingerprint"] not in current:
                cs.resolved.append(dict(r))
        return cs

    def commit(self, findings: List[Finding], run: int, ts: float) -> None:
        """Fold this run's findings into the baseline and persist."""
        current: set = set()
        for f in findings:
            fp = finding_fingerprint(f)
            current.add(fp)
            row = self._conn.execute(
                "SELECT runs_seen, status FROM findings_seen WHERE fingerprint=?",
                (fp,)).fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO findings_seen(fingerprint,kind,target,summary,"
                    "severity,first_seen,last_seen,first_run,last_run,runs_seen,"
                    "status) VALUES(?,?,?,?,?,?,?,?,?,1,'active')",
                    (fp, f.kind, f.target, f.summary, _severity(f),
                     ts, ts, run, run))
            else:
                # a reappearance after resolve restarts the streak at 1
                runs_seen = row["runs_seen"] + 1 if row["status"] == "active" else 1
                self._conn.execute(
                    "UPDATE findings_seen SET summary=?, severity=?, last_seen=?, "
                    "last_run=?, runs_seen=?, status='active' WHERE fingerprint=?",
                    (f.summary, _severity(f), ts, run, runs_seen, fp))

        if current:
            placeholders = ",".join("?" * len(current))
            self._conn.execute(
                f"UPDATE findings_seen SET status='resolved', last_run=? "
                f"WHERE status='active' AND fingerprint NOT IN ({placeholders})",
                [run, *current])
        else:
            self._conn.execute(
                "UPDATE findings_seen SET status='resolved', last_run=? "
                "WHERE status='active'", (run,))
        self._conn.commit()

    def record_run(self, run: int, ts: float, total: int,
                   new: int, resolved: int) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO runs(run,ts,total,new,resolved) "
            "VALUES(?,?,?,?,?)", (run, ts, total, new, resolved))
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()


# ---------------------------------------------------------------------------
# the loop
# ---------------------------------------------------------------------------
@dataclass
class MonitorCycle:
    run: int
    total: int
    new: int
    resolved: int


def _interruptible_sleep(interval: float,
                         should_stop: Optional[Callable[[], bool]],
                         sleep: Callable[[float], None]) -> None:
    """Sleep up to ``interval`` seconds, waking early if a stop is requested.

    A daemon on a long interval must still react to a shutdown signal promptly,
    so the wait is broken into short slices that re-check ``should_stop``.
    """
    if should_stop is None:
        sleep(interval)
        return
    remaining = interval
    while remaining > 0 and not should_stop():
        slice_ = min(1.0, remaining)
        sleep(slice_)
        remaining -= slice_


def _write_heartbeat(path: str, run: int, ts: float,
                     total: int, new: int, resolved: int) -> None:
    """Write a tiny liveness/status file after each run (best-effort).

    Lets an operator — or another monitor — confirm the daemon is alive and see
    when it last completed a pass, without parsing logs.
    """
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    payload = {
        "pid": os.getpid(), "run": run, "ts": ts,
        "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
        "total": total, "new": new, "resolved": resolved,
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    os.replace(tmp, path)


def run_monitor(cfg: RunConfig, state_path: str, sinks: AlertSink,
                cycles: int = 0, interval: float = 0.0,
                injector=None, should_stop: Optional[Callable[[], bool]] = None,
                heartbeat_path: str = "",
                now: Callable[[], float] = time.time,
                sleep: Callable[[float], None] = time.sleep,
                log: Callable[[str], None] = print) -> List[MonitorCycle]:
    """Continuous monitor: run the campaign on a loop, persist a baseline across
    runs, and fire alerts only on change. ``cycles <= 0`` runs until interrupted.

    State lives in ``state_path`` and survives restarts, so a fresh process
    picks up exactly where the last one left off — the key difference from
    ``watch``, whose memory dies with the process.
    """
    state = MonitorState(state_path)
    base = cfg.workdir
    out: List[MonitorCycle] = []
    c = 0
    try:
        while cycles <= 0 or c < cycles:
            if should_stop is not None and should_stop():
                log("stopping — shutdown requested")
                break
            c += 1
            run = state.next_run()
            if injector is not None:
                for e in injector.apply_due(c, now()):
                    log(f"[run {run}] injected: {e.label}")

            wcfg = replace(cfg, workdir=os.path.join(base, f"run{run}"),
                           db_path="", quiet=True, fresh=True)
            Orchestrator(wcfg).run()
            store = Store(wcfg.db_path)
            findings = store.all_findings()
            store.close()

            ts = now()
            changes = state.diff(findings, run)
            for f in changes.new:
                sinks.emit(Alert("new", finding_fingerprint(f), f.kind, f.target,
                                 f.summary, _severity(f), run, ts))
            for r in changes.resolved:
                sinks.emit(Alert("resolved", r["fingerprint"], r["kind"],
                                 r["target"], r["summary"], r["severity"] or "",
                                 run, ts))

            state.commit(findings, run, ts)
            state.record_run(run, ts, len(findings), len(changes.new),
                             len(changes.resolved))
            log(f"[run {run}] {len(findings)} finding(s): "
                f"{len(changes.new)} new, {len(changes.resolved)} resolved")
            out.append(MonitorCycle(run, len(findings), len(changes.new),
                                    len(changes.resolved)))
            if heartbeat_path:
                _write_heartbeat(heartbeat_path, run, ts, len(findings),
                                 len(changes.new), len(changes.resolved))

            if should_stop is not None and should_stop():
                break
            if interval and (cycles <= 0 or c < cycles):
                _interruptible_sleep(interval, should_stop, sleep)
    except KeyboardInterrupt:  # pragma: no cover - interactive
        log("\nstopped.")
    finally:
        state.close()
    return out
