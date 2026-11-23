"""Continuous watch mode — the "attacks nonstop" half of the idea.

A one-shot campaign maps a target once. Real attack surface drifts: a new host
appears, a port opens, a developer ships a misconfig. Watch mode runs the
campaign on a loop and reports only what *changed* since the last pass, so the
monitor keeps pace with the target instead of going stale between audits.

Two pieces:

  * `run_watch` — the loop. Each cycle runs a fresh campaign, diffs its findings
    against everything seen so far, and reports the new ones. On a real lab
    (`--execute`) this is the whole feature: it catches changes *you* make.

  * `VulnInjector` — for the simulated lab only. It mutates the in-memory lab on
    a schedule (adds a vuln to a web box, or stands up a whole new host) so the
    loop has something to catch, and it timestamps each change. That turns the
    headline claim into a measured number: *time to detection* — how long from a
    weakness appearing to Hannibal finding and confirming it.

The injector touches `hannibal.lab.LAB` in place and is a test/demo device; it
never runs against, or sends anything to, a real system.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field, replace
from typing import Callable, List, Optional

from .config import RunConfig
from .orchestrator import Orchestrator
from .store import Store
from .types import Finding
from . import lab as _lab


@dataclass
class InjectionEvent:
    """One scheduled change to the simulated lab, with its detection timing."""
    cycle: int                 # the watch cycle at whose start it goes live
    kind: str                  # "vuln" | "host"
    box_ip: str
    payload: dict              # a vuln dict, or a box spec for a new host
    injected_at: float = 0.0
    detected_at: float = 0.0
    detected_cycle: int = -1
    validated_at: float = 0.0
    validated_cycle: int = -1

    @property
    def label(self) -> str:
        if self.kind == "vuln":
            return f"{self.box_ip} [{self.payload.get('id', '?')}]"
        return f"new host {self.box_ip}"


class VulnInjector:
    """Mutates the simulated lab over time (sim only — never a real target)."""

    def __init__(self, events: List[InjectionEvent]):
        self.events = list(events)

    def apply_due(self, cycle: int, now: float) -> List[InjectionEvent]:
        applied: List[InjectionEvent] = []
        for e in self.events:
            if e.cycle != cycle or e.injected_at:
                continue
            if e.kind == "vuln":
                box = _lab.LAB.get(e.box_ip)
                if box is not None:
                    box.vulns.append(dict(e.payload))
            elif e.kind == "host":
                spec = e.payload
                _lab.LAB[e.box_ip] = _lab.BoxProfile(
                    ip=e.box_ip,
                    ports={int(k): str(v) for k, v in spec.get("ports", {}).items()},
                    versions={int(k): str(v) for k, v in spec.get("versions", {}).items()},
                    web_title=spec.get("web_title", ""),
                    web_tech=spec.get("web_tech", "") or "Apache,PHP",
                    vulns=[dict(v) for v in spec.get("vulns", [])],
                )
            e.injected_at = now
            applied.append(e)
        return applied


def _matches(event: InjectionEvent, f: Finding) -> bool:
    if event.kind == "vuln":
        return (f.kind == "vuln"
                and f.data.get("template") == event.payload.get("id")
                and event.box_ip in f.target)
    return event.kind == "host" and f.kind == "host" and f.target == event.box_ip


@dataclass
class CycleResult:
    cycle: int
    new_findings: int
    injected: List[str] = field(default_factory=list)
    detected: List[str] = field(default_factory=list)


def run_watch(cfg: RunConfig, cycles: int,
              injector: Optional[VulnInjector] = None,
              interval: float = 0.0,
              now: Callable[[], float] = time.time,
              sleep: Callable[[float], None] = time.sleep,
              log: Callable[[str], None] = print) -> List[CycleResult]:
    """Run `cycles` monitoring passes (cycles <= 0 means run until interrupted).

    Each pass is a fresh campaign in its own workdir. Returns one CycleResult
    per pass; when an injector is given, its events carry the detection timing.
    """
    base = cfg.workdir
    seen: set = set()
    results: List[CycleResult] = []
    c = 0
    while cycles <= 0 or c < cycles:
        c += 1
        applied = injector.apply_due(c, now()) if injector else []
        for e in applied:
            log(f"[cycle {c}] injected: {e.label}")

        wcfg = replace(cfg, workdir=os.path.join(base, f"cycle{c}"),
                       db_path="", quiet=True, fresh=True)
        Orchestrator(wcfg).run()
        store = Store(wcfg.db_path)
        findings = store.all_findings()
        store.close()

        new = 0
        for f in findings:
            key = (f.kind, f.target)
            if key not in seen:
                seen.add(key)
                new += 1

        detected_now: List[str] = []
        if injector:
            for e in injector.events:
                if not e.injected_at:
                    continue
                match = next((f for f in findings if _matches(e, f)), None)
                if match is None:
                    continue
                if e.detected_cycle < 0:
                    e.detected_at, e.detected_cycle = now(), c
                    detected_now.append(e.label)
                if (e.kind == "vuln" and e.validated_cycle < 0
                        and match.data.get("validated")):
                    e.validated_at, e.validated_cycle = now(), c

        results.append(CycleResult(c, new, [e.label for e in applied], detected_now))
        msg = f"[cycle {c}] {new} new finding(s)"
        if detected_now:
            msg += f" — detected: {', '.join(detected_now)}"
        log(msg)

        if interval and (cycles <= 0 or c < cycles):
            sleep(interval)
    return results


def detection_table(injector: VulnInjector) -> str:
    """A time-to-detection report over the injector's events."""
    rows = ["change                          inj→det  inj→validated   latency",
            "─" * 72]
    for e in injector.events:
        if not e.injected_at:
            rows.append(f"{e.label:30}  (not injected)")
            continue
        det = f"cycle {e.detected_cycle}" if e.detected_cycle > 0 else "—"
        val = f"cycle {e.validated_cycle}" if e.validated_cycle > 0 else "—"
        if e.detected_at:
            secs = e.detected_at - e.injected_at
            lat = f"{secs:.2f}s / {e.detected_cycle - e.cycle} cycle(s)"
        else:
            lat = "not detected"
        rows.append(f"{e.label:30}  {det:7}  {val:13}   {lat}")
    return "\n".join(rows)


# ---------------------------------------------------------------------------
# A baked demo schedule for `hannibal watch --demo` against the simulated lab:
# a new weakness appears on an existing host, then a whole new host comes up.
# ---------------------------------------------------------------------------
def demo_injector() -> VulnInjector:
    return VulnInjector([
        InjectionEvent(
            cycle=2, kind="vuln", box_ip="10.10.11.20",
            payload={"id": "exposed-sql-backup",
                     "name": "Database backup left in web root",
                     "severity": "high", "path": "/backup.sql",
                     "evidence": ["-- MySQL dump", "INSERT INTO users VALUES"]}),
        InjectionEvent(
            cycle=3, kind="host", box_ip="10.10.11.50",
            payload={"ports": {22: "ssh", 80: "http"},
                     "versions": {22: "OpenSSH 8.9", 80: "Apache httpd 2.4.57"},
                     "web_title": "Staging — Acme", "web_tech": "Apache,PHP",
                     "vulns": [{"id": "git-config",
                                "name": "Exposed Git repository config",
                                "severity": "medium", "path": "/.git/config",
                                "evidence": ["[core]", "url = git@git.acme.lab:web.git"]}]}),
    ])
