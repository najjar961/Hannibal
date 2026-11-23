"""End-to-end scorecard — does the whole pipeline actually work, and is it
getting better?

`benchmark.py` scores recon coverage per box. This scores the *full* pipeline
against the simulated lab's ground truth in one shot: recon recall, attack
recall (did it find the planted weaknesses), validation quality (of what it
confirmed, how much was real, and how much of the real set it confirmed), and
known-CVE lead recall. Every run appends one line to a history file, so a
change that helps — or quietly regresses something — shows up as a moving
number instead of a hunch.

Ground truth comes from `hannibal/lab.py` (planted ports, services and vulns)
plus the small expected-CVE map below. All offline, deterministic in mock mode.
Point `--backend ollama` at a real model to score its planning the same way.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from typing import Dict, List

from .config import RunConfig
from .lab import LAB
from .orchestrator import Orchestrator
from .store import Store
from .types import Finding

# Which CVE leads the known-weakness pass *should* raise, per box. Hand-curated
# ground truth (not derived from the detector, so it can actually catch a
# regression in the detector).
EXPECTED_CVES: Dict[str, set] = {
    "10.10.10.13": {"CVE-2011-2523", "CVE-2007-2447", "CVE-2018-15473"},
    "10.10.10.9": {"CVE-2018-15473"},
}


def _ratio(hit: int, total: int) -> float:
    return round(hit / total, 3) if total else 1.0


def score(findings: List[Finding], weaknesses: list,
          lab: dict = LAB, expected_cves: dict = EXPECTED_CVES) -> dict:
    """Pure scoring over a finished run's findings + weakness leads.

    Separated from the live run so it is unit-testable with hand-built findings
    and reused identically for the sim lab and (later) real boxes.
    """
    # --- recon: ports and services discovered vs present ---
    truth_ports = {(ip, p) for ip, b in lab.items() for p in b.ports}
    found_ports, found_svcs = set(), set()
    for f in findings:
        if f.kind in ("port", "service") and f.parent_target:
            p = f.data.get("port")
            if isinstance(p, int):
                found_ports.add((f.parent_target, p))
                if f.kind == "service" and f.data.get("version"):
                    found_svcs.add((f.parent_target, p))

    # --- attack: planted vulns found, then confirmed by the validator ---
    planted = {(ip, v["id"]) for ip, b in lab.items() for v in b.vulns}
    found_vulns, confirmed_vulns = set(), set()
    for f in findings:
        if f.kind == "vuln" and f.parent_target:
            key = (f.parent_target, f.data.get("template"))
            found_vulns.add(key)
            if f.data.get("validated"):
                confirmed_vulns.add(key)

    # --- cve leads: expected advisory CVEs raised ---
    found_cves = {(w.host, w.cve) for w in weaknesses if w.cve}
    expected = {(ip, c) for ip, cves in expected_cves.items() for c in cves}

    return {
        "port_recall": _ratio(len(found_ports & truth_ports), len(truth_ports)),
        "svc_recall": _ratio(len(found_svcs & truth_ports), len(truth_ports)),
        "vuln_recall": _ratio(len(found_vulns & planted), len(planted)),
        "val_recall": _ratio(len(confirmed_vulns & planted), len(planted)),
        # of what we confirmed, how much was really planted (false-positive guard)
        "val_precision": _ratio(len(confirmed_vulns & planted), len(confirmed_vulns)),
        "cve_lead_recall": _ratio(len(found_cves & expected), len(expected)),
        "planted_vulns": len(planted),
        "confirmed": len(confirmed_vulns),
    }


def run_eval(backend: str = "mock", model: str = "qwen3:8b",
             base_url: str = "http://localhost:11434/v1", api_key: str = "",
             workdir: str = "") -> dict:
    wd = workdir or tempfile.mkdtemp(prefix="hanneval_")
    cfg = RunConfig(
        objective="map and attack the whole lab",
        scope=["10.10.10.0/24", "10.10.11.0/24"],
        backend=backend, model=model, base_url=base_url, api_key=api_key or "",
        quiet=True, workdir=wd, max_auto_tier=2,
        db_path=os.path.join(wd, "h.sqlite"))
    orch = Orchestrator(cfg)
    orch.run()
    store = Store(cfg.db_path)
    findings = store.all_findings()
    store.close()
    card = score(findings, orch.weaknesses)
    card["backend"] = backend
    card["ts"] = round(time.time(), 2)
    return card


def append_history(card: dict, path: str) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(card) + "\n")


_METRICS = [
    ("port_recall", "recon — port recall"),
    ("svc_recall", "recon — service recall"),
    ("vuln_recall", "attack — planted-vuln recall"),
    ("val_recall", "validation — confirmed of planted"),
    ("val_precision", "validation — precision (no false confirms)"),
    ("cve_lead_recall", "known-CVE — expected leads raised"),
]


def render(card: dict, history: List[dict] | None = None) -> str:
    rows = [f"HANNIBAL SCORECARD — backend={card.get('backend', '?')}",
            "─" * 58]
    prev = history[-2] if history and len(history) >= 2 else None
    for key, label in _METRICS:
        v = card[key]
        delta = ""
        if prev and key in prev:
            d = round(v - prev[key], 3)
            delta = f"  (prev {prev[key]:.3f}, {'+' if d >= 0 else ''}{d})" if d else "  (no change)"
        bar = "█" * int(round(v * 20)) + "·" * (20 - int(round(v * 20)))
        rows.append(f"{label:42} {v:5.2f} {bar}{delta}")
    rows.append("─" * 58)
    rows.append(f"planted vulns: {card['planted_vulns']}  ·  confirmed: {card['confirmed']}")
    return "\n".join(rows)
