"""Turn raw command output into structured, provenance-tagged findings.

Deterministic parsing (not the LLM) is what keeps findings trustworthy: the
model decides *what to run*, but facts entering the knowledge base come from
regex over real tool output. Each finding records its parent target so the
graph can later show port->host, service->port, web->host relationships.
"""
from __future__ import annotations

import re
from typing import List

from .types import CommandSpec, Finding
from .injection import scan
from . import realparse

_HOST_UP = re.compile(r"Nmap scan report for (\S+)")
# [ \t] rather than \s so the version group never swallows the next line
_PORT = re.compile(r"(\d{1,5})/tcp[ \t]+open[ \t]+(\S+)(?:[ \t]+([^\n]*))?")
_WEB = re.compile(r"https?://(\S+)[ \t]+\[(\d{3})\][ \t]+\[([^\]]*)\]")


def parse(spec: CommandSpec, output: str, task_id: int) -> List[Finding]:
    # real structured output first (from --execute). The simulator emits text,
    # which falls through to the regex parsing below.
    sr = scan(output)
    if spec.binary == "nuclei":
        # tool output we couldn't get (not installed / timeout) is not a
        # completed phase — return nothing so the planner can retry or give up
        if output.startswith(("[skipped]", "[timeout]", "[error]")):
            return [], sr
        from urllib.parse import urlsplit
        url = next((t for t in spec.targets if "://" in t), "")
        host = urlsplit(url).hostname or (spec.targets or ["target"])[0]
        return realparse.parse_nuclei_jsonl(output, task_id, host), sr
    if realparse.looks_like_nmap_xml(output):
        return realparse.parse_nmap_xml(output, task_id), sr
    if realparse.looks_like_httpx_json(output):
        return realparse.parse_httpx_json(output, task_id), sr

    findings: List[Finding] = []
    host = (spec.targets or ["target"])[0]

    # host liveness
    for m in _HOST_UP.finditer(output):
        h = m.group(1)
        if "-sn" in spec.args:
            findings.append(Finding("host", h, "host is up", {"ip": h},
                                    task_id, None))

    # open ports / services
    for m in _PORT.finditer(output):
        port = int(m.group(1))
        svc = m.group(2)
        ver = (m.group(3) or "").strip()
        if "-sV" in spec.args and ver:
            findings.append(Finding(
                "service", f"{host}:{port}",
                f"{svc} — {ver}", {"port": port, "service": svc, "version": ver},
                task_id, host))
        else:
            findings.append(Finding(
                "port", f"{host}:{port}", f"{port}/tcp open ({svc})",
                {"port": port, "service": svc}, task_id, host))

    # web fingerprints (attacker-controlled -> honour the injection scan)
    for m in _WEB.finditer(output):
        endpoint, code, title = m.group(1), m.group(2), m.group(3)
        findings.append(Finding(
            "web", endpoint, f"HTTP {code} — {title[:60]}",
            {"status": int(code), "title": title}, task_id,
            host, suspicious=sr.suspicious))
    # a whatweb-style line without the bracket format still yields a note
    if spec.binary == "whatweb" and not any(f.kind == "web" for f in findings):
        findings.append(Finding("web", host, "web tech fingerprinted",
                                {"raw": output[:200]}, task_id, host,
                                suspicious=sr.suspicious))

    return findings, sr
