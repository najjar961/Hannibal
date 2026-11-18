"""Parsers for real tool output (used by --execute).

The simulator emits human-readable text that `parse.py` reads with regex. Real
tools emit structured formats, which are both easier and safer to parse:

  * nmap  -oX -   → XML on stdout   → parse_nmap_xml
  * httpx -json   → JSON lines      → parse_httpx_json

The runner adds those flags automatically in execute mode, so a real scan
produces the same structured Findings the simulator does. Service banners and
web titles are still attacker-controlled, so each is run through the injection
scanner and flagged per-field.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from typing import List

from .types import Finding
from .injection import scan


def looks_like_nmap_xml(output: str) -> bool:
    head = output.lstrip()[:300].lower()
    return "<nmaprun" in head or (head.startswith("<?xml") and "nmaprun" in output[:800].lower())


def looks_like_httpx_json(output: str) -> bool:
    s = output.lstrip()
    if not s.startswith("{"):
        return False
    probe = s[:500]
    return '"url"' in probe or '"status_code"' in probe or '"status-code"' in probe


def parse_nmap_xml(output: str, task_id: int) -> List[Finding]:
    findings: List[Finding] = []
    try:
        root = ET.fromstring(output)   # stdlib ET does not expand external entities
    except ET.ParseError:
        return findings
    for host in root.iter("host"):
        status = host.find("status")
        up = status is not None and status.get("state") == "up"
        ip = None
        for addr in host.findall("address"):
            if addr.get("addrtype", "").startswith("ipv"):
                ip = addr.get("addr")
                break
        if ip is None:
            continue
        if up:
            findings.append(Finding("host", ip, "host is up", {"ip": ip}, task_id, None))
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            st = port.find("state")
            if st is None or st.get("state") != "open":
                continue
            portid = int(port.get("portid", "0"))
            svc = port.find("service")
            name = svc.get("name", "unknown") if svc is not None else "unknown"
            banner = ""
            if svc is not None:
                banner = " ".join(x for x in (svc.get("product", ""),
                                              svc.get("version", ""),
                                              svc.get("extrainfo", "")) if x).strip()
            if banner:
                findings.append(Finding(
                    "service", f"{ip}:{portid}", f"{name} — {banner}",
                    {"port": portid, "service": name, "version": banner},
                    task_id, ip, suspicious=scan(banner).suspicious))
            else:
                findings.append(Finding(
                    "port", f"{ip}:{portid}", f"{portid}/tcp open ({name})",
                    {"port": portid, "service": name}, task_id, ip))
    return findings


def parse_httpx_json(output: str, task_id: int) -> List[Finding]:
    findings: List[Finding] = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = obj.get("url") or obj.get("input") or ""
        host = obj.get("host") or url
        code = obj.get("status_code", obj.get("status-code", 0))
        title = obj.get("title", "") or ""
        tech = obj.get("tech") or obj.get("technologies") or []
        tech_s = ",".join(str(t) for t in tech) if isinstance(tech, list) else str(tech)
        findings.append(Finding(
            "web", url or host, f"HTTP {code} — {str(title)[:60]}",
            {"status": int(code) if str(code).isdigit() else 0,
             "title": title, "tech": tech_s},
            task_id, host, suspicious=scan(f"{title} {tech_s}").suspicious))
    return findings
