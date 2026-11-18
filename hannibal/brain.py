"""The 'brain' — the decision layer behind the commander and the generals.

Two interchangeable implementations with the same interface:

  * MockBrain   — deterministic rules. Needs no model, no network, no API key.
                  It drives the full orchestration loop so the tool can be run,
                  tested, demoed and benchmarked reproducibly. This is what runs
                  in dry-run mode.
  * LLMBrain    — builds prompts, calls an OpenAI-compatible model, parses the
                  JSON it returns, and falls back to the mock rules if the model
                  returns something unusable. Untrusted findings are quarantined
                  before they ever reach the model.

Both return the same typed objects (Plan, list[CommandSpec]), so the
orchestrator never knows or cares which one it is using.
"""
from __future__ import annotations

import json
import re
from typing import List, Protocol

from .types import Plan, GeneralObjective, CommandSpec, Finding
from .injection import quarantine, SYSTEM_GUARDRAIL
from .llm import LLMClient, estimate_tokens


class Brain(Protocol):
    def plan(self, objective: str, findings: List[Finding]) -> Plan: ...
    def decompose(self, goal: str, findings: List[Finding],
                  scope: List[str]) -> List[CommandSpec]: ...
    def tokens_used(self) -> int: ...


# ---------------------------------------------------------------------------
# Deterministic rules shared by both brains (LLMBrain falls back to these).
# The commander walks a classic recon progression and then stops.
# ---------------------------------------------------------------------------
def _open_ports(findings: List[Finding]) -> List[int]:
    ports = []
    for f in findings:
        if f.kind == "port":
            p = f.data.get("port")
            if isinstance(p, int):
                ports.append(p)
    return sorted(set(ports))


def _has(findings: List[Finding], kind: str) -> bool:
    return any(f.kind == kind for f in findings)


def _primary_host(findings: List[Finding], scope: List[str]) -> str:
    concrete = [s for s in scope if "/" not in s]
    host_findings = [f.target for f in findings if f.kind == "host"]
    # prefer a discovered host the operator explicitly scoped, so a broad sweep
    # that turns up several in-scope hosts doesn't make the loop fixate on
    # whichever one happened to answer first
    for h in host_findings:
        if h in concrete:
            return h
    if host_findings:
        return host_findings[0]
    if concrete:
        return concrete[0]
    return scope[0] if scope else "target"


def rule_plan(objective: str, findings: List[Finding]) -> Plan:
    if not _has(findings, "host") and not _has(findings, "port"):
        return Plan(False, "no recon yet — begin with host and port discovery",
                    [GeneralObjective("host and port discovery across the scope",
                                      "establish what is alive and reachable")])
    if _open_ports(findings) and not _has(findings, "service"):
        return Plan(False, "ports found — identify the services behind them",
                    [GeneralObjective("service and version enumeration on open ports",
                                      "turn open ports into actionable service facts")])
    ports = _open_ports(findings)
    if (80 in ports or 443 in ports) and not _has(findings, "web"):
        return Plan(False, "web service present — fingerprint it",
                    [GeneralObjective("web fingerprinting on http/https",
                                      "capture titles and tech stack")])
    return Plan(True, "recon objective satisfied: hosts, services and web surface mapped")


def rule_decompose(goal: str, findings: List[Finding],
                   scope: List[str]) -> List[CommandSpec]:
    g = goal.lower()
    host = _primary_host(findings, scope)
    if "host and port" in g or "discovery" in g:
        net = next((s for s in scope if "/" in s), host)
        return [
            CommandSpec("nmap", ["-sn", net], [net], "ping-sweep the scope"),
            CommandSpec("nmap", ["-p-", "--min-rate", "1000", "--open", host],
                        [host], "full TCP port scan of the primary host"),
        ]
    if "service" in g:
        ports = _open_ports(findings) or [22, 80, 445]
        plist = ",".join(str(p) for p in ports)
        return [CommandSpec("nmap", ["-sV", "-p", plist, host], [host],
                            "version-detect the open ports")]
    if "web" in g:
        return [
            CommandSpec("nmap", ["--script", "http-title", "-p", "80,443", host],
                        [host], "grab web titles"),
            CommandSpec("whatweb", ["-a", "1", host], [host], "fingerprint web tech"),
        ]
    # unknown goal -> safe no-op discovery
    return [CommandSpec("nmap", ["-sn", host], [host], "fallback liveness check")]


class MockBrain:
    def __init__(self) -> None:
        self._tokens = 0

    def plan(self, objective: str, findings: List[Finding]) -> Plan:
        self._tokens += 50
        return rule_plan(objective, findings)

    def decompose(self, goal: str, findings: List[Finding],
                  scope: List[str]) -> List[CommandSpec]:
        self._tokens += 40
        return rule_decompose(goal, findings, scope)

    def tokens_used(self) -> int:
        return self._tokens


# ---------------------------------------------------------------------------
# Real model brain.
# ---------------------------------------------------------------------------
_PLAN_SCHEMA = (
    'Return JSON only: {"done": bool, "reason": str, '
    '"objectives": [{"goal": str, "rationale": str}]}. '
    "Set done=true when hosts, services and any web surface are mapped."
)
_DECOMPOSE_SCHEMA = (
    'Return JSON only: {"commands": [{"binary": str, "args": [str], '
    '"targets": [str], "rationale": str}]}. '
    "binary must be one of: nmap, httpx, whatweb, dig, whois. "
    "Only use targets from the authorized scope."
)


def _findings_block(findings: List[Finding]) -> str:
    if not findings:
        return "(no findings yet)"
    lines = []
    for f in findings[-40:]:
        tag = " [SUSPICIOUS/quarantined]" if f.suspicious else ""
        lines.append(f"- ({f.kind}) {f.target}: {f.summary}{tag}")
    # the summaries derive from untrusted output, so fence the whole block
    return quarantine("\n".join(lines))


def _extract_json(text: str) -> dict:
    # tolerate models that wrap JSON in prose or code fences
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("no JSON object in model output")
    return json.loads(m.group(0))


class LLMBrain:
    def __init__(self, client: LLMClient, scope: List[str]):
        self.client = client
        self.scope = scope
        self._tokens = 0

    def _call(self, task_prompt: str) -> dict:
        messages = [
            {"role": "system", "content": SYSTEM_GUARDRAIL +
             f"\nAuthorized scope (the ONLY permitted targets): {self.scope}"},
            {"role": "user", "content": task_prompt},
        ]
        self._tokens += estimate_tokens(task_prompt) + 200
        raw = self.client.chat(messages)
        self._tokens += estimate_tokens(raw)
        return _extract_json(raw)

    def plan(self, objective: str, findings: List[Finding]) -> Plan:
        prompt = (f"Objective: {objective}\n\nFindings so far:\n"
                  f"{_findings_block(findings)}\n\n{_PLAN_SCHEMA}")
        try:
            obj = self._call(prompt)
            objectives = [GeneralObjective(o["goal"], o.get("rationale", ""))
                          for o in obj.get("objectives", [])]
            return Plan(bool(obj.get("done", False)),
                        str(obj.get("reason", "")), objectives)
        except Exception:
            return rule_plan(objective, findings)  # safe fallback

    def decompose(self, goal: str, findings: List[Finding],
                  scope: List[str]) -> List[CommandSpec]:
        prompt = (f"General objective: {goal}\n\nFindings so far:\n"
                  f"{_findings_block(findings)}\n\n{_DECOMPOSE_SCHEMA}")
        try:
            obj = self._call(prompt)
            specs = []
            for c in obj.get("commands", []):
                specs.append(CommandSpec(
                    str(c["binary"]), [str(a) for a in c.get("args", [])],
                    [str(t) for t in c.get("targets", [])],
                    str(c.get("rationale", "")),
                ))
            return specs or rule_decompose(goal, findings, scope)
        except Exception:
            return rule_decompose(goal, findings, scope)

    def tokens_used(self) -> int:
        return self._tokens
