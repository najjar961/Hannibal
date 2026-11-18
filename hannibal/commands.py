"""Command allowlist + runner.

Only reconnaissance tools are permitted, and each has an argument validator so
a wraith cannot, say, hand nmap a `--script` it shouldn't run or sneak a shell
metacharacter through. Execution is always `shell=False` with an explicit arg
vector, and only after ScopeGuard has approved it.

In dry-run mode (the default) the runner never spawns a process: it returns a
deterministic simulated banner so the full orchestration loop can be exercised,
demoed and benchmarked with zero setup and zero network traffic.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from .types import CommandSpec

# characters that must never appear in an argument (defence in depth; we never
# use a shell, but this blocks obviously malformed / injected args early)
_FORBIDDEN = re.compile(r"[;&|`$><\n\r]")


@dataclass
class AllowedCommand:
    binary: str
    description: str
    validate: Callable[[List[str]], Optional[str]]  # returns error string or None


def _only_flags_and_targets(allowed_flags: set[str]):
    def _v(args: List[str]) -> Optional[str]:
        for a in args:
            if _FORBIDDEN.search(a):
                return f"forbidden character in argument {a!r}"
            if a.startswith("-"):
                flag = a.split("=", 1)[0]
                if flag not in allowed_flags:
                    return f"flag {flag!r} not permitted for this command"
        return None
    return _v


# The recon-only allowlist. Deliberately conservative; extend intentionally.
REGISTRY: Dict[str, AllowedCommand] = {
    "nmap": AllowedCommand(
        "nmap", "port/host discovery and safe service detection",
        _only_flags_and_targets({
            "-sn", "-sV", "-sC", "-p", "-p-", "-Pn", "-T2", "-T3", "-T4",
            "--min-rate", "--top-ports", "-oX", "-oN", "--open", "-A",
            "--script",  # validated further below
        }),
    ),
    "httpx": AllowedCommand(
        "httpx", "HTTP probing / title + tech detection",
        _only_flags_and_targets({"-title", "-tech-detect", "-status-code",
                                 "-sc", "-td", "-json", "-silent", "-u"}),
    ),
    "whatweb": AllowedCommand(
        "whatweb", "web technology fingerprinting",
        _only_flags_and_targets({"-a", "--color", "--log-json"}),
    ),
    "dig": AllowedCommand(
        "dig", "DNS lookups", _only_flags_and_targets({"+short", "-t", "any", "axfr"}),
    ),
    "whois": AllowedCommand(
        "whois", "registration lookup", _only_flags_and_targets(set()),
    ),
}

# nmap --script is powerful; restrict to safe, non-intrusive categories/scripts
_SAFE_NMAP_SCRIPTS = re.compile(r"^(http-title|http-headers|banner|ssl-cert|"
                                r"dns-axfr|smb-os-discovery|ssh-hostkey)$")


def validate(spec: CommandSpec) -> Optional[str]:
    cmd = REGISTRY.get(spec.binary)
    if cmd is None:
        return f"command {spec.binary!r} is not on the recon allowlist"
    err = cmd.validate(spec.args)
    if err:
        return err
    # extra check for nmap scripts
    if spec.binary == "nmap":
        for i, a in enumerate(spec.args):
            val = None
            if a.startswith("--script="):
                val = a.split("=", 1)[1]
            elif a == "--script" and i + 1 < len(spec.args):
                val = spec.args[i + 1]
            if val:
                for s in val.split(","):
                    if not _SAFE_NMAP_SCRIPTS.match(s.strip()):
                        return f"nmap script {s!r} not on the safe-script allowlist"
    return None


# ---------------------------------------------------------------------------
# Deterministic simulator for dry-run mode. Output is generated from the lab
# box profiles (hannibal/lab.py), so the loop produces realistic, progressing
# findings and the benchmark can score discovery against known ground truth.
# Boxes flagged `injection` emit a web title carrying a prompt-injection payload
# to exercise the quarantine layer.
# ---------------------------------------------------------------------------
def _simulate(spec: CommandSpec) -> str:
    import ipaddress
    from .lab import resolve_box, LAB  # local import avoids a cycle at load

    line = spec.as_cmdline()
    box = resolve_box(spec.targets)
    if box is None:
        return f"[simulated] {line}\n(no host at that target in the lab)"
    ip = box.ip

    if spec.binary == "nmap" and "-sn" in spec.args:
        # a ping sweep of a network reports every live host in range, not one
        nets = []
        for t in spec.targets:
            try:
                nets.append(ipaddress.ip_network(t.strip(), strict=False))
            except ValueError:
                pass
        ups = [b.ip for h, b in LAB.items()
               if any(ipaddress.ip_address(h) in n for n in nets)] or [ip]
        return "\n".join(f"Nmap scan report for {u}\nHost is up (0.012s latency)."
                         for u in ups)

    if spec.binary == "nmap" and ("-p-" in spec.args or "--top-ports" in line):
        rows = "\n".join(f"{p}/tcp  open  {svc}"
                         for p, svc in sorted(box.ports.items()))
        return f"Nmap scan report for {ip}\nPORT    STATE SERVICE\n{rows}"

    if spec.binary == "nmap" and "-sV" in spec.args:
        rows = "\n".join(
            f"{p}/tcp  open  {box.ports[p]}  {box.versions.get(p, '')}".rstrip()
            for p in sorted(box.ports))
        return f"Nmap scan report for {ip}\n{rows}"

    if spec.binary in ("httpx", "whatweb") or "http-title" in line:
        if box.web_endpoint_port() is None:
            return f"http probe {ip}: no web service"
        # the title is attacker-controlled content (intentional test payload)
        return f"http://{ip} [200] [{box.web_title}] [{box.web_tech}]"

    if spec.binary == "dig":
        return f";; connection to {ip} — no zone transfer allowed"
    return f"[simulated] {line}\n(no notable output)"


def _with_structured_output(spec: CommandSpec) -> List[str]:
    """Add machine-readable output flags so real runs parse cleanly.

    nmap -> XML on stdout; httpx -> JSON lines. These flags are already on the
    allowlist; adding them here means the brain never has to remember to.
    """
    args = list(spec.args)
    if spec.binary == "nmap" and "-oX" not in args:
        args += ["-oX", "-"]
    if spec.binary == "httpx":
        if "-json" not in args:
            args.append("-json")
        if "-silent" not in args:
            args.append("-silent")
    return args


def run(spec: CommandSpec, execute: bool, timeout: int) -> str:
    """Run (or simulate) an already scope-approved, validated command."""
    if not execute:
        return _simulate(spec)
    if shutil.which(spec.binary) is None:
        return f"[skipped] {spec.binary} not installed on this host"
    try:
        proc = subprocess.run(
            [spec.binary, *_with_structured_output(spec)],
            capture_output=True, text=True, timeout=timeout, shell=False,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        return out.strip() or f"[no output] exit={proc.returncode}"
    except subprocess.TimeoutExpired:
        return f"[timeout] after {timeout}s"
    except Exception as e:  # pragma: no cover - defensive
        return f"[error] {e}"
