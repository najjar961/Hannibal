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
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from .types import CommandSpec

# characters that must never appear in an argument (defence in depth; we never
# use a shell, but this blocks obviously malformed / injected args early)
_FORBIDDEN = re.compile(r"[;&|`$><\n\r]")


# ---------------------------------------------------------------------------
# Per-tool argument grammar.
#
# Every argument must be accounted for: a known flag, a known flag's value
# (validated), a known keyword, or a target. Anything else is rejected. The
# targets this produces are what ScopeGuard checks, so the guard sees exactly
# what the tool will see instead of guessing with a regex. (The earlier regex
# extractor let through whatever it didn't recognise: nmap octet ranges such as
# 10.0-255.0-255.1-254, integer IPs, IPv6, single-label names, and file paths
# after -oN / --log-json.)
# ---------------------------------------------------------------------------
Validator = Callable[[str], Optional[str]]   # returns an error string or None


@dataclass
class ArgGrammar:
    flags: Set[str] = field(default_factory=set)                # take no value
    value_flags: Dict[str, Validator] = field(default_factory=dict)
    target_value_flags: Set[str] = field(default_factory=set)   # value is a target (httpx -u)
    attached: Dict[str, Validator] = field(default_factory=dict)  # nmap -p80 style
    keywords: Set[str] = field(default_factory=set)             # bare non-target words (lowercase)
    at_target: bool = False                                     # dig @server is a target


# Risk tiers — the rules of engagement. The orchestrator runs a command on its
# own only if its tier is <= RunConfig.max_auto_tier; anything higher is held
# for a human (or refused) before it can touch a target.
#   1 = recon: observes the target (port scans, fingerprinting, DNS)
#   2 = attack: sends probes designed to trigger a vulnerability
TIER_RECON = 1
TIER_ATTACK = 2
TIER_NAMES = {TIER_RECON: "recon", TIER_ATTACK: "attack"}


@dataclass
class AllowedCommand:
    binary: str
    description: str
    grammar: ArgGrammar
    tier: int = TIER_RECON


def _int_between(lo: int, hi: int) -> Validator:
    def _v(val: str) -> Optional[str]:
        if not val.isdigit() or not lo <= int(val) <= hi:
            return f"value {val!r} must be an integer {lo}-{hi}"
        return None
    return _v


def _one_of(*choices: str) -> Validator:
    allowed = {c.lower() for c in choices}
    def _v(val: str) -> Optional[str]:
        if val.lower() not in allowed:
            return f"value {val!r} not permitted (allowed: {', '.join(sorted(allowed))})"
        return None
    return _v


_PORT_ITEM = r"(?:[TU]:)?\d{1,5}(?:-\d{1,5})?"
_PORT_SPEC = re.compile(rf"{_PORT_ITEM}(?:,{_PORT_ITEM})*")


def _ports(val: str) -> Optional[str]:
    if not _PORT_SPEC.fullmatch(val):
        return f"port spec {val!r} is not a plain port list"
    for n in re.findall(r"\d+", val):
        if not 0 <= int(n) <= 65535:
            return f"port {n} out of range"
    return None


# nmap --script is powerful; restrict to safe, non-intrusive scripts. -sC / -A
# are NOT allowed: they run nmap's whole "default" script set and would make
# this allowlist meaningless.
_SAFE_NMAP_SCRIPTS = re.compile(r"^(http-title|http-headers|banner|ssl-cert|"
                                r"dns-axfr|smb-os-discovery|ssh-hostkey)$")


def _scripts(val: str) -> Optional[str]:
    for s in val.split(","):
        if not _SAFE_NMAP_SCRIPTS.match(s.strip()):
            return f"nmap script {s!r} not on the safe-script allowlist"
    return None


def _stdout_only(val: str) -> Optional[str]:
    # output goes to stdout so it can be parsed; a path would let the model
    # write (or overwrite) arbitrary files with partly attacker-controlled text
    if val != "-":
        return f"output must go to stdout ('-'), not to file {val!r}"
    return None


_DNS_TYPES = ("a", "aaaa", "mx", "ns", "txt", "soa", "cname", "ptr", "srv", "any", "axfr")

# nuclei template tags a wraith may select. Detection-only families; the
# destructive / noisy ones (dos, fuzz, intrusive, brute-force, default-login)
# are not on the list, and the runner also excludes them explicitly.
_SAFE_NUCLEI_TAGS = {"exposure", "misconfig", "cve", "panel", "config", "tech",
                     "files", "disclosure", "takeover", "ssl"}
_NUCLEI_SEVERITIES = {"info", "low", "medium", "high", "critical"}
# always appended to a real nuclei run (see _with_structured_output)
NUCLEI_FORCED_FLAGS = ["-jsonl", "-silent", "-nc", "-duc", "-ni"]
NUCLEI_EXCLUDED_TAGS = "dos,fuzz,intrusive,brute-force,default-login"


def _nuclei_tags(val: str) -> Optional[str]:
    for t in val.split(","):
        if t.strip().lower() not in _SAFE_NUCLEI_TAGS:
            return f"nuclei tag {t!r} not on the safe-tag allowlist"
    return None


def _nuclei_severity(val: str) -> Optional[str]:
    for s in val.split(","):
        if s.strip().lower() not in _NUCLEI_SEVERITIES:
            return f"nuclei severity {s!r} not recognised"
    return None

# The recon-only allowlist. Deliberately conservative; extend intentionally.
REGISTRY: Dict[str, AllowedCommand] = {
    "nmap": AllowedCommand(
        "nmap", "port/host discovery and safe service detection",
        ArgGrammar(
            flags={"-sn", "-sV", "-p-", "-Pn", "-T2", "-T3", "-T4", "--open"},
            value_flags={"-p": _ports, "--min-rate": _int_between(1, 100_000),
                         "--top-ports": _int_between(1, 65535),
                         "--script": _scripts, "-oX": _stdout_only},
            attached={"-p": _ports},
        ),
    ),
    "httpx": AllowedCommand(
        "httpx", "HTTP probing / title + tech detection",
        ArgGrammar(flags={"-title", "-tech-detect", "-status-code", "-sc", "-td",
                          "-json", "-silent"},
                   target_value_flags={"-u"}),
    ),
    "whatweb": AllowedCommand(
        "whatweb", "web technology fingerprinting",
        # --log-json is gone: it takes a file path (arbitrary file write)
        ArgGrammar(flags={"--color"},
                   value_flags={"-a": _int_between(1, 4),
                                "--color": _one_of("never", "always", "auto")}),
    ),
    "dig": AllowedCommand(
        "dig", "DNS lookups",
        ArgGrammar(flags={"+short"}, value_flags={"-t": _one_of(*_DNS_TYPES)},
                   keywords=set(_DNS_TYPES), at_target=True),
    ),
    "whois": AllowedCommand("whois", "registration lookup", ArgGrammar()),
    # The first attack-tier wraith. Template-based web vulnerability scanner.
    # Deliberately NOT allowed: -t/-w/-l (load templates, workflows or target
    # lists from arbitrary paths or URLs), -o (file write), -H (headers), the
    # headless / code / fuzzing engines, and interactsh (-ni is forced: OOB
    # callbacks would make the *target* contact an outside server — traffic
    # that leaves the authorized scope).
    "nuclei": AllowedCommand(
        "nuclei", "template-based web vulnerability scan (detection only)",
        ArgGrammar(flags={"-silent", "-jsonl", "-nc", "-duc", "-ni"},
                   value_flags={"-tags": _nuclei_tags,
                                "-severity": _nuclei_severity,
                                "-rl": _int_between(1, 50),
                                "-timeout": _int_between(1, 30)},
                   target_value_flags={"-u"}),
        tier=TIER_ATTACK,
    ),
    # web crawler (recon tier): discovers URLs/endpoints on a site, including
    # parameterized ones — richer attack surface for nuclei, and the input a
    # future access-control test needs. Crawl-only: no form submission
    # (-aff/-fx), no headless browser, no file output (-o), no custom headers,
    # no proxy. Stays on the target domain.
    "katana": AllowedCommand(
        "katana", "web crawler — discover endpoints (crawl only)",
        ArgGrammar(flags={"-silent", "-nc", "-jsonl"},
                   value_flags={"-d": _int_between(1, 3),
                                "-c": _int_between(1, 20),
                                "-rl": _int_between(1, 50),
                                "-rd": _int_between(0, 10)},
                   target_value_flags={"-u"}),
        tier=TIER_RECON,
    ),
}


def tier_of(binary: str) -> int:
    """Risk tier of a tool. Unknown tools get an unreachable tier (deny)."""
    cmd = REGISTRY.get(binary)
    return cmd.tier if cmd is not None else 99


def parse_args(binary: str, args: List[str]) -> Tuple[List[str], Optional[str]]:
    """Split an argument vector into its targets, or return an error.

    Deny by default: a token that is not a known flag, a validated flag value or
    a known keyword is a target, and every target is scope-checked later.
    """
    cmd = REGISTRY.get(binary)
    if cmd is None:
        return [], f"command {binary!r} is not on the recon allowlist"
    g = cmd.grammar
    targets: List[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if not a or _FORBIDDEN.search(a) or a != a.strip():
            return [], f"forbidden character or whitespace in argument {a!r}"
        if a.startswith("-") and len(a) > 1:
            if a.startswith("--") and "=" in a:
                name, val = a.split("=", 1)
                if name in g.value_flags:
                    err = g.value_flags[name](val)
                    if err:
                        return [], err
                elif name in g.target_value_flags:
                    targets.append(val)
                else:
                    return [], f"flag {name!r} not permitted for {binary}"
            elif a in g.flags:
                pass
            elif a in g.value_flags or a in g.target_value_flags:
                if i + 1 >= len(args):
                    return [], f"flag {a!r} needs a value"
                i += 1
                val = args[i]
                if _FORBIDDEN.search(val):
                    return [], f"forbidden character in argument {val!r}"
                if a in g.value_flags:
                    err = g.value_flags[a](val)
                    if err:
                        return [], err
                else:
                    targets.append(val)
            else:
                for prefix, check in g.attached.items():
                    if a.startswith(prefix) and len(a) > len(prefix):
                        err = check(a[len(prefix):])
                        if err:
                            return [], err
                        break
                else:
                    return [], f"flag {a.split('=', 1)[0]!r} not permitted for {binary}"
        elif a.startswith("+"):
            if a not in g.flags:
                return [], f"option {a!r} not permitted for {binary}"
        elif a.lower() in g.keywords:
            pass
        elif g.at_target and a.startswith("@"):
            targets.append(a[1:])
        else:
            targets.append(a)
        i += 1
    return targets, None


def validate(spec: CommandSpec) -> Optional[str]:
    """Allowlist + argument-grammar check. Scope is checked separately."""
    _, err = parse_args(spec.binary, spec.args)
    return err


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
    # attack-tier tools take URLs; the lab is keyed by host
    from urllib.parse import urlsplit
    hosts = [urlsplit(t).hostname or t if "://" in t else t for t in spec.targets]
    box = resolve_box(hosts)
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

    if spec.binary == "nuclei":
        # emit the same JSON-lines shape real `nuclei -jsonl` prints, so one
        # parser handles both simulated and real runs
        import json
        base = next((t for t in spec.targets if "://" in t), f"http://{ip}").rstrip("/")
        if box.web_endpoint_port() is None:
            return ""
        return "\n".join(json.dumps({
            "template-id": v["id"],
            "info": {"name": v["name"], "severity": v["severity"]},
            "type": "http", "host": base,
            "matched-at": base + str(v.get("path", "/")),
            "extracted-results": list(v.get("evidence", [])),
        }) for v in box.vulns)

    if spec.binary == "katana":
        if box.web_endpoint_port() is None or not box.endpoints:
            return ""
        base = f"http://{ip}"
        return "\n".join(base + path for path in box.endpoints)

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
    if spec.binary == "nuclei":
        args += [f for f in NUCLEI_FORCED_FLAGS if f not in args]
        args += ["-etags", NUCLEI_EXCLUDED_TAGS]
        if "-rl" not in args:
            args += ["-rl", "10"]   # gentle default: 10 requests / second
    if spec.binary == "katana":
        for f in ("-silent", "-nc"):
            if f not in args:
                args.append(f)
        if "-d" not in args:
            args += ["-d", "2"]
        if "-rl" not in args:
            args += ["-rl", "10"]   # gentle default: 10 requests / second
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
