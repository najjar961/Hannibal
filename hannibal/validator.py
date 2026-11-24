"""Finding validator — turn raw detections into confirmed findings.

A nuclei match is a *detection*: the scanner saw a pattern that *suggests* a
weakness. Before a detection is reported as real it should be corroborated, so
an operator reads a short list of confirmed issues instead of wading through
scanner noise. The false-positive rate is the single number that decides
whether anyone trusts an automated pentest, so this is where the trust is won.

This validator is deliberately NON-destructive and adds no new capability. It
does not exploit anything and sends no new traffic of its own — it re-examines
the evidence a detection already produced and decides, by a deterministic rule
per detection class, whether that evidence actually corroborates the claim.
Exploit-based proof is intentionally out of scope for this tool, which stays
detection-and-validation only; a real exploit attempt is a human decision.

Outcome per `vuln` finding:
  * validated=True  — the evidence corroborates the claim (e.g. an env-file
    detection whose body actually contains KEY=value secret lines)
  * validated=False — detected but not corroborated; flagged for manual review
Each carries a short, human-readable reason in `data["validation"]`.

A finding whose evidence tripped the injection scanner is never auto-validated:
the evidence is attacker-controlled, so a human reads it instead.
"""
from __future__ import annotations

import re
from typing import List, Tuple

from .types import Finding

# an uppercase KEY = value line, the shape of a leaked secret in a .env / config
_KEYVAL = re.compile(r"[A-Z][A-Z0-9_]{2,}\s*=\s*\S")

# template ids that denote remote code execution / command injection
_RCE_HINT = re.compile(r"rce|cgi|shellshock|command-exec|cmd.?inj|1823|log4j|"
                       r"struts|deserial", re.I)
# markers that a command or code actually ran in the response (not just a match)
_EXEC_PROOF = re.compile(r"uid=\d|gid=\d|root:.*:0:0:|www-data|php version|"
                         r"/bin/(?:ba)?sh|drwx[r-]", re.I)


def _corroborates(template: str, evidence: str) -> Tuple[bool, str]:
    """Does the collected evidence actually back up this detection class?

    Deny by default: a detection class with no rule here, or whose evidence
    lacks the expected markers, stays unconfirmed. Being honest that we *can't*
    confirm something is the whole point — a false 'confirmed' is worse than an
    honest 'needs review'.
    """
    t = template.lower()
    low = evidence.lower()

    def has(*subs: str) -> bool:
        return any(s.lower() in low for s in subs)

    # RCE / command-injection: only confirm when the evidence actually shows
    # code or a command running (command output, a shell, /etc/passwd, PHP
    # output). A bare detection with no execution proof stays manual review —
    # an automated tool must not declare "confirmed RCE" without real output.
    if _RCE_HINT.search(t):
        if _EXEC_PROOF.search(evidence):
            return True, "response shows command/code-execution output"
        return False, "RCE detected but no execution output captured — verify by hand"

    if "env" in t:
        if _KEYVAL.search(evidence):
            return True, "response body contains KEY=value secret lines"
        return False, "no secret-looking KEY=value lines in the response"
    if "git" in t:
        if has("[core]", "repositoryformatversion", "url =", "[remote"):
            return True, "response body is a real git config"
        return False, "response lacked git-config markers"
    if "phpinfo" in t:
        if has("php version", "phpinfo()"):
            return True, "page carries the phpinfo() banner"
        return False, "no phpinfo() banner in the page"
    if "dir" in t or "listing" in t:
        if has("index of", "parent directory"):
            return True, "directory-index markup present"
        return False, "no directory-index markers"
    if "swagger" in t or "openapi" in t or "api" in t:
        if has("swagger", "openapi", '"paths"', "api"):
            return True, "API / Swagger documentation markers present"
        return False, "no API-doc markers in the response"
    if "sql" in t or "backup" in t or "dump" in t:
        if has("insert into", "create table", "mysql dump", "-- dump",
               "sqlite format"):
            return True, "response body is a database dump"
        return False, "no database-dump markers in the response"
    if "ssl" in t or "tls" in t or "cert" in t:
        return False, "certificate findings need manual review"
    return False, "no corroboration rule for this detection type — manual review"


def validate_finding(f: Finding) -> Tuple[bool, str]:
    """Validate a single `vuln` finding from its own evidence."""
    if f.kind != "vuln":
        return False, ""
    if f.suspicious:
        # attacker-controlled evidence that tripped the injection scanner is
        # exactly what we must NOT trust to auto-confirm anything
        return False, "evidence quarantined (possible injection) — manual review"
    evidence = f.data.get("evidence") or []
    text = " ".join(str(e) for e in evidence)
    if not text.strip():
        return False, "detection produced no evidence to corroborate"
    return _corroborates(str(f.data.get("template", "")), text)


def validate_findings(findings: List[Finding]) -> List[Finding]:
    """Annotate every `vuln` finding in place with its validation outcome.

    Idempotent: the summary marker is rewritten, not appended, so running this
    twice does not stack ' — CONFIRMED — CONFIRMED'.
    """
    for f in findings:
        if f.kind != "vuln":
            continue
        ok, reason = validate_finding(f)
        f.data["validated"] = ok
        f.data["validation"] = reason
        base = f.summary.split("  —  ")[0]
        f.summary = f"{base}  —  {'CONFIRMED' if ok else 'unconfirmed'}"
    return findings


def enrich_evidence(findings: List[Finding], transcript) -> None:
    """Augment each vuln finding's evidence with the real response body the
    scope proxy captured for its matched URL, in place.

    A nuclei detection ships only a thin `extracted-results` snippet; the proxy
    recorded the full response the tool actually received. Corroborating against
    the real body makes a CONFIRMED verdict mean more. HTTP only — Phase 1 does
    not capture HTTPS bodies (see proxy.py).

    The body is attacker-controlled: if it tripped the proxy's injection scan,
    the finding is marked suspicious, and validate_finding then holds it for
    manual review instead of auto-confirming. `transcript` is duck-typed (any
    object with `.body_for(url) -> Exchange|None`) so the validator stays
    decoupled from the proxy module.
    """
    for f in findings:
        if f.kind != "vuln":
            continue
        url = str(f.data.get("matched_at") or f.target or "")
        ex = transcript.body_for(url)
        if ex is None:
            continue
        evidence = list(f.data.get("evidence") or [])
        snippet = (ex.body or "")[:2000]
        if snippet and snippet not in evidence:
            evidence.append(snippet)
        f.data["evidence"] = evidence
        f.data["proxy_status"] = ex.status
        if ex.suspicious:
            f.suspicious = True


def validation_counts(findings: List[Finding]) -> Tuple[int, int]:
    """(confirmed, total) over the `vuln` findings."""
    vulns = [f for f in findings if f.kind == "vuln"]
    confirmed = sum(1 for f in vulns if f.data.get("validated"))
    return confirmed, len(vulns)
