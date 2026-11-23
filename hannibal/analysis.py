"""Read-only attack-surface analysis.

Hannibal is a *recon* tool and stops short of exploitation by design. This layer
sits on top of the findings and does what a pentester does next in their head:
look at each discovered service and version and flag the publicly-known
weaknesses associated with it — a CVE, a cleartext-protocol exposure, a service
that shouldn't be internet-facing.

It is deliberately advisory and non-actionable: it names the weakness and points
at public references, but ships no exploit, payload, or step-by-step. Every hit
is a lead to verify by hand, under authorization — not a confirmed vulnerability.
Matching is signature-based over the service name and version banner that recon
already captured, so it runs offline against stored findings and never touches
the target again.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from .types import Finding

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class Weakness:
    host: str
    port: int
    service: str
    severity: str          # critical | high | medium | low | info
    title: str             # what the weakness is, in plain words
    cve: str               # "CVE-…" when there is one, else ""
    evidence: str          # the banner/version that triggered the match
    note: str              # one-line advisory (what to check, never how to exploit)
    remediation: str = ""  # recommended fix, for the report's remediation column


@dataclass(frozen=True)
class _Sig:
    """One signature. A field left None is a wildcard; all set fields must match."""
    severity: str
    title: str
    note: str
    name_re: Optional[str] = None     # matched against the service name
    ver_re: Optional[str] = None      # matched against the version banner
    port: Optional[int] = None        # matched against the port number
    cve: str = ""

    def hit(self, name: str, ver: str, port: int) -> bool:
        if self.name_re and not re.search(self.name_re, name, re.I):
            return False
        if self.ver_re and not re.search(self.ver_re, ver, re.I):
            return False
        if self.port is not None and self.port != port:
            return False
        # a signature that constrains nothing is meaningless — never match
        return any(x is not None for x in (self.name_re, self.ver_re, self.port))


# Curated knowledge base. Version-specific CVEs plus protocol/exposure issues
# that depend only on a service being reachable. References are public (NVD).
_SIGNATURES: List[_Sig] = [
    # --- version-specific, high-confidence backdoors / RCEs ---
    _Sig("critical", "vsftpd 2.3.4 backdoor",
         "Known malicious build; a ':)' username opens a root shell on 6200. Verify the exact build.",
         name_re=r"vsftpd|ftp", ver_re=r"2\.3\.4", cve="CVE-2011-2523"),
    _Sig("critical", "Samba 'username map script' command injection",
         "Shell metacharacters in the username are executed by smbd. Confirm the Samba version.",
         name_re=r"samba|smbd|netbios|microsoft-ds", ver_re=r"3\.0\.2\d", cve="CVE-2007-2447"),
    _Sig("critical", "UnrealIRCd backdoor",
         "The 3.2.8.1 tarball shipped with a backdoor. Confirm the server version string.",
         ver_re=r"unreal", cve="CVE-2010-2075"),
    _Sig("critical", "distccd remote command execution",
         "distcc accepts and runs arbitrary compile jobs when exposed. Should never be reachable.",
         name_re=r"distcc", cve="CVE-2004-2687"),
    _Sig("critical", "Metasploitable bind shell",
         "An open root shell listening on 1524 — a deliberate backdoor, not a real service.",
         port=1524),
    # --- version-specific, medium ---
    _Sig("medium", "OpenSSH username enumeration",
         "Pre-7.7 OpenSSH leaks valid usernames via timing. Confirm the version.",
         name_re=r"openssh|ssh", ver_re=r"(?:[0-6]\.|7\.[0-6])", cve="CVE-2018-15473"),
    _Sig("high", "MySQL authentication bypass (affected builds)",
         "Some 5.0/5.1 builds accept a bad password ~1/256 tries. Verify the build.",
         name_re=r"mysql", ver_re=r"5\.[01]\.", cve="CVE-2012-2122"),
    _Sig("medium", "Outdated Apache httpd",
         "2.2.x is end-of-life with many fixed CVEs. Check against the running version.",
         name_re=r"apache", ver_re=r"2\.2\.", cve=""),
    _Sig("medium", "Outdated ISC BIND",
         "9.4.x is end-of-life (cache-poisoning era). Review the resolver config.",
         name_re=r"bind", ver_re=r"9\.[0-4]\.", cve=""),
    # --- protocol / exposure issues (depend only on reachability) ---
    _Sig("high", "Cleartext Telnet exposed",
         "Credentials and session travel unencrypted. Replace with SSH.",
         name_re=r"telnet", port=23),
    _Sig("high", "r-services exposed (rexec/rlogin/rsh)",
         "Trust-based, cleartext remote access — no place on a modern host.",
         port=512),
    _Sig("high", "r-services exposed (rexec/rlogin/rsh)",
         "Trust-based, cleartext remote access — no place on a modern host.",
         port=513),
    _Sig("high", "r-services exposed (rexec/rlogin/rsh)",
         "Trust-based, cleartext remote access — no place on a modern host.",
         port=514),
    _Sig("high", "VNC exposed",
         "Remote desktop reachable; often weak or no auth. Restrict and require strong auth.",
         name_re=r"vnc", port=5900),
    _Sig("medium", "Open X11 server",
         "An unauthenticated X server allows keystroke capture and screen access.",
         port=6000),
    _Sig("medium", "NFS export reachable",
         "Enumerate exports (showmount); world-readable shares are common here.",
         name_re=r"nfs", port=2049),
    _Sig("low", "rpcbind reachable",
         "Portmapper discloses registered RPC services; useful for further enumeration.",
         name_re=r"rpcbind|portmapper", port=111),
    _Sig("medium", "Apache Tomcat manager exposed",
         "Tomcat on 8180 frequently ships default manager credentials. Check /manager.",
         name_re=r"tomcat|coyote|ajp", cve=""),
]


# Recommended fix per weakness title — defensive guidance only (what to do,
# never how to exploit). Keyed by the signature's title so one entry covers all
# ports that share it (e.g. the three r-services rows).
_REMEDIATION = {
    "vsftpd 2.3.4 backdoor":
        "Remove the compromised package and reinstall a current vsftpd from a "
        "trusted repository; treat the host as breached and rotate credentials.",
    "Samba 'username map script' command injection":
        "Upgrade Samba to a supported release and remove any `username map "
        "script` directive from smb.conf.",
    "UnrealIRCd backdoor":
        "Rebuild from a verified UnrealIRCd source on a current release and "
        "treat the host as compromised.",
    "distccd remote command execution":
        "Disable distccd or bind it to localhost; never expose the distcc "
        "daemon to untrusted networks.",
    "Metasploitable bind shell":
        "Unauthenticated root shell — rebuild the host; it must not run in any "
        "real environment.",
    "OpenSSH username enumeration":
        "Upgrade OpenSSH to 7.7 or later.",
    "MySQL authentication bypass (affected builds)":
        "Upgrade MySQL/MariaDB to a patched build and restrict the service to "
        "trusted hosts only.",
    "Outdated Apache httpd":
        "Upgrade to a supported Apache httpd release and apply current patches.",
    "Outdated ISC BIND":
        "Upgrade BIND to a supported version and review recursion/exposure.",
    "Cleartext Telnet exposed":
        "Disable Telnet; use SSH for remote administration.",
    "r-services exposed (rexec/rlogin/rsh)":
        "Disable the r-services (rexec/rlogin/rsh) and use SSH instead.",
    "VNC exposed":
        "Restrict VNC to a management network or VPN, require strong auth, or "
        "tunnel it over SSH.",
    "Open X11 server":
        "Disable remote X11 access or require xauth; never run `xhost +`.",
    "NFS export reachable":
        "Restrict exports to specific hosts, disable world-readable shares, and "
        "firewall the service.",
    "rpcbind reachable":
        "Firewall rpcbind/portmapper from untrusted networks and disable unused "
        "RPC services.",
    "Apache Tomcat manager exposed":
        "Remove or restrict the Tomcat manager app and change default "
        "credentials.",
}


def remediation_for_vuln(template: str, severity: str = "") -> str:
    """Recommended fix for a nuclei vuln finding, by template family."""
    t = (template or "").lower()
    table = [
        (("1823", "cgi"), "Stop running PHP via CGI or upgrade PHP to a patched "
                          "release; php-cgi query-string injection allows RCE."),
        (("env",), "Remove the exposed file from the web root and rotate any "
                   "secrets it contained."),
        (("git",), "Block access to the .git directory and remove it from the "
                   "web root."),
        (("phpinfo",), "Remove phpinfo() pages from production."),
        (("dir", "listing"), "Disable directory listing (e.g. Options -Indexes)."),
        (("swagger", "openapi", "api"), "Restrict access to API documentation in "
                                        "production."),
        (("sql", "backup", "dump"), "Remove database dumps/backups from the web "
                                    "root and rotate exposed credentials."),
        (("shellshock",), "Patch Bash (CVE-2014-6271) and disable CGI scripts "
                          "that invoke the shell."),
        (("idor", "access-control", "bola"),
         "Enforce object-level authorization: confirm the authenticated session "
         "owns the requested object before returning it."),
    ]
    for keys, fix in table:
        if any(k in t for k in keys):
            return fix
    if severity.lower() in ("critical", "high"):
        return ("Verify the finding and patch or remove the affected component "
                "as a priority.")
    return "Review and remediate the affected component as appropriate."


def analyze(findings: List[Finding]) -> List[Weakness]:
    """Map service findings to known weaknesses, most severe first."""
    out: List[Weakness] = []
    seen = set()
    for f in findings:
        if f.kind != "service":
            continue
        name = str((f.data or {}).get("service") or "").lower()
        ver = str((f.data or {}).get("version") or "")
        host = f.parent_target or ""
        try:
            port = int((f.data or {}).get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        for sig in _SIGNATURES:
            if sig.hit(name, ver, port):
                key = (host, port, sig.title)
                if key in seen:
                    continue
                seen.add(key)
                out.append(Weakness(
                    host=host, port=port, service=name or sig.name_re or "?",
                    severity=sig.severity, title=sig.title, cve=sig.cve,
                    evidence=(ver or f.summary), note=sig.note,
                    remediation=_REMEDIATION.get(sig.title, "")))
    return sorted(out, key=lambda w: (_SEV_ORDER.get(w.severity, 9), w.host, w.port))


def summarize(weaknesses: List[Weakness]) -> dict:
    """Severity histogram for headline counts."""
    counts = {s: 0 for s in _SEV_ORDER}
    for w in weaknesses:
        counts[w.severity] = counts.get(w.severity, 0) + 1
    return counts
