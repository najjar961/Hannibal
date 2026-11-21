"""Scope enforcement — the single most important safety control.

Every command, from any agent, must pass through ScopeGuard before it can run.
The guard checks two things, and either failing blocks the command:

  1. The CommandSpec.targets the brain declared.
  2. The targets actually present in the argument vector, as split out by the
     per-tool grammar in commands.parse_args — the same tokens the tool will
     act on, not a regex guess at them.

Deny by default. A target passes only if it is
  * an IP address or CIDR (in canonical dotted / colon notation) that lies
    entirely inside an allow-listed network, or
  * a hostname allow-listed exactly (or, with resolve=True, one that resolves
    only to in-scope addresses), or
  * a URL / host:port whose host passes one of the above.

Everything else is rejected — including the forms that slipped through the
earlier regex-based extractor: nmap octet ranges (10.0-255.0-255.1-254),
wildcards, integer / hex / shorthand IPs (167772161, 0x0a0a0a05, 10.1), IPv6
outside scope, unlisted single-label names (localhost) and URLs with userinfo
(http://10.10.10.5@8.8.8.8). The guard never silently widens scope.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlsplit

from .commands import parse_args

# a syntactically valid DNS name (labels of letters, digits and hyphens)
_HOSTNAME = re.compile(
    r"(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*")
# numeric-looking tokens that are not canonical IPs: nmap ranges and octet
# lists (10.10.10-11.5, 10.1,2.3.4), wildcards, integer / hex / shorthand IPs.
# Tools and resolvers expand these in ways a set-membership check cannot see.
_NUMERICISH = re.compile(r"[0-9.,*\-]+|(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+))*", re.I)
_HOST_PORT = re.compile(r"([^:\[\]@/]+):(\d{1,5})")
_BRACKETED_V6 = re.compile(r"\[([0-9a-fA-F:.]+)\](?::\d{1,5})?")


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    checked: List[str]


class ScopeError(Exception):
    pass


class ScopeGuard:
    def __init__(self, scope: List[str], resolve: bool = False):
        """scope: list of IPs, CIDRs or hostnames the run is authorized to touch.

        resolve=True lets a hostname pass if every address it resolves to is in
        scope. It is off by default: DNS is attacker-influenceable, so the safe
        default is to require that the exact hostname be allow-listed.
        """
        self.resolve = resolve
        self._networks: List[ipaddress._BaseNetwork] = []
        self._hostnames: set[str] = set()
        for item in scope:
            item = item.strip()
            if not item:
                continue
            try:
                self._networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                if not _HOSTNAME.fullmatch(item) or _NUMERICISH.fullmatch(item):
                    raise ScopeError(f"scope entry {item!r} is not an IP, CIDR or hostname")
                self._hostnames.add(item.lower().rstrip("."))
        if not self._networks and not self._hostnames:
            raise ScopeError("scope is empty — refusing to run with no authorized targets")

    # -- membership ---------------------------------------------------------
    def _net_in_scope(self, net: ipaddress._BaseNetwork) -> bool:
        # every address of the candidate must fall inside one allowed network
        return any(net.version == a.version and net.subnet_of(a) for a in self._networks)

    def _host_in_scope(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        if host in self._hostnames:
            return True
        if self.resolve:
            try:
                addrs = {res[4][0] for res in socket.getaddrinfo(host, None)}
            except (socket.gaierror, UnicodeError):
                return False
            # all resolved addresses must be in scope, not just one of them
            return bool(addrs) and all(
                self._net_in_scope(ipaddress.ip_network(a.split("%", 1)[0]))
                for a in addrs)
        return False

    @staticmethod
    def _host_part(token: str) -> Optional[str]:
        """The host a token points at, or None if the token is malformed."""
        if "://" in token:
            try:
                parts = urlsplit(token)
                parts.port  # raises ValueError on a bad port
            except ValueError:
                return None
            if parts.username is not None or parts.password is not None:
                return None   # http://in-scope@out-of-scope
            return parts.hostname
        if "@" in token or "/" in token and not re.fullmatch(r"[0-9a-fA-F:.]+/\d{1,3}", token):
            return None
        m = _BRACKETED_V6.fullmatch(token)
        if m:
            return m.group(1)
        m = _HOST_PORT.fullmatch(token)
        if m:
            return m.group(1)
        return token

    def why_out_of_scope(self, token: str) -> Optional[str]:
        """None if the token is in scope, otherwise the reason it is not."""
        host = self._host_part(token.strip())
        if not host:
            return f"target {token!r} is malformed (userinfo, bad port or path)"
        try:
            net = ipaddress.ip_network(host, strict=False)
        except ValueError:
            net = None
        if net is not None:
            if self._net_in_scope(net):
                return None
            return f"target {token!r} is outside the authorized scope"
        if _NUMERICISH.fullmatch(host):
            return (f"target {token!r} is a range, wildcard or non-canonical IP — "
                    "write in-scope targets as plain IPs or CIDRs")
        if not _HOSTNAME.fullmatch(host):
            return f"target {token!r} is not a valid IP, CIDR or hostname"
        if self._host_in_scope(host):
            return None
        return f"target {token!r} is outside the authorized scope"

    # -- the gate -----------------------------------------------------------
    def check(self, declared_targets: List[str], args: List[str],
              binary: Optional[str] = None) -> ScopeDecision:
        """Allow a command only if every declared and actual target is in scope.

        With `binary`, the tool's grammar splits the args exactly. Without it,
        every non-flag argument is treated as a target (stricter, never looser).
        """
        if binary is not None:
            actual, err = parse_args(binary, args)
            if err:
                return ScopeDecision(False, f"command rejected: {err}", [])
        else:
            actual = [a for a in args if not a.startswith("-")]
        checked = list(dict.fromkeys([*declared_targets, *actual]))
        if not actual:
            return ScopeDecision(False, "no target found in command arguments", checked)
        for t in checked:
            why = self.why_out_of_scope(t)
            if why:
                return ScopeDecision(False, why, checked)
        return ScopeDecision(True, "all targets in scope", checked)
