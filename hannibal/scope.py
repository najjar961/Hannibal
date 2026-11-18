"""Scope enforcement — the single most important safety control.

Every command, from any agent, must pass through ScopeGuard before it can run.
The guard does two independent things:

  1. Checks the CommandSpec.targets the brain declared.
  2. Re-parses the raw argument list for anything that *looks* like a host or
     network and checks that too.

Either check failing blocks the command. This "declare and re-verify" design
means a hallucinated or injected target cannot execute even if one layer is
fooled. Hostnames that don't resolve to an allow-listed value are blocked by
default; the guard never silently widens scope.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import List, Optional, Tuple

# crude but effective extractors for the re-verification pass
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_HOSTISH = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")

# arguments that are never targets (avoids false "out of scope" on flag values)
_NON_TARGET_TOKENS = {"http", "https", "tcp", "udp"}


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

        resolve=True lets a hostname pass if it resolves to an in-scope IP. It
        is off by default: DNS is attacker-influenceable, so the safe default
        is to require that the exact hostname be allow-listed.
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
                self._hostnames.add(item.lower())
        if not self._networks and not self._hostnames:
            raise ScopeError("scope is empty — refusing to run with no authorized targets")

    # -- membership ---------------------------------------------------------
    def _ip_in_scope(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._networks)

    def _host_in_scope(self, host: str) -> bool:
        host = host.lower()
        if host in self._hostnames:
            return True
        if self.resolve:
            try:
                for res in socket.getaddrinfo(host, None):
                    if self._ip_in_scope(res[4][0]):
                        return True
            except socket.gaierror:
                return False
        return False

    def _token_in_scope(self, token: str) -> bool:
        token = token.rstrip("/")
        # a bare network/ip
        try:
            net = ipaddress.ip_network(token, strict=False)
            # every address of the candidate must fall inside an allowed net
            return any(net.subnet_of(a) for a in self._networks) or \
                   (net.num_addresses == 1 and self._ip_in_scope(str(net.network_address)))
        except ValueError:
            return self._host_in_scope(token)

    # -- extraction ---------------------------------------------------------
    @staticmethod
    def extract_targets(args: List[str]) -> List[str]:
        found: List[str] = []
        for a in args:
            if a.startswith("-"):
                continue
            for m in _IPV4.findall(a):
                found.append(m)
            for m in _HOSTISH.findall(a):
                if m.split(".")[0].lower() not in _NON_TARGET_TOKENS:
                    found.append(m)
        # de-dupe, preserve order
        seen, out = set(), []
        for t in found:
            if t not in seen:
                seen.add(t); out.append(t)
        return out

    # -- the gate -----------------------------------------------------------
    def check(self, declared_targets: List[str], args: List[str]) -> ScopeDecision:
        parsed = self.extract_targets(args)
        checked = list(dict.fromkeys([*declared_targets, *parsed]))
        if not checked:
            return ScopeDecision(False, "no target found in command", checked)
        for t in checked:
            if not self._token_in_scope(t):
                return ScopeDecision(False, f"target {t!r} is outside the authorized scope", checked)
        return ScopeDecision(True, "all targets in scope", checked)
