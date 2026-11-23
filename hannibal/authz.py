"""Access-control (IDOR / BOLA) testing — the check a scanner can't do.

Parameterized endpoints reference objects by id. If the application hands back a
*different* object just because you changed the id, it isn't enforcing
object-level authorization — a broken-access-control / IDOR flaw, consistently
one of the most damaging and most common web weaknesses. A signature scanner
like nuclei can't find this: it requires reasoning about whether an identifier
*should* be reachable. This does the standard manual test automatically —
request an object reference, request a sibling id, and compare the responses.

It is detection-only and scope-bound. It reports that cross-object access
appears possible, with the two URLs as evidence; it never stores the returned
data and never escalates. Confirming real impact against production data is a
human decision. In --execute it issues two scoped GETs per endpoint (the host is
checked against the run's scope first, and nothing out of scope is ever
requested); in dry-run it is modeled against the lab. Responses are reduced to a
coarse fingerprint (status + size bucket) — the body itself is never retained.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, List, Optional
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from .types import Finding


@dataclass
class Resp:
    ok: bool
    fp: str          # coarse fingerprint of the response — never the body itself


def _ident(url: str) -> Optional[str]:
    """The object identifier in a URL — a numeric query value or path segment."""
    parts = urlsplit(url)
    for _, v in parse_qsl(parts.query):
        if v.isdigit():
            return v
    for seg in parts.path.split("/"):
        if seg.isdigit():
            return seg
    return None


def _sibling(url: str) -> Optional[str]:
    """The same URL with its object id changed to a neighbour (id+1)."""
    parts = urlsplit(url)
    q = parse_qsl(parts.query)
    for i, (k, v) in enumerate(q):
        if v.isdigit():
            q2 = list(q)
            q2[i] = (k, str(int(v) + 1))
            return urlunsplit(parts._replace(query=urlencode(q2)))
    segs = parts.path.split("/")
    for i, seg in enumerate(segs):
        if seg.isdigit():
            segs[i] = str(int(seg) + 1)
            return urlunsplit(parts._replace(path="/".join(segs)))
    return None


def _endpoint_key(url: str) -> str:
    """Identity of an endpoint ignoring the id value, so id=1 and id=2 of the
    same endpoint are tested once, not twice."""
    parts = urlsplit(url)
    q = urlencode([(k, "" if v.isdigit() else v) for k, v in parse_qsl(parts.query)])
    path = re.sub(r"/\d+(?=/|$)", "/#", parts.path)
    return f"{parts.hostname}{path}?{q}"


def test_endpoint(url: str, fetch: Callable[[str], Resp]) -> Optional[dict]:
    """Return evidence of an IDOR at `url`, or None.

    An IDOR is indicated when the original and a sibling object reference are
    *both* reachable and return *distinct* content — i.e. the id, not the
    session, decided what you got back.
    """
    sib = _sibling(url)
    if sib is None:
        return None
    a = fetch(url)
    b = fetch(sib)
    if a.ok and b.ok and a.fp != b.fp:
        return {"url": url, "sibling": sib}
    return None


def check_access_control(urls: List[str], fetch: Callable[[str], Resp]) -> List[Finding]:
    """Run the access-control test over parameterized endpoints -> idor findings."""
    out: List[Finding] = []
    seen = set()
    for url in urls:
        key = _endpoint_key(url)
        if key in seen:
            continue
        seen.add(key)
        hit = test_endpoint(url, fetch)
        if not hit:
            continue
        host = urlsplit(url).hostname or url
        out.append(Finding(
            "idor", f"{url} [access-control]",
            "[HIGH] Broken object-level authorization (IDOR)",
            {"template": "access-control-idor", "severity": "high",
             "matched_at": url,
             "evidence": [f"{hit['url']} and {hit['sibling']} return different "
                          "objects — the id, not the session, controls access"],
             "validated": True},   # the differential test is itself the proof
            parent_target=host))
    return out


# --- fetchers -------------------------------------------------------------

def sim_fetch(url: str) -> Resp:
    """Deterministic fetcher for dry-run, backed by the lab's ground truth."""
    from .lab import resolve_box
    parts = urlsplit(url)
    box = resolve_box([parts.hostname or ""])
    if box is None:
        return Resp(False, "")
    ident = _ident(url)
    if ident is None:
        return Resp(True, "static")
    vulnerable = any(parts.path.startswith(pre) for pre in getattr(box, "idor", []))
    # a vulnerable endpoint returns a distinct object per id; a safe one returns
    # the same (its own object / an access-denied page) regardless of the id
    return Resp(True, f"object-{ident}" if vulnerable else "same")


def make_scoped_fetch(guard, timeout: float = 5.0) -> Callable[[str], Resp]:
    """Real fetcher for --execute: two scoped GETs, in-scope only, body discarded."""
    import urllib.request

    def fetch(url: str) -> Resp:
        if guard.why_out_of_scope(url) is not None:
            return Resp(False, "")      # never request anything out of scope
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Hannibal"})
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
                body = r.read(8192)
                status = getattr(r, "status", 200)
                return Resp(status == 200, f"{status}:{len(body) // 128}")
        except Exception:
            return Resp(False, "")

    return fetch
