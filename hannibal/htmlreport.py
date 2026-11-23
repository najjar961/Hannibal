"""Render a run into a self-contained HTML scan report.

Reads the run's SQLite findings + the audit log and produces one standalone
HTML file: summary stats, a findings table (suspicious rows flagged), the
provenance graph (Mermaid, rendered via CDN), and a verified audit-integrity
badge. No server, no build step — open it in a browser or share the file.
"""
from __future__ import annotations

import html
import json
import os
from typing import Dict, List, Optional

from .store import Store, to_mermaid
from .audit import AuditLog
from .types import Finding
from .analysis import remediation_for_vuln

_KIND_ORDER = {"vuln": -1, "host": 0, "port": 1, "service": 2, "web": 3, "note": 4}


def _run_meta(workdir: str) -> Dict:
    """Pull objective/scope/stats from the audit log's start+end events."""
    meta: Dict = {"objective": "", "scope": [], "rounds": 0, "commands": 0,
                  "tokens": 0, "reason": "", "ts": None}
    path = os.path.join(workdir, "audit.log")
    if not os.path.exists(path):
        return meta
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            d = e.get("data", {})
            if e.get("event") == "run_start":
                meta["objective"] = d.get("objective", "")
                meta["scope"] = d.get("scope", [])
                meta["ts"] = e.get("ts")
            elif e.get("event") == "run_end":
                meta.update(rounds=d.get("rounds", 0), commands=d.get("commands", 0),
                            tokens=d.get("tokens", 0), reason=d.get("reason", ""))
    return meta


def _stat(label: str, value, accent: bool = False) -> str:
    cls = " stat--accent" if accent else ""
    return (f'<div class="stat{cls}"><div class="stat__v">{html.escape(str(value))}</div>'
            f'<div class="stat__l">{html.escape(label)}</div></div>')


_SEV_RANK = ["critical", "high", "medium", "low", "info"]


def _severity_rollup(vulns: List[Finding], weaknesses) -> Dict[str, int]:
    """Count every issue — confirmed/detected vulns plus advisory leads — by
    severity, so the report opens with the risk picture a reader needs first."""
    counts = {s: 0 for s in _SEV_RANK}
    for f in vulns:
        sev = str((f.data or {}).get("severity", "info")).lower()
        counts[sev if sev in counts else "info"] += 1
    for w in weaknesses:
        sev = str(w.severity).lower()
        counts[sev if sev in counts else "info"] += 1
    return counts


def _risk_rating(counts: Dict[str, int]) -> str:
    """Overall posture = the highest severity present."""
    for sev in _SEV_RANK:
        if counts.get(sev):
            return sev
    return "info"


def _vuln_rows(vulns: List[Finding]) -> str:
    rows = []
    order = {s: i for i, s in enumerate(_SEV_RANK)}
    for f in sorted(vulns, key=lambda x: order.get(
            str((x.data or {}).get("severity", "info")).lower(), 9)):
        d = f.data or {}
        sev = str(d.get("severity", "info")).lower()
        confirmed = bool(d.get("validated"))
        status = ('<span class="badge badge--ok">✓ confirmed</span>' if confirmed
                  else '<span class="badge badge--warn">needs review</span>')
        reason = html.escape(str(d.get("validation", "")))
        ev = d.get("evidence") or []
        eh = ""
        if ev:
            items = "".join(f"<code>{html.escape(str(e))}</code>" for e in ev[:4])
            eh = f'<div class="ev">{items}</div>'
        name = html.escape(f.summary.split("  —  ")[0])
        where = html.escape(str(d.get("matched_at", f.target)))
        tmpl = str(d.get("template", ""))
        fix = remediation_for_vuln(tmpl, sev)
        rem = f'<div class="fix"><b>Recommendation:</b> {html.escape(fix)}</div>' if fix else ""
        rows.append(
            f'<tr><td><span class="sev sev--{sev}">{sev}</span></td>'
            f'<td>{name}<div class="note">{reason}</div>{eh}{rem}</td>'
            f'<td class="mono">{html.escape(where)}<div class="note">{html.escape(tmpl)}</div></td>'
            f'<td>{status}</td></tr>')
    return "\n".join(rows)


def build_html(workdir: str) -> str:
    db = os.path.join(workdir, "hannibal.sqlite")
    store = Store(db)
    findings: List[Finding] = store.all_findings()
    counts = store.counts()
    store.close()

    meta = _run_meta(workdir)
    audit_path = os.path.join(workdir, "audit.log")
    audit_ok, audit_msg, audit_n = (False, "no audit log", 0)
    if os.path.exists(audit_path):
        audit_ok, audit_msg, audit_n = AuditLog.verify(
            audit_path, os.environ.get("HANNIBAL_AUDIT_KEY"))

    suspicious_n = sum(1 for f in findings if f.suspicious)
    mermaid = to_mermaid(findings)
    vulns = [f for f in findings if f.kind == "vuln"]
    endpoints = [f for f in findings if f.kind == "endpoint"]
    ep_param = sum(1 for f in endpoints if (f.data or {}).get("parameterized"))

    # attack-surface analysis (read-only, advisory)
    from .analysis import analyze, summarize, remediation_for_vuln
    weaknesses = analyze(findings)
    wcounts = summarize(weaknesses)
    wrows = []
    for w in weaknesses:
        cve = (f'<a href="https://nvd.nist.gov/vuln/detail/{html.escape(w.cve)}" '
               f'target="_blank" rel="noopener">{html.escape(w.cve)}</a>') if w.cve else "—"
        rem = (f'<div class="fix"><b>Recommendation:</b> {html.escape(w.remediation)}</div>'
               if w.remediation else "")
        wrows.append(
            f'<tr><td><span class="sev sev--{w.severity}">{w.severity}</span></td>'
            f'<td class="mono">{html.escape(w.host)}:{w.port}</td>'
            f'<td>{html.escape(w.title)}<div class="note">{html.escape(w.note)}</div>{rem}</td>'
            f'<td class="mono">{cve}</td></tr>')
    wtable = "\n".join(wrows)
    wsummary = " · ".join(f"{wcounts[s]} {s}" for s in
                          ("critical", "high", "medium", "low", "info") if wcounts[s])

    # executive summary — risk rating + severity rollup across everything
    rollup = _severity_rollup(vulns, weaknesses)
    rating = _risk_rating(rollup)
    confirmed_n = sum(1 for f in vulns if (f.data or {}).get("validated"))
    seg = "".join(
        f'<div class="seg seg--{s}" style="flex:{rollup[s]}" title="{rollup[s]} {s}"></div>'
        for s in _SEV_RANK if rollup[s])
    chips = " ".join(f'<span class="sev sev--{s}">{rollup[s]} {s}</span>'
                     for s in _SEV_RANK if rollup[s]) or '<span class="muted">none</span>'
    total_issues = sum(rollup.values())
    exec_summary = f"""
  <div class="exec exec--{rating}">
    <div class="exec__rating">{html.escape(rating.upper())}</div>
    <div class="exec__body">
      <div class="exec__line"><b>{total_issues}</b> issue(s) across the target —
        <b>{confirmed_n}</b> confirmed by evidence,
        the rest advisory and to verify by hand.</div>
      <div class="bar">{seg}</div>
      <div class="chips">{chips}</div>
    </div>
  </div>"""

    # confirmed / detected vulnerabilities (own section, severity-sorted)
    vuln_section = ("" if not vulns else f"""
  <h2>Vulnerabilities <span class="muted">— {len(vulns)} detected · {confirmed_n} confirmed</span></h2>
  <table><tr><th>sev</th><th>finding</th><th>location</th><th>status</th></tr>
  {_vuln_rows(vulns)}
  </table>""")
    weakness_section = ("" if not weaknesses else f"""
  <h2>Attack surface <span class="muted">— {html.escape(wsummary)} · advisory, verify manually</span></h2>
  <table><tr><th>severity</th><th>host</th><th>weakness</th><th>reference</th></tr>
  {wtable}
  </table>""")

    # recon inventory table (vulns get their own section above)
    rows = []
    for f in sorted([x for x in findings if x.kind != "vuln"],
                    key=lambda x: (_KIND_ORDER.get(x.kind, 9), x.target)):
        flag = '<span class="badge badge--bad">⚠ quarantined</span>' if f.suspicious else ""
        rows.append(
            f'<tr class="{ "row--bad" if f.suspicious else "" }">'
            f'<td><span class="kind kind--{html.escape(f.kind)}">{html.escape(f.kind)}</span></td>'
            f'<td class="mono">{html.escape(f.target)}</td>'
            f'<td>{html.escape(f.summary)} {flag}</td></tr>')
    table = "\n".join(rows) or '<tr><td colspan="3">no findings</td></tr>'

    audit_badge = (f'<span class="badge badge--ok">✓ audit intact · {audit_n} entries</span>'
                   if audit_ok else
                   f'<span class="badge badge--bad">✗ {html.escape(audit_msg)}</span>')

    # optional red-team scorecard
    rt = ""
    rt_path = os.path.join(workdir, "..", "redteam_results.json")
    for cand in (os.path.join(workdir, "redteam_results.json"), rt_path):
        if os.path.exists(cand):
            try:
                d = json.load(open(cand, encoding="utf-8"))
                rt = (f'<div class="pill">injection red-team: '
                      f'{d.get("catch")}/{d.get("total")} caught · '
                      f'{d.get("false_positives")}/{d.get("benign")} false positives</div>')
            except Exception:
                pass
            break

    scope = ", ".join(meta["scope"]) if meta["scope"] else "—"
    objective = meta["objective"] or "(unknown)"

    import datetime
    try:
        report_date = (datetime.datetime.fromtimestamp(meta["ts"]) if meta.get("ts")
                       else datetime.datetime.now()).strftime("%B %d, %Y")
    except Exception:
        report_date = datetime.date.today().strftime("%B %d, %Y")
    objective_statement = ("Autonomously discover, validate, and prioritize "
                           "exploitable weaknesses across the target's exposed "
                           "attack surface, under controlled rules of engagement.")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Assessment Report — Hannibal</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<script>mermaid.initialize({{startOnLoad:true, theme:'neutral'}});</script>
<style>
  :root{{--ink:#1a2233;--body:#344054;--muted:#667085;--line:#e4e7ec;
    --soft:#f9fafb;--accent:#0f766e;--page:#eef0f3;
    --crit:#b42318;--high:#b54708;--med:#9f6407;--low:#175cd3;--info:#475467;}}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--page);color:var(--body);
    font:15px/1.6 ui-sans-serif,-apple-system,Segoe UI,Roboto,Helvetica,sans-serif}}
  .doc{{max-width:820px;margin:28px auto;background:#fff;border:1px solid var(--line);
    border-radius:4px;box-shadow:0 1px 3px rgba(16,24,40,.08);
    padding:52px 56px}}
  .ink{{color:var(--ink)}}
  .mono{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}}
  .muted{{color:var(--muted);font-size:12.5px;font-weight:400}}
  a{{color:var(--accent);text-decoration:none}} a:hover{{text-decoration:underline}}
  .eyebrow{{font-size:11px;letter-spacing:2px;text-transform:uppercase;
    color:var(--crit);font-weight:700}}
  h1{{margin:6px 0 2px;font-size:27px;letter-spacing:-.2px;color:var(--ink);font-weight:700}}
  .byline{{color:var(--muted);font-size:13px}}
  .lead{{margin:16px 0 0;font-size:15px;color:var(--ink);font-style:italic;
    border-left:3px solid var(--crit);padding-left:14px}}
  .classif{{float:right;border:1px solid #fecdca;background:#fef3f2;color:var(--crit);
    border-radius:3px;font-size:10.5px;letter-spacing:1.5px;font-weight:700;
    padding:3px 9px;text-transform:uppercase}}
  .metagrid{{display:grid;grid-template-columns:1fr 1fr;gap:2px 28px;margin:22px 0 4px;
    border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:16px 0}}
  .metagrid div{{font-size:13px}}
  .metagrid .k{{color:var(--muted);text-transform:uppercase;font-size:10.5px;
    letter-spacing:1px;margin-bottom:1px}}
  h2{{font-size:13px;letter-spacing:1px;text-transform:uppercase;color:var(--ink);
    margin:34px 0 12px;padding-bottom:7px;border-bottom:2px solid var(--ink);font-weight:700}}
  h2 .muted{{text-transform:none;letter-spacing:0}}
  .badge{{display:inline-block;padding:2px 9px;border-radius:3px;font-size:11.5px;
    font-weight:600;white-space:nowrap}}
  .badge--ok{{background:#ecfdf3;color:#067647;border:1px solid #abefc6}}
  .badge--warn{{background:#fffaeb;color:#b54708;border:1px solid #fedf89}}
  .badge--bad{{background:#fef3f2;color:#b42318;border:1px solid #fecdca}}
  .exec{{display:flex;gap:20px;align-items:stretch;background:var(--soft);
    border:1px solid var(--line);border-left-width:4px;border-radius:4px;
    padding:18px 20px;margin:4px 0 8px}}
  .exec--critical{{border-left-color:var(--crit)}} .exec--high{{border-left-color:var(--high)}}
  .exec--medium{{border-left-color:var(--med)}} .exec--low{{border-left-color:var(--low)}}
  .exec--info{{border-left-color:var(--info)}}
  .exec__rating{{font-weight:800;font-size:13px;letter-spacing:1.5px;align-self:center;
    min-width:74px;text-align:center}}
  .exec--critical .exec__rating{{color:var(--crit)}} .exec--high .exec__rating{{color:var(--high)}}
  .exec--medium .exec__rating{{color:var(--med)}} .exec--low .exec__rating{{color:var(--low)}}
  .exec--info .exec__rating{{color:var(--info)}}
  .exec__body{{flex:1}} .exec__line{{margin-bottom:12px;color:var(--ink)}}
  .bar{{display:flex;height:9px;border-radius:5px;overflow:hidden;margin-bottom:11px;
    background:#eaecf0}}
  .seg--critical{{background:var(--crit)}} .seg--high{{background:var(--high)}}
  .seg--medium{{background:var(--med)}} .seg--low{{background:var(--low)}} .seg--info{{background:#98a2b3}}
  .chips{{display:flex;gap:7px;flex-wrap:wrap}}
  .ev{{margin-top:7px;display:flex;flex-direction:column;gap:3px}}
  .ev code{{background:#fff;border:1px solid var(--line);border-radius:3px;
    padding:2px 6px;font-size:12px;color:#344054;font-family:ui-monospace,monospace;
    overflow-wrap:anywhere}}
  .pill{{display:inline-block;background:#fff;border:1px solid var(--line);
    color:var(--body);border-radius:3px;padding:3px 10px;font-size:12px;margin-left:6px}}
  table{{width:100%;border-collapse:collapse;font-size:13.5px;margin-top:2px}}
  th,td{{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);
    vertical-align:top}}
  thead th,table tr:first-child th{{color:var(--muted);font-size:10.5px;
    text-transform:uppercase;letter-spacing:.8px;border-bottom:1.5px solid #d0d5dd}}
  tbody tr:hover,tr:hover{{background:var(--soft)}}
  .row--bad{{background:#fef6f6}}
  .kind{{font-family:ui-monospace,monospace;font-size:11px;padding:1px 7px;
    border-radius:3px;background:#f2f4f7;color:var(--body)}}
  .kind--web{{color:var(--high)}} .kind--service{{color:#6941c6}}
  .kind--vuln{{color:var(--crit);background:#fef3f2}}
  .graph{{background:var(--soft);border:1px solid var(--line);border-radius:4px;
    padding:18px;overflow:auto}}
  .sev{{display:inline-block;font-size:10.5px;padding:2px 8px;border-radius:3px;
    text-transform:uppercase;letter-spacing:.5px;font-weight:700}}
  .sev--critical{{background:#fef3f2;color:var(--crit);border:1px solid #fecdca}}
  .sev--high{{background:#fff4ed;color:var(--high);border:1px solid #fddcab}}
  .sev--medium{{background:#fffaeb;color:var(--med);border:1px solid #fedf89}}
  .sev--low{{background:#eff8ff;color:var(--low);border:1px solid #b2ddff}}
  .sev--info{{background:#f2f4f7;color:var(--info);border:1px solid #e4e7ec}}
  .note{{color:var(--muted);font-size:12px;margin-top:3px}}
  .fix{{color:var(--ink);font-size:12.5px;margin-top:6px;background:var(--soft);
    border:1px solid var(--line);border-radius:3px;padding:6px 9px}}
  .fix b{{color:var(--accent)}}
  .foot{{color:var(--muted);font-size:11.5px;margin-top:34px;border-top:1px solid var(--line);
    padding-top:16px}}
  @media print{{body{{background:#fff}}.doc{{box-shadow:none;border:none;margin:0;
    max-width:none;padding:0}}tr:hover{{background:none}}}}
</style></head>
<body><div class="doc">
  <span class="classif">Confidential</span>
  <div class="eyebrow">Security Assessment Report</div>
  <h1>Autonomous Penetration Test</h1>
  <div class="byline">Prepared by <b>Hannibal</b> — autonomous reconnaissance &amp; vulnerability orchestrator</div>

  <p class="lead">{html.escape(objective_statement)}</p>

  <div class="metagrid">
    <div><div class="k">Target / Scope</div><span class="mono ink">{html.escape(scope)}</span></div>
    <div><div class="k">Date</div><span class="ink">{html.escape(report_date)}</span></div>
    <div><div class="k">Methodology</div><span class="ink">Automated recon → attack → validation</span></div>
    <div><div class="k">Issues identified</div><span class="ink">{len(vulns)} vulnerabilit{"y" if len(vulns)==1 else "ies"} · {len(weaknesses)} advisory lead(s)</span></div>
    <div><div class="k">Evidence integrity</div>{audit_badge} {rt}</div>
    <div><div class="k">Endpoints crawled</div><span class="ink">{len(endpoints)} ({ep_param} parameterized)</span></div>
  </div>

  <h2>Executive summary</h2>
{exec_summary}
{vuln_section}
{weakness_section}
  <h2>Appendix A — Recon inventory</h2>
  <table><tr><th>kind</th><th>target</th><th>detail</th></tr>
  {table}
  </table>

  <h2>Appendix B — Finding provenance</h2>
  <div class="graph"><pre class="mermaid">{html.escape(mermaid)}</pre></div>

  <div class="foot">
    Produced by Hannibal, an autonomous security orchestrator. Advisory leads are
    derived from service-version signatures and must be manually verified before
    remediation. Testing was performed only against authorized, isolated systems.
    Engagement: {meta["rounds"]} rounds, {meta["commands"]} commands · termination: {html.escape(meta["reason"] or "—")}
  </div>
</div></body></html>"""


def write_report(workdir: str, out_path: str) -> str:
    htmltext = build_html(workdir)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(htmltext)
    return out_path
