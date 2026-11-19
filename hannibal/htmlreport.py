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

_KIND_ORDER = {"host": 0, "port": 1, "service": 2, "web": 3, "note": 4}


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

    # attack-surface analysis (read-only, advisory)
    from .analysis import analyze, summarize
    weaknesses = analyze(findings)
    wcounts = summarize(weaknesses)
    wrows = []
    for w in weaknesses:
        cve = (f'<a href="https://nvd.nist.gov/vuln/detail/{html.escape(w.cve)}" '
               f'target="_blank" rel="noopener">{html.escape(w.cve)}</a>') if w.cve else "—"
        wrows.append(
            f'<tr><td><span class="sev sev--{w.severity}">{w.severity}</span></td>'
            f'<td class="mono">{html.escape(w.host)}:{w.port}</td>'
            f'<td>{html.escape(w.title)}<div class="note">{html.escape(w.note)}</div></td>'
            f'<td class="mono">{cve}</td></tr>')
    wtable = "\n".join(wrows)
    wsummary = " · ".join(f"{wcounts[s]} {s}" for s in
                          ("critical", "high", "medium", "low", "info") if wcounts[s])
    weakness_section = ("" if not weaknesses else f"""
  <h2>Attack surface <span class="muted">— {html.escape(wsummary)} · advisory, verify manually</span></h2>
  <table><tr><th>severity</th><th>host</th><th>weakness</th><th>reference</th></tr>
  {wtable}
  </table>""")

    # findings table
    rows = []
    for f in sorted(findings, key=lambda x: (_KIND_ORDER.get(x.kind, 9), x.target)):
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

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hannibal — scan report</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<script>mermaid.initialize({{startOnLoad:true, theme:'dark',
  themeVariables:{{primaryColor:'#161b22',lineColor:'#1a786e',
  primaryTextColor:'#f0f4f8',primaryBorderColor:'#2dd4bf'}}}});</script>
<style>
  :root{{--bg:#0d1117;--panel:#161b22;--line:#222;--teal:#2dd4bf;
    --dim:#8b949e;--white:#f0f4f8;--bad:#f85149;--badbg:#2d1414;}}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--bg);color:var(--white);
    font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;padding:32px}}
  .wrap{{max-width:980px;margin:0 auto}}
  h1{{margin:0;font-size:30px;letter-spacing:.5px}}
  h1 .x{{color:var(--teal)}}
  .sub{{color:var(--teal);font-family:ui-monospace,monospace;margin:4px 0 2px}}
  .meta{{color:var(--dim);font-family:ui-monospace,monospace;font-size:13px}}
  .rule{{height:3px;background:var(--teal);width:120px;margin:16px 0 24px;border-radius:2px}}
  .stats{{display:flex;flex-wrap:wrap;gap:12px;margin:0 0 20px}}
  .stat{{background:var(--panel);border:1px solid var(--line);border-radius:10px;
    padding:14px 18px;min-width:110px}}
  .stat--accent{{border-color:var(--teal)}}
  .stat__v{{font-size:26px;font-weight:700}}
  .stat__l{{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.5px}}
  .badge{{display:inline-block;padding:2px 9px;border-radius:20px;font-size:12px;
    font-family:ui-monospace,monospace}}
  .badge--ok{{background:#0f2e1a;color:#3fb950;border:1px solid #1a5}}
  .badge--bad{{background:var(--badbg);color:var(--bad);border:1px solid #633}}
  .pill{{display:inline-block;background:var(--panel);border:1px solid var(--teal);
    color:var(--teal);border-radius:20px;padding:4px 12px;font-size:13px;
    font-family:ui-monospace,monospace;margin-left:8px}}
  h2{{font-size:16px;margin:28px 0 12px;color:var(--white)}}
  table{{width:100%;border-collapse:collapse;background:var(--panel);
    border:1px solid var(--line);border-radius:10px;overflow:hidden}}
  th,td{{text-align:left;padding:10px 14px;border-bottom:1px solid var(--line);
    vertical-align:top}}
  th{{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.5px}}
  tr:last-child td{{border-bottom:none}}
  .row--bad{{background:var(--badbg)}}
  .mono{{font-family:ui-monospace,monospace;font-size:13px}}
  .kind{{font-family:ui-monospace,monospace;font-size:12px;padding:1px 7px;
    border-radius:5px;background:#1b2330;color:var(--teal)}}
  .kind--web{{color:#d29922}} .kind--service{{color:#a371f7}}
  .graph{{background:var(--panel);border:1px solid var(--line);border-radius:10px;
    padding:18px;overflow:auto}}
  .sev{{font-family:ui-monospace,monospace;font-size:11px;padding:2px 8px;
    border-radius:5px;text-transform:uppercase;letter-spacing:.5px;font-weight:700}}
  .sev--critical{{background:#3d0f12;color:#ff6b6b;border:1px solid #a33}}
  .sev--high{{background:#3a230d;color:#ff9d4d;border:1px solid #a63}}
  .sev--medium{{background:#3a360d;color:#e3c93a;border:1px solid #883}}
  .sev--low{{background:#12263a;color:#4da3ff;border:1px solid #358}}
  .sev--info{{background:#1b2330;color:var(--dim);border:1px solid #333}}
  .note{{color:var(--dim);font-size:12px;margin-top:3px}}
  .muted{{color:var(--dim);font-size:12px;font-weight:400}}
  a{{color:var(--teal)}}
  .foot{{color:var(--dim);font-size:12px;margin-top:28px;border-top:1px solid var(--line);
    padding-top:14px}}
</style></head>
<body><div class="wrap">
  <h1>⚔ HANNIBAL <span class="x">scan report</span></h1>
  <div class="sub">objective: {html.escape(objective)}</div>
  <div class="meta">scope: {html.escape(scope)} · {audit_badge} {rt}</div>
  <div class="rule"></div>

  <div class="stats">
    {_stat("rounds", meta["rounds"])}
    {_stat("commands", meta["commands"])}
    {_stat("~tokens", meta["tokens"])}
    {_stat("findings", sum(counts.values()))}
    {_stat("weaknesses", len(weaknesses), accent=len(weaknesses) > 0)}
    {_stat("quarantined", suspicious_n, accent=suspicious_n > 0)}
  </div>

  <h2>Findings</h2>
  <table><tr><th>kind</th><th>target</th><th>detail</th></tr>
  {table}
  </table>
{weakness_section}
  <h2>Provenance graph</h2>
  <div class="graph"><pre class="mermaid">{html.escape(mermaid)}</pre></div>

  <div class="foot">Generated by Hannibal · authorized lab use only ·
    stopped: {html.escape(meta["reason"] or "—")}</div>
</div></body></html>"""


def write_report(workdir: str, out_path: str) -> str:
    htmltext = build_html(workdir)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(htmltext)
    return out_path
