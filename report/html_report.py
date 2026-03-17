"""
report/html_report.py
─────────────────────
Phase 7: HTML Report Generator.

Produces a self-contained, single-file HTML dashboard with:
  - Executive summary cards
  - Severity distribution donut chart (Chart.js)
  - Risk score bar chart
  - Full findings table with sortable columns
  - Patch results section
  - Per-CWE breakdown
  - Diff viewer for patched files

No Flask required — generates static HTML directly.
"""

from __future__ import annotations
import json
import html as _html
from datetime import datetime
from pathlib import Path
from typing import Optional


def generate_html_report(
    all_results: dict,
    output_path: Optional[str] = None,
) -> str:
    """
    Generate a self-contained HTML dashboard.
    Returns the HTML string. Saves to output_path if provided.
    """
    p4 = all_results.get("phase4")
    p5 = all_results.get("phase5")
    p6 = all_results.get("phase6")

    vulns       = p4.sorted_by_risk() if p4 else []
    patch_res   = p6.patch_results   if p6 else []
    verify_res  = p6.verification    if p6 else []
    fix_rate    = p6.total_fix_rate  if p6 else 0.0

    # Load diff content if available
    diff_content = _load_diff(p6)

    html_str = _build_html(vulns, patch_res, verify_res, fix_rate, diff_content, all_results)

    if output_path:
        Path(output_path).write_text(html_str, encoding="utf-8")

    return html_str


def _load_diff(p6) -> str:
    if not p6 or not p6.patched_files:
        return ""
    for orig, patched in p6.patched_files.items():
        diff_path = Path(patched).parent / (Path(orig).stem + ".diff")
        if diff_path.exists():
            return diff_path.read_text(encoding="utf-8", errors="replace")
    return ""


def _build_html(vulns, patch_res, verify_res, fix_rate, diff_content, all_results) -> str:
    from rules.vuln_object import Severity

    p4 = all_results.get("phase4")
    p5 = all_results.get("phase5")

    n_total    = len(vulns)
    n_critical = sum(1 for v in vulns if v.severity == Severity.CRITICAL)
    n_high     = sum(1 for v in vulns if v.severity == Severity.HIGH)
    n_medium   = sum(1 for v in vulns if v.severity == Severity.MEDIUM)
    n_low      = sum(1 for v in vulns if v.severity == Severity.LOW)
    n_patched  = sum(1 for p in patch_res if p.success)

    # Chart data
    sev_data    = json.dumps([n_critical, n_high, n_medium, n_low])
    risk_labels = json.dumps([v.vuln_id for v in vulns[:15]])
    risk_data   = json.dumps([round(v.risk_score or 0, 3) for v in vulns[:15]])
    exp_data    = json.dumps([round(v.exploit_prob or 0, 3) for v in vulns[:15]])

    # CWE breakdown
    from collections import Counter
    cwe_counts  = Counter(v.cwe.value for v in vulns)
    cwe_labels  = json.dumps(list(cwe_counts.keys()))
    cwe_values  = json.dumps(list(cwe_counts.values()))

    # Agent mode
    agent_mode = p5.agent_mode if p5 else "N/A"
    n_decisions = p5.n_decisions if p5 else 0

    # Build findings rows
    findings_rows = ""
    sev_badge = {
        "CRITICAL": "badge-critical",
        "HIGH":     "badge-high",
        "MEDIUM":   "badge-medium",
        "LOW":      "badge-low",
        "INFO":     "badge-info",
    }
    for v in vulns:
        risk = v.risk_score or 0
        risk_cls = "risk-high" if risk >= 0.7 else "risk-med" if risk >= 0.4 else "risk-low"
        strategy = _html.escape(v.patch_strategy or "—")
        findings_rows += f"""
        <tr>
          <td><code>{_html.escape(v.vuln_id)}</code></td>
          <td><span class="badge {sev_badge.get(v.severity.value,'badge-info')}">{v.severity.value}</span></td>
          <td>{_html.escape(v.cwe.value)}</td>
          <td><code>{_html.escape(v.function_name or '—')}</code></td>
          <td>{v.line_start}</td>
          <td class="{risk_cls}">{risk:.3f}</td>
          <td>{(v.exploit_prob or 0):.0%}</td>
          <td><small>{strategy}</small></td>
        </tr>"""

    # Build patch rows
    patch_rows = ""
    for pr in patch_res:
        status_cls = "text-green" if pr.success else "text-red"
        status_txt = "✓ patched" if pr.success else "✗ failed"
        desc = _html.escape((pr.description or pr.error or "")[:80])
        patch_rows += f"""
        <tr>
          <td><code>{_html.escape(pr.vuln_id)}</code></td>
          <td><small>{_html.escape(pr.strategy)}</small></td>
          <td class="{status_cls}">{status_txt}</td>
          <td><small>{desc}</small></td>
        </tr>"""

    # Verification rows
    verify_rows = ""
    for vr in verify_res:
        rate_cls = "text-green" if vr.fix_rate >= 0.5 else "text-yellow"
        verify_rows += f"""
        <tr>
          <td><code>{_html.escape(Path(vr.patched_file).name)}</code></td>
          <td>{vr.vulns_before}</td>
          <td>{vr.vulns_after}</td>
          <td class="text-green">{vr.vulns_fixed}</td>
          <td class="{rate_cls}">{vr.fix_rate:.1%}</td>
        </tr>"""

    diff_html = ""
    if diff_content:
        escaped_diff = _html.escape(diff_content[:8000])
        diff_html = f"""
        <section>
          <h2>Unified Diff</h2>
          <pre class="diff-block">{escaped_diff}</pre>
        </section>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VAPT Intelligence System — Report</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    :root {{
      --bg:      #0d1117;
      --card:    #161b22;
      --border:  #30363d;
      --text:    #e6edf3;
      --muted:   #8b949e;
      --cyan:    #58a6ff;
      --green:   #3fb950;
      --red:     #f85149;
      --orange:  #e3b341;
      --purple:  #bc8cff;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace; }}
    header {{ background: var(--card); border-bottom: 1px solid var(--border); padding: 20px 40px; }}
    header h1 {{ color: var(--cyan); font-size: 1.6rem; }}
    header p  {{ color: var(--muted); font-size: 0.9rem; margin-top: 4px; }}
    main {{ max-width: 1400px; margin: 0 auto; padding: 32px 40px; }}
    h2 {{ color: var(--cyan); font-size: 1.1rem; margin: 32px 0 16px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 32px; }}
    .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-align: center; }}
    .card .num  {{ font-size: 2.2rem; font-weight: 700; line-height: 1; }}
    .card .label {{ color: var(--muted); font-size: 0.8rem; margin-top: 6px; }}
    .num.red    {{ color: var(--red); }}
    .num.orange {{ color: var(--orange); }}
    .num.cyan   {{ color: var(--cyan); }}
    .num.green  {{ color: var(--green); }}
    .num.purple {{ color: var(--purple); }}
    .charts {{ display: grid; grid-template-columns: 1fr 2fr; gap: 24px; margin-bottom: 32px; }}
    .chart-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }}
    .chart-card h3 {{ color: var(--muted); font-size: 0.85rem; margin-bottom: 16px; }}
    table {{ width: 100%; border-collapse: collapse; background: var(--card); border-radius: 8px; overflow: hidden; margin-bottom: 24px; }}
    thead th {{ background: #1c2128; color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); }}
    tbody td {{ padding: 9px 14px; font-size: 0.875rem; border-bottom: 1px solid #21262d; vertical-align: middle; }}
    tbody tr:hover {{ background: #1c2128; }}
    code {{ font-family: 'Courier New', monospace; font-size: 0.82rem; color: var(--cyan); background: #1c2128; padding: 1px 5px; border-radius: 3px; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }}
    .badge-critical {{ background: #3d1212; color: var(--red); border: 1px solid var(--red); }}
    .badge-high     {{ background: #2d1f0a; color: var(--orange); border: 1px solid var(--orange); }}
    .badge-medium   {{ background: #2a2208; color: #e3b341; border: 1px solid #e3b341; }}
    .badge-low      {{ background: #0d2216; color: var(--green); border: 1px solid var(--green); }}
    .badge-info     {{ background: #1c2128; color: var(--muted); border: 1px solid var(--border); }}
    .risk-high  {{ color: var(--red); font-weight: 600; }}
    .risk-med   {{ color: var(--orange); }}
    .risk-low   {{ color: var(--green); }}
    .text-green {{ color: var(--green); font-weight: 600; }}
    .text-red   {{ color: var(--red); }}
    .text-yellow{{ color: var(--orange); }}
    .diff-block {{ background: #0d1117; border: 1px solid var(--border); border-radius: 6px; padding: 16px; font-family: 'Courier New', monospace; font-size: 0.78rem; overflow-x: auto; white-space: pre; line-height: 1.5; color: #cdd9e5; max-height: 600px; overflow-y: auto; }}
    section {{ margin-bottom: 40px; }}
    footer {{ text-align: center; color: var(--muted); font-size: 0.8rem; padding: 32px; border-top: 1px solid var(--border); margin-top: 40px; }}
  </style>
</head>
<body>
  <header>
    <h1>⚡ VAPT Intelligence System</h1>
    <p>Agent-Orchestrated Hybrid Static Vulnerability Assessment &nbsp;|&nbsp; Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; Agent: {_html.escape(agent_mode)}</p>
  </header>

  <main>
    <!-- Summary Cards -->
    <div class="cards">
      <div class="card"><div class="num red">{n_critical}</div><div class="label">CRITICAL</div></div>
      <div class="card"><div class="num orange">{n_high}</div><div class="label">HIGH</div></div>
      <div class="card"><div class="num" style="color:var(--orange)">{n_medium}</div><div class="label">MEDIUM</div></div>
      <div class="card"><div class="num cyan">{n_low}</div><div class="label">LOW</div></div>
      <div class="card"><div class="num purple">{n_total}</div><div class="label">TOTAL FINDINGS</div></div>
      <div class="card"><div class="num green">{n_patched}</div><div class="label">PATCHES APPLIED</div></div>
      <div class="card"><div class="num {'green' if fix_rate >= 0.5 else 'orange'}">{fix_rate:.0%}</div><div class="label">FIX RATE</div></div>
      <div class="card"><div class="num cyan">{n_decisions}</div><div class="label">AGENT DECISIONS</div></div>
    </div>

    <!-- Charts -->
    <div class="charts">
      <div class="chart-card">
        <h3>Severity Distribution</h3>
        <canvas id="sevChart" height="200"></canvas>
      </div>
      <div class="chart-card">
        <h3>Risk Score vs Exploit Probability (Top 15)</h3>
        <canvas id="riskChart" height="200"></canvas>
      </div>
    </div>

    <!-- CWE Breakdown Chart -->
    <section>
      <h2>CWE Breakdown</h2>
      <div class="chart-card">
        <canvas id="cweChart" height="100"></canvas>
      </div>
    </section>

    <!-- Findings Table -->
    <section>
      <h2>All Findings — Sorted by Risk</h2>
      <table>
        <thead>
          <tr>
            <th>ID</th><th>Severity</th><th>CWE</th><th>Function</th>
            <th>Line</th><th>Risk Score</th><th>Exploit%</th><th>Strategy</th>
          </tr>
        </thead>
        <tbody>{findings_rows}</tbody>
      </table>
    </section>

    <!-- Patch Results -->
    <section>
      <h2>Patch Results</h2>
      <table>
        <thead>
          <tr><th>Vuln ID</th><th>Strategy</th><th>Status</th><th>Detail</th></tr>
        </thead>
        <tbody>{patch_rows}</tbody>
      </table>
    </section>

    <!-- Verification -->
    <section>
      <h2>Verification (Re-Analysis)</h2>
      <table>
        <thead>
          <tr><th>File</th><th>Before</th><th>After</th><th>Fixed</th><th>Fix Rate</th></tr>
        </thead>
        <tbody>{verify_rows}</tbody>
      </table>
    </section>

    {diff_html}
  </main>

  <footer>
    VAPT Intelligence System v1.0.0 &nbsp;·&nbsp; {n_total} findings &nbsp;·&nbsp; {n_patched} patches &nbsp;·&nbsp; {fix_rate:.1%} fix rate
  </footer>

  <script>
    const C = (id, cfg) => new Chart(document.getElementById(id), cfg);

    // Severity donut
    C('sevChart', {{
      type: 'doughnut',
      data: {{
        labels: ['CRITICAL','HIGH','MEDIUM','LOW'],
        datasets: [{{ data: {sev_data}, backgroundColor: ['#f85149','#e3b341','#d29922','#3fb950'], borderWidth: 0 }}]
      }},
      options: {{ plugins: {{ legend: {{ labels: {{ color: '#8b949e' }} }} }}, cutout: '65%' }}
    }});

    // Risk + exploit bar
    C('riskChart', {{
      type: 'bar',
      data: {{
        labels: {risk_labels},
        datasets: [
          {{ label: 'Risk Score',     data: {risk_data}, backgroundColor: '#f85149aa', borderRadius: 3 }},
          {{ label: 'Exploit Prob',   data: {exp_data},  backgroundColor: '#58a6ffaa', borderRadius: 3 }},
        ]
      }},
      options: {{
        plugins: {{ legend: {{ labels: {{ color: '#8b949e' }} }} }},
        scales: {{
          x: {{ ticks: {{ color: '#8b949e', maxRotation: 45 }}, grid: {{ color: '#21262d' }} }},
          y: {{ ticks: {{ color: '#8b949e' }}, grid: {{ color: '#21262d' }}, max: 1.0 }}
        }}
      }}
    }});

    // CWE bar
    C('cweChart', {{
      type: 'bar',
      data: {{
        labels: {cwe_labels},
        datasets: [{{ label: 'Findings', data: {cwe_values}, backgroundColor: '#bc8cffaa', borderRadius: 3 }}]
      }},
      options: {{
        plugins: {{ legend: {{ display: false }} }},
        scales: {{
          x: {{ ticks: {{ color: '#8b949e' }}, grid: {{ color: '#21262d' }} }},
          y: {{ ticks: {{ color: '#8b949e', stepSize: 1 }}, grid: {{ color: '#21262d' }} }}
        }}
      }}
    }});
  </script>
</body>
</html>"""