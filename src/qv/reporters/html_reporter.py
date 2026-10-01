"""Self-contained interactive HTML reporter for qv diagnostic scan results."""

from __future__ import annotations

import html

from qv.core.models import ScanResult, Severity


class HtmlReporter:
    """Renders scan results as a standalone, responsive, interactive HTML dashboard."""

    def render(self, result: ScanResult) -> str:
        score = result.health_score
        score_color = "#10b981" if score >= 80 else ("#f59e0b" if score >= 50 else "#ef4444")
        error_count = result.error_count
        warning_count = result.warning_count
        passed_count = result.checks_passed

        # Circular gauge SVG calculations
        circumference = 282.74  # 2 * PI * 45
        dashoffset = circumference - (score / 100.0) * circumference

        # Build diagnostic cards HTML
        cards_html: list[str] = []
        for idx, d in enumerate(result.diagnostics, 1):
            sev_class = "severity-error" if d.severity == Severity.ERROR else "severity-warning"
            sev_badge = "ERROR" if d.severity == Severity.ERROR else "WARNING"
            sev_icon = "🔴" if d.severity == Severity.ERROR else "🟡"

            evidence_items: list[str] = []
            for ev in d.evidence:
                ev_source_str = (
                    f" <span class='ev-source'>({html.escape(ev.source)})</span>"
                    if ev.source
                    else ""
                )
                evidence_items.append(
                    f"<li><span class='ev-fact'>{html.escape(ev.fact)}</span>{ev_source_str}</li>"
                )
            evidence_html = "".join(evidence_items)

            suggestion_items: list[str] = []
            for sug in d.suggestions:
                cmd_block = ""
                if sug.command:
                    cmd_block = f"<div class='code-block'><pre><code>{html.escape(sug.command)}</code></pre><button class='copy-btn' onclick='copyText(this, `{html.escape(sug.command, quote=True)}`)'>Copy</button></div>"
                elif sug.code_snippet:
                    cmd_block = f"<div class='code-block'><pre><code>{html.escape(sug.code_snippet)}</code></pre><button class='copy-btn' onclick='copyText(this, `{html.escape(sug.code_snippet, quote=True)}`)'>Copy</button></div>"
                suggestion_items.append(
                    f"<div class='sug-item'><p class='sug-desc'>👉 {html.escape(sug.description)}</p>{cmd_block}</div>"
                )
            suggestions_html = "".join(suggestion_items)

            loc_str = ""
            if d.file:
                loc_str = f"<span class='diag-loc'>📄 {html.escape(d.file)}{f':{d.line}' if d.line else ''}</span>"

            doc_link = ""
            if d.doc_url:
                doc_link = f"<a href='{html.escape(d.doc_url)}' target='_blank' class='doc-link'>Rules Doc ↗</a>"

            cards_html.append(f"""
            <div class="diag-card {sev_class}" data-severity="{d.severity.value}" data-rule="{html.escape(d.id)}">
                <div class="diag-header" onclick="toggleAccordion('diag-{idx}')">
                    <div class="diag-header-left">
                        <span class="sev-badge {sev_class}">{sev_icon} {sev_badge}</span>
                        <span class="rule-id">{html.escape(d.id)}</span>
                        <span class="diag-title">{html.escape(d.title)}</span>
                    </div>
                    <div class="diag-header-right">
                        {loc_str}
                        <span class="accordion-arrow" id="arrow-diag-{idx}">▼</span>
                    </div>
                </div>
                <div class="diag-body" id="diag-{idx}">
                    <p class="diag-message">{html.escape(d.message)}</p>
                    {f'<div class="section-block"><h4>Evidence</h4><ul class="evidence-list">{evidence_html}</ul></div>' if evidence_items else ""}
                    {f'<div class="section-block"><h4>Remediation</h4>{suggestions_html}</div>' if suggestion_items else ""}
                    {f'<div class="diag-footer">{doc_link}</div>' if doc_link else ""}
                </div>
            </div>
            """)

        all_cards_html = (
            "\n".join(cards_html)
            if cards_html
            else "<div class='empty-state'>🎉 No issues found! Project is fully healthy.</div>"
        )

        # Build Root Causes HTML
        rc_cards: list[str] = []
        for rc in result.root_causes:
            rc_cards.append(f"""
            <div class="rc-card">
                <div class="rc-header">
                    <span class="rc-id">{html.escape(rc.id)}</span>
                    <span class="rc-title">{html.escape(rc.title)}</span>
                </div>
                <p class="rc-summary">{html.escape(rc.summary)}</p>
                <div class="rc-recommendation"><strong>Recommendation:</strong> {html.escape(rc.recommendation.description)}</div>
            </div>
            """)
        rc_section_html = (
            f"""
        <div class="root-causes-section">
            <h3 class="section-title">🧠 Correlated Root Causes</h3>
            <div class="rc-grid">{"".join(rc_cards)}</div>
        </div>
        """
            if rc_cards
            else ""
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>qv Health Report - {html.escape(result.project_name)}</title>
<style>
:root {{
    --bg: #0f172a;
    --card-bg: #1e293b;
    --card-border: #334155;
    --text-main: #f8fafc;
    --text-muted: #94a3b8;
    --accent: #38bdf8;
    --error: #ef4444;
    --error-bg: rgba(239, 68, 68, 0.12);
    --warning: #f59e0b;
    --warning-bg: rgba(245, 158, 11, 0.12);
    --success: #10b981;
    --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}}

body.light {{
    --bg: #f8fafc;
    --card-bg: #ffffff;
    --card-border: #e2e8f0;
    --text-main: #0f172a;
    --text-muted: #64748b;
    --accent: #0284c7;
    --error: #dc2626;
    --error-bg: rgba(220, 38, 38, 0.08);
    --warning: #d97706;
    --warning-bg: rgba(217, 119, 6, 0.08);
    --success: #059669;
}}

* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: var(--font);
    background-color: var(--bg);
    color: var(--text-main);
    padding: 2rem;
    transition: background 0.2s ease, color 0.2s ease;
}}

.container {{ max-width: 1200px; margin: 0 auto; }}

header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 2rem;
    border-bottom: 1px solid var(--card-border);
    margin-bottom: 2rem;
}}

.header-title h1 {{ font-size: 1.8rem; font-weight: 700; display: flex; align-items: center; gap: 0.5rem; }}
.header-title .tagline {{ color: var(--text-muted); font-size: 0.95rem; margin-top: 0.3rem; }}

.theme-toggle {{
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    color: var(--text-main);
    padding: 0.5rem 1rem;
    border-radius: 8px;
    cursor: pointer;
    font-weight: 600;
}}

.overview-grid {{
    display: grid;
    grid-template-columns: 280px 1fr;
    gap: 1.5rem;
    margin-bottom: 2.5rem;
}}

@media (max-width: 850px) {{
    .overview-grid {{ grid-template-columns: 1fr; }}
}}

.score-card {{
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 12px;
    padding: 2rem;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
}}

.circle-chart {{ width: 140px; height: 140px; transform: rotate(-90deg); }}
.circle-bg {{ fill: none; stroke: var(--card-border); stroke-width: 10; }}
.circle-progress {{
    fill: none;
    stroke: {score_color};
    stroke-width: 10;
    stroke-linecap: round;
    stroke-dasharray: 282.74;
    stroke-dashoffset: {dashoffset:.2f};
    transition: stroke-dashoffset 0.8s ease;
}}
.score-text {{ font-size: 2.2rem; font-weight: 800; color: {score_color}; margin-top: -95px; margin-bottom: 45px; }}

.stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1rem;
}}

.stat-box {{
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 12px;
    padding: 1.25rem;
    display: flex;
    flex-direction: column;
    justify-content: center;
}}
.stat-label {{ color: var(--text-muted); font-size: 0.85rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }}
.stat-val {{ font-size: 1.6rem; font-weight: 700; margin-top: 0.4rem; }}
.stat-val.error {{ color: var(--error); }}
.stat-val.warning {{ color: var(--warning); }}
.stat-val.success {{ color: var(--success); }}

.controls-bar {{
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    flex-wrap: wrap;
    margin-bottom: 1.5rem;
}}

.filter-group {{ display: flex; gap: 0.5rem; }}
.filter-btn {{
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    color: var(--text-muted);
    padding: 0.5rem 1rem;
    border-radius: 8px;
    cursor: pointer;
    font-size: 0.9rem;
    font-weight: 600;
}}
.filter-btn.active {{
    background: var(--accent);
    color: #fff;
    border-color: var(--accent);
}}

.search-input {{
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    color: var(--text-main);
    padding: 0.5rem 1rem;
    border-radius: 8px;
    min-width: 260px;
    font-size: 0.9rem;
}}
.search-input:focus {{ outline: 2px solid var(--accent); }}

.diag-card {{
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 10px;
    margin-bottom: 1rem;
    overflow: hidden;
    transition: transform 0.15s ease, border-color 0.15s ease;
}}
.diag-card.severity-error {{ border-left: 4px solid var(--error); }}
.diag-card.severity-warning {{ border-left: 4px solid var(--warning); }}

.diag-header {{
    padding: 1.1rem 1.25rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    cursor: pointer;
    user-select: none;
}}
.diag-header-left {{ display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }}
.diag-header-right {{ display: flex; align-items: center; gap: 0.75rem; }}

.sev-badge {{
    font-size: 0.75rem;
    font-weight: 700;
    padding: 0.2rem 0.5rem;
    border-radius: 6px;
    letter-spacing: 0.5px;
}}
.sev-badge.severity-error {{ background: var(--error-bg); color: var(--error); }}
.sev-badge.severity-warning {{ background: var(--warning-bg); color: var(--warning); }}

.rule-id {{
    background: var(--card-border);
    color: var(--text-muted);
    font-family: monospace;
    font-size: 0.85rem;
    font-weight: 700;
    padding: 0.2rem 0.5rem;
    border-radius: 6px;
}}
.diag-title {{ font-weight: 600; font-size: 1rem; }}
.diag-loc {{ color: var(--text-muted); font-size: 0.85rem; font-family: monospace; }}
.accordion-arrow {{ color: var(--text-muted); font-size: 0.8rem; transition: transform 0.2s ease; }}

.diag-body {{
    padding: 0 1.25rem 1.25rem 1.25rem;
    display: none;
    border-top: 1px solid var(--card-border);
    margin-top: 0.5rem;
    padding-top: 1rem;
}}
.diag-body.open {{ display: block; }}

.diag-message {{ font-size: 0.95rem; line-height: 1.5; margin-bottom: 1rem; }}
.section-block {{ margin-top: 1rem; }}
.section-block h4 {{ font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 0.5rem; }}

.evidence-list {{ list-style-type: none; }}
.evidence-list li {{ padding: 0.3rem 0; font-size: 0.9rem; }}
.ev-fact {{ font-weight: 600; }}
.ev-source {{ color: var(--text-muted); font-size: 0.85rem; }}

.sug-item {{ background: var(--bg); border: 1px solid var(--card-border); border-radius: 8px; padding: 0.85rem; margin-top: 0.5rem; }}
.sug-desc {{ font-size: 0.9rem; font-weight: 500; margin-bottom: 0.4rem; }}

.code-block {{
    background: #000;
    color: #4ade80;
    font-family: monospace;
    padding: 0.6rem 0.85rem;
    border-radius: 6px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.85rem;
    overflow-x: auto;
}}
.copy-btn {{
    background: #334155;
    color: #fff;
    border: none;
    padding: 0.25rem 0.6rem;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.75rem;
    font-weight: 600;
}}
.copy-btn:hover {{ background: var(--accent); }}

.diag-footer {{ margin-top: 1rem; display: flex; justify-content: flex-end; }}
.doc-link {{ color: var(--accent); text-decoration: none; font-size: 0.85rem; font-weight: 600; }}
.doc-link:hover {{ text-decoration: underline; }}

.root-causes-section {{ margin-top: 2.5rem; margin-bottom: 2rem; }}
.section-title {{ font-size: 1.25rem; font-weight: 700; margin-bottom: 1rem; }}
.rc-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1rem; }}
.rc-card {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 10px; padding: 1.25rem; }}
.rc-header {{ display: flex; gap: 0.5rem; align-items: center; margin-bottom: 0.5rem; }}
.rc-id {{ background: var(--accent); color: #fff; font-size: 0.75rem; font-weight: 700; padding: 0.15rem 0.45rem; border-radius: 4px; }}
.rc-title {{ font-weight: 700; font-size: 0.95rem; }}
.rc-summary {{ font-size: 0.9rem; color: var(--text-muted); margin-bottom: 0.75rem; }}
.rc-recommendation {{ font-size: 0.85rem; background: var(--bg); padding: 0.5rem 0.75rem; border-radius: 6px; }}

.empty-state {{
    background: var(--card-bg);
    border: 1px dashed var(--card-border);
    padding: 3rem;
    text-align: center;
    border-radius: 12px;
    color: var(--text-muted);
    font-size: 1.1rem;
}}
</style>
</head>
<body>
<div class="container">
    <header>
        <div class="header-title">
            <h1>🔍 qv Health Report</h1>
            <div class="tagline">Project: <strong>{html.escape(result.project_name)}</strong> • Path: <code>{html.escape(result.project_path)}</code></div>
        </div>
        <button class="theme-toggle" onclick="toggleTheme()">🌓 Toggle Theme</button>
    </header>

    <div class="overview-grid">
        <div class="score-card">
            <svg class="circle-chart" viewBox="0 0 100 100">
                <circle class="circle-bg" cx="50" cy="50" r="45" />
                <circle class="circle-progress" cx="50" cy="50" r="45" />
            </svg>
            <div class="score-text">{score}</div>
            <p style="color: var(--text-muted); font-size: 0.9rem; font-weight: 600;">HEALTH SCORE / 100</p>
        </div>

        <div class="stats-grid">
            <div class="stat-box">
                <span class="stat-label">Blocking Errors</span>
                <span class="stat-val error">{error_count}</span>
            </div>
            <div class="stat-box">
                <span class="stat-label">Warnings</span>
                <span class="stat-val warning">{warning_count}</span>
            </div>
            <div class="stat-box">
                <span class="stat-label">Checks Evaluated</span>
                <span class="stat-val success">{passed_count}</span>
            </div>
            <div class="stat-box">
                <span class="stat-label">Python Runtime</span>
                <span class="stat-val" style="font-size: 1.25rem;">{html.escape(result.python_version)}</span>
            </div>
            <div class="stat-box">
                <span class="stat-label">Package Manager</span>
                <span class="stat-val" style="font-size: 1.25rem;">{html.escape(result.package_manager.upper())}</span>
            </div>
        </div>
    </div>

    {rc_section_html}

    <div class="controls-bar">
        <div class="filter-group">
            <button class="filter-btn active" onclick="setFilter('all', this)">All ({len(result.diagnostics)})</button>
            <button class="filter-btn" onclick="setFilter('error', this)">Errors ({error_count})</button>
            <button class="filter-btn" onclick="setFilter('warning', this)">Warnings ({warning_count})</button>
        </div>
        <input type="text" id="search" class="search-input" placeholder="Search diagnostics..." onkeyup="filterDiagnostics()" />
    </div>

    <div id="diagnostics-container">
        {all_cards_html}
    </div>
</div>

<script>
function toggleAccordion(id) {{
    const body = document.getElementById(id);
    const arrow = document.getElementById('arrow-' + id);
    if (body.classList.contains('open')) {{
        body.classList.remove('open');
        arrow.style.transform = 'rotate(0deg)';
    }} else {{
        body.classList.add('open');
        arrow.style.transform = 'rotate(180deg)';
    }}
}}

function toggleTheme() {{
    document.body.classList.toggle('light');
    localStorage.setItem('qv-theme', document.body.classList.contains('light') ? 'light' : 'dark');
}}

if (localStorage.getItem('qv-theme') === 'light') {{
    document.body.classList.add('light');
}}

let currentFilter = 'all';

function setFilter(filter, btn) {{
    currentFilter = filter;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    filterDiagnostics();
}}

function filterDiagnostics() {{
    const query = document.getElementById('search').value.toLowerCase();
    const cards = document.querySelectorAll('.diag-card');

    cards.forEach(card => {{
        const severity = card.getAttribute('data-severity');
        const text = card.innerText.toLowerCase();
        const matchesFilter = currentFilter === 'all' || severity === currentFilter;
        const matchesQuery = !query || text.includes(query);

        if (matchesFilter && matchesQuery) {{
            card.style.display = 'block';
        }} else {{
            card.style.display = 'none';
        }}
    }});
}}

function copyText(btn, text) {{
    navigator.clipboard.writeText(text).then(() => {{
        const orig = btn.innerText;
        btn.innerText = 'Copied!';
        setTimeout(() => btn.innerText = orig, 1500);
    }});
}}
</script>
</body>
</html>
"""
