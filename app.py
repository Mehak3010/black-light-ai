import os
import re
import json
from dataclasses import dataclass, asdict
from typing import List, Optional
from urllib.parse import urlparse
from flask import Flask, request, send_file, jsonify, abort

OUTPUT_DIR = os.path.join(os.getcwd(), "artifacts")
RAW_SCAN_PATH = os.path.join(os.getcwd(), "scan.jsonl")
UPLOADED_SCAN_PATH = os.path.join(OUTPUT_DIR, "uploaded_scan.jsonl")
RUN_LIVE_SCAN = False

os.makedirs(OUTPUT_DIR, exist_ok=True)

def html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )

def json_write(obj, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

@dataclass
class Finding:
    title: str
    severity: str
    host: str
    evidence: str
    template_id: str
    timestamp: str
    cve_ids: List[str]
    cve_links: List[str]
    cvss: Optional[float]
    confidence: str
    risk_score: float
    notes: str

def parser_agent(scan_path: str, target_host: Optional[str]) -> List[Finding]:
    findings: List[Finding] = []
    if not os.path.isfile(scan_path):
        return findings
    with open(scan_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            host = obj.get("host") or obj.get("matched-at") or ""
            if target_host and host and target_host not in host:
                continue
            info = obj.get("info", {})
            title = info.get("name") or obj.get("template-id") or "Finding"
            severity = str(info.get("severity", "info")).lower()
            evidence = ", ".join(obj.get("extracted-results", [])[:1])
            template_id = obj.get("template-id") or obj.get("template") or ""
            timestamp = obj.get("timestamp") or ""
            findings.append(Finding(
                title=title,
                severity=severity,
                host=host,
                evidence=evidence,
                template_id=template_id,
                timestamp=timestamp,
                cve_ids=[],
                cve_links=[],
                cvss=None,
                confidence="low",
                risk_score=0.0,
                notes=""
            ))
    findings_path = os.path.join(OUTPUT_DIR, "findings.json")
    json_write([asdict(f) for f in findings], findings_path)
    return findings

SEV_BASE = {"info": 0, "low": 2, "medium": 5, "high": 8, "critical": 10}

def enrich_and_score_agent(findings: List[Finding]) -> List[Finding]:
    for f in findings:
        cves = set(re.findall(r"CVE-\d{4}-\d{4,7}", f.title or ""))
        f.cve_ids = sorted(cves)
        f.cve_links = [f"https://nvd.nist.gov/vuln/detail/{c}" for c in f.cve_ids]
        base = SEV_BASE.get(f.severity, 0)
        conf = {"low": 0.7, "medium": 0.85, "high": 1.0}.get(f.confidence, 0.7)
        bonus = 1.0 if f.cve_ids else 0.0
        f.risk_score = round(min(10.0, base * conf + bonus), 2)
    scored_path = os.path.join(OUTPUT_DIR, "findings_scored.json")
    json_write([asdict(x) for x in findings], scored_path)
    return findings

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Web Application Security Assessment Report - {{SITE_NAME}}</title>
  <style>
    :root{ --ink:#0f172a; --muted:#475569; --line:#e2e8f0; --soft:#f8fafc;
      --critical:#b91c1c; --high:#c2410c; --medium:#b45309; --low:#0f766e; --info:#1d4ed8; }
    *{box-sizing:border-box}
    body{ margin:0; padding:0; font-family:system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; color:var(--ink); background:#fff; line-height:1.55; }
    .page{ width:210mm; min-height:297mm; padding:18mm 16mm; margin:0 auto; border-bottom:10px solid #fff; position:relative; }
    .page-break{ page-break-after: always; break-after: page; }
    header.report-header{ display:flex; justify-content:space-between; align-items:flex-start; border-bottom:2px solid var(--ink); padding-bottom:10px; margin-bottom:14px; }
    .title h1{font-size:22px; margin:0 0 6px 0; letter-spacing:.2px;}
    .title p{margin:0; color:var(--muted); font-size:13px;}
    .doc-meta{ font-size:12.5px; color:var(--muted); text-align:right; }
    .doc-meta div{margin-bottom:4px}
    .badge{ display:inline-block; padding:2px 8px; border-radius:12px; font-size:12px; color:#fff; }
    .b-critical{background:var(--critical)} .b-high{background:var(--high)} .b-medium{background:var(--medium)} .b-low{background:var(--low)} .b-info{background:var(--info)}
    .card{ border:1px solid var(--line); border-radius:8px; padding:10px 12px; margin:10px 0; background:#fff; }
    .grid-2{ display:grid; grid-template-columns:1fr 1fr; gap:12px; }
    .finding{ border:1px solid var(--line); border-radius:8px; padding:12px; margin:10px 0; }
    .finding-header{ display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; }
    .finding-title{ font-weight:600; }
    .poc{ background:var(--soft); border:1px dashed var(--line); padding:8px; border-radius:6px; white-space:pre-wrap; }
    .page-footer{ display:flex; justify-content:space-between; font-size:12px; color:var(--muted); border-top:1px dashed var(--line); padding-top:6px; }
  </style>
  </head>
<body>
  <section class="page page-break">
    <header class="report-header">
      <div class="title">
        <h1>Web Application Security Assessment Report — {{SITE_NAME}}</h1>
        <p>Executive Summary & Scope</p>
      </div>
      <div class="doc-meta">
        <div><strong>Date:</strong> {{DATE}}</div>
        <div><strong>Author:</strong> {{AUTHOR}}</div>
        <div><strong>Version:</strong> {{VERSION}}</div>
      </div>
    </header>
    <h2>1. Executive Summary (Bottom Line)</h2>
    {{EXEC_SUMMARY_HTML}}
    <div class="card">
      <p style="margin-top:0"><strong>Overall Security Status:</strong> <span class="badge {{STATUS_BADGE_CLASS}}">{{STATUS_LABEL}}</span></p>
      <p class="muted" style="margin-bottom:0">{{STATUS_LINE}}</p>
    </div>
    {{BUSINESS_IMPACT_UL}}
    <h2>2. Scorecard / Visual Summary</h2>
    {{SCORECARD_TABLE}}
    <h2>3. Scope & Methodology</h2>
    <div class="grid-2">
      <div class="card"><h3 style="margin-top:0">Scope</h3>{{SCOPE_HTML}}</div>
      <div class="card"><h3 style="margin-top:0">Methodology & Tools</h3>{{METHODOLOGY_UL}}</div>
    </div>
    <footer class="page-footer"><div>{{SITE_NAME}} Security Assessment</div><div>Page 1 of 3</div></footer>
  </section>
  <section class="page page-break">
    <header class="report-header">
      <div class="title"><h1>Detailed Technical Findings</h1><p>Critical & High Risk Issues</p></div>
      <div class="doc-meta"><div><strong>Target:</strong> {{TARGET_URL}}</div><div><strong>Version:</strong> {{VERSION}}</div></div>
    </header>
    {{TOP_FINDINGS_HTML}}
    <footer class="page-footer"><div>{{SITE_NAME}} Security Assessment</div><div>Page 2 of 3</div></footer>
  </section>
  <section class="page">
    <header class="report-header">
      <div class="title"><h1>Remediations & Best Practices</h1><p>Fixes and Guidance</p></div>
      <div class="doc-meta"><div><strong>Target:</strong> {{TARGET_URL}}</div><div><strong>Version:</strong> {{VERSION}}</div></div>
    </header>
    <h2>Recommended Fixes</h2>
    {{REMEDIATION_HTML}}
    <h2>Best Practices</h2>
    {{BEST_PRACTICES_UL}}
    <h2>Conclusion</h2>
    {{CONCLUSION_HTML}}
    <footer class="page-footer"><div>{{SITE_NAME}} Security Assessment</div><div>Page 3 of 3</div></footer>
  </section>
</body>
</html>
"""

def reporter_agent(findings: List[Finding], site_name: str, target_url: str) -> str:
    sev_counts = {"critical":0, "high":0, "medium":0, "low":0, "info":0}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    top = sorted(findings, key=lambda x: x.risk_score, reverse=True)[:5]
    status_class = "b-info"
    status_label = "Info"
    if sev_counts["critical"] or sev_counts["high"]:
        status_class, status_label = "b-high", "High Risk"
    elif sev_counts["medium"]:
        status_class, status_label = "b-medium", "Medium Risk"
    elif sev_counts["low"]:
        status_class, status_label = "b-low", "Low Risk"
    status_line = (
        f"The assessment identified <strong>{sev_counts['critical']} Critical</strong>, "
        f"<strong>{sev_counts['high']} High</strong>, "
        f"<strong>{sev_counts['medium']} Medium</strong>, and "
        f"<strong>{sev_counts['low']} Low</strong> issues."
    )
    exec_summary_html = (
        "<p>This report summarizes the security posture based on available scan data. "
        "Top risks are highlighted for rapid remediation.</p>"
    )
    business_impact_ul = (
        "<ul><li>Reputation risk due to potential exposure.</li>"
        "<li>Compliance risk depending on data involved.</li>"
        "<li>Operational risk from possible downtime.</li></ul>"
    )
    scorecard_table = (
        "<table style=\"width:100%; border-collapse:collapse\">"
        "<thead><tr><th>Severity</th><th>Count</th><th>Notes</th></tr></thead><tbody>"
        f"<tr><td>Critical</td><td>{sev_counts['critical']}</td><td>Immediate action required.</td></tr>"
        f"<tr><td>High</td><td>{sev_counts['high']}</td><td>Prioritize remediation.</td></tr>"
        f"<tr><td>Medium</td><td>{sev_counts['medium']}</td><td>Address in planned sprints.</td></tr>"
        f"<tr><td>Low</td><td>{sev_counts['low']}</td><td>Monitor and harden.</td></tr>"
        f"<tr><td>Info</td><td>{sev_counts['info']}</td><td>Informational observations.</td></tr>"
        "</tbody></table>"
    )
    scope_html = (
        f"<p><strong>Target URL:</strong> {html_escape(target_url)}</p>"
        "<p><strong>Testing Period:</strong> Nov 2025</p>"
        "<p><strong>Environment:</strong> Production (non-destructive tests only)</p>"
        "<p><strong>Out of Scope:</strong> DoS/Stress testing, 3rd-party vendor systems</p>"
    )
    methodology_ul = (
        "<ul><li>Automated discovery and scan (offline sample)</li>"
        "<li>Manual validation where applicable</li>"
        "<li>OWASP Testing Guide aligned checks</li>"
        "<li>Risk rated by Likelihood × Impact</li></ul>"
    )
    blocks = []
    for i, f in enumerate(top, 1):
        sev = f.severity.lower()
        badge = f"b-{sev if sev in ('critical','high','medium','low','info') else 'info'}"
        blocks.append(
            f"<div class=\"finding\"><div class=\"finding-header\"><div class=\"finding-title\">{i}) {html_escape(f.title)}</div>"
            f"<div class=\"badge {badge}\">{html_escape(sev.upper())}</div></div>"
            f"<div class=\"finding-meta\">Affected Host: <code>{html_escape(f.host)}</code> • Template: <code>{html_escape(f.template_id)}</code></div>"
            f"<h3>Description</h3><p>{html_escape(f.notes or 'Automated detection based on available templates.')}</p>"
            f"<h3>Evidence / Proof of Concept (PoC)</h3><div class=\"poc\"><code>{html_escape(f.evidence or 'N/A')}</code></div>"
            f"<h3>Impact</h3><ul><li>Potential risk depending on exploitability.</li></ul></div>"
        )
    top_findings_html = "\n".join(blocks) if blocks else "<p>No high-priority findings available.</p>"
    rem_blocks = []
    for i, f in enumerate(top, 1):
        sev = f.severity.lower()
        badge = f"b-{sev if sev in ('critical','high','medium','low','info') else 'info'}"
        rem_blocks.append(
            f"<div class=\"finding\"><div class=\"finding-header\"><div class=\"finding-title\">Recommendation for Finding {i}: {html_escape(f.title)}</div>"
            f"<div class=\"badge {badge}\">{html_escape(sev.upper())}</div></div>"
            "<ul><li>Patch or update affected component/dependency.</li>"
            "<li>Validate and sanitize inputs.</li>"
            "<li>Add monitoring and regression tests.</li></ul></div>"
        )
    remediation_html = "\n".join(rem_blocks)
    best_practices_ul = (
        "<ul><li>Enforce HTTPS site-wide and use HSTS.</li>"
        "<li>Update server/framework dependencies regularly.</li>"
        "<li>Disable verbose errors in production.</li>"
        "<li>Set secure cookies.</li>"
        "<li>Centralize logging and alerting.</li></ul>"
    )
    conclusion_html = (
        f"<p>Applying the remediations in this report will significantly improve the security posture of <strong>{html_escape(site_name)}</strong>. A re-test is recommended after fixes are deployed.</p>"
    )
    html_out = HTML_TEMPLATE
    replacements = {
        "{{SITE_NAME}}": html_escape(site_name),
        "{{DATE}}": "01 Dec 2025",
        "{{AUTHOR}}": "Team TRIPOD",
        "{{VERSION}}": "v1.0",
        "{{TARGET_URL}}": html_escape(target_url),
        "{{EXEC_SUMMARY_HTML}}": exec_summary_html,
        "{{STATUS_BADGE_CLASS}}": status_class,
        "{{STATUS_LABEL}}": status_label,
        "{{STATUS_LINE}}": status_line,
        "{{BUSINESS_IMPACT_UL}}": business_impact_ul,
        "{{SCORECARD_TABLE}}": scorecard_table,
        "{{SCOPE_HTML}}": scope_html,
        "{{METHODOLOGY_UL}}": methodology_ul,
        "{{TOP_FINDINGS_HTML}}": top_findings_html,
        "{{REMEDIATION_HTML}}": remediation_html,
        "{{BEST_PRACTICES_UL}}": best_practices_ul,
        "{{CONCLUSION_HTML}}": conclusion_html,
    }
    for k, v in replacements.items():
        html_out = html_out.replace(k, v)
    report_path = os.path.join(OUTPUT_DIR, "report.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_out)
    return report_path

def export_pdf(report_html_path: str) -> Optional[str]:
    pdf_path = os.path.join(OUTPUT_DIR, "report.pdf")
    try:
        from weasyprint import HTML
        HTML(filename=report_html_path).write_pdf(pdf_path)
        return pdf_path
    except Exception:
        return None

app = Flask(__name__)

def latest_artifact() -> Optional[str]:
    pdf = os.path.join(OUTPUT_DIR, "report.pdf")
    html = os.path.join(OUTPUT_DIR, "report.html")
    if os.path.isfile(pdf):
        return pdf
    if os.path.isfile(html):
        return html
    return None

@app.get("/")
def root():
    doc = os.path.join(os.getcwd(), "docs", "index.html")
    if os.path.isfile(doc):
        return send_file(doc, mimetype="text/html")
    return jsonify({"status": "ok"})

@app.get("/api/generate-report")
def generate_report():
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
    except Exception:
        host = ""
    site_name = host or "ExampleSite"
    scan_path = UPLOADED_SCAN_PATH if os.path.isfile(UPLOADED_SCAN_PATH) else RAW_SCAN_PATH
    findings = parser_agent(scan_path, host if host else None)
    if not findings:
        findings = parser_agent(scan_path, None)
    findings = enrich_and_score_agent(findings)
    report_html = reporter_agent(findings, site_name=site_name, target_url=url if url else "https://example.com")
    pdf_path = export_pdf(report_html)
    path = pdf_path or report_html
    if not os.path.isfile(path):
        abort(500)
    if path.endswith(".pdf"):
        return send_file(path, mimetype="application/pdf", as_attachment=True, download_name="report.pdf")
    else:
        return send_file(path, mimetype="text/html", as_attachment=True, download_name="report.html")

@app.post("/api/upload")
def upload_dataset():
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "file is required"}), 400
    f.save(UPLOADED_SCAN_PATH)
    return jsonify({"status": "ok"})

@app.get("/api/latest")
def get_latest():
    path = latest_artifact()
    if not path:
        return jsonify({"error": "no artifact"}), 404
    if path.endswith(".pdf"):
        return send_file(path, mimetype="application/pdf", as_attachment=True, download_name="report.pdf")
    else:
        return send_file(path, mimetype="text/html", as_attachment=True, download_name="report.html")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
