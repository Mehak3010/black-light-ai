import os
import re
import json
from dataclasses import dataclass, asdict
from typing import List, Optional
from urllib.parse import urlparse
from flask import Flask, request, send_file, jsonify, render_template
import subprocess
import shutil
import tempfile

OUTPUT_DIR = os.path.join(os.getcwd(), "artifacts")
RAW_SCAN_PATH = os.path.join(os.getcwd(), "scan.jsonl")
UPLOADED_SCAN_PATH = os.path.join(OUTPUT_DIR, "uploaded_scan.jsonl")
BIN_DIR = os.path.join(os.getcwd(), "bin")
NUCLEI_TEMPLATES_DIR = os.path.join(os.getcwd(), "nuclei-templates")

os.makedirs(OUTPUT_DIR, exist_ok=True)

# Escape helper
def html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )

# Write JSON file
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
    findings = []
    if not os.path.isfile(scan_path):
        return findings

    with open(scan_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line.strip())
            except:
                continue

            host = obj.get("host") or obj.get("matched-at") or ""
            if target_host and target_host not in host:
                continue

            info = obj.get("info", {})
            findings.append(Finding(
                title=info.get("name") or obj.get("template-id") or "Finding",
                severity=str(info.get("severity", "info")).lower(),
                host=host,
                evidence=", ".join(obj.get("extracted-results", [])[:1]),
                template_id=obj.get("template-id") or obj.get("template") or "",
                timestamp=obj.get("timestamp") or "",
                cve_ids=[], cve_links=[], cvss=None,
                confidence="low", risk_score=0.0, notes=""
            ))

    json_write([asdict(f) for f in findings], os.path.join(OUTPUT_DIR, "findings.json"))
    return findings

SEV_BASE = {"info": 0, "low": 2, "medium": 5, "high": 8, "critical": 10}

def enrich_and_score_agent(findings: List[Finding]) -> List[Finding]:
    for f in findings:
        cves = set(re.findall(r"CVE-\d{4}-\d{4,7}", f.title))
        f.cve_ids = sorted(cves)
        f.cve_links = [f"https://nvd.nist.gov/vuln/detail/{c}" for c in f.cve_ids]
        f.risk_score = round(min(10.0, SEV_BASE.get(f.severity, 0) + (1.0 if f.cve_ids else 0)), 2)

    json_write([asdict(x) for x in findings], os.path.join(OUTPUT_DIR, "findings_scored.json"))
    return findings

# 🟩 OLD REPORT STYLE (Simple Table — Report 1)
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
    html_template = """
<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"UTF-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>
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
    .finding{ border:1px solid var(--line); border-radius:14px; padding:12px; margin:10px 0; }
    .finding-header{ display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; }
    .finding-title{ font-weight:600; }
    .poc{ background:var(--soft); border:1px dashed var(--line); padding:8px; border-radius:6px; white-space:pre-wrap; }
    .page-footer{ display:flex; justify-content:space-between; font-size:12px; color:var(--muted); border-top:1px dashed var(--line); padding-top:6px; }
    table{ width:100%; border-collapse:collapse }
    th, td{ border:1px solid var(--line); padding:8px 9px; vertical-align:top }
    th{ background:#f1f5f9; text-align:left }
  </style>
  </head>
<body>
  <section class=\"page page-break\">
    <header class=\"report-header\">
      <div class=\"title\">
        <h1>Web Application Security Assessment Report — {{SITE_NAME}}</h1>
        <p>Executive Summary & Scope</p>
      </div>
      <div class=\"doc-meta\">
        <div><strong>Date:</strong> {{DATE}}</div>
        <div><strong>Author:</strong> {{AUTHOR}}</div>
        <div><strong>Version:</strong> {{VERSION}}</div>
      </div>
    </header>
    <h2>1. Executive Summary (Bottom Line)</h2>
    {{EXEC_SUMMARY_HTML}}
    <div class=\"card\">
      <p style=\"margin-top:0\"><strong>Overall Security Status:</strong> <span class=\"badge {{STATUS_BADGE_CLASS}}\">{{STATUS_LABEL}}</span></p>
      <p class=\"muted\" style=\"margin-bottom:0\">{{STATUS_LINE}}</p>
    </div>
    {{BUSINESS_IMPACT_UL}}
    <h2>2. Scorecard / Visual Summary</h2>
    {{SCORECARD_TABLE}}
    <h2>3. Scope & Methodology</h2>
    <div class=\"grid-2\">
      <div class=\"card\"><h3 style=\"margin-top:0\">Scope</h3>{{SCOPE_HTML}}</div>
      <div class=\"card\"><h3 style=\"margin-top:0\">Methodology & Tools</h3>{{METHODOLOGY_UL}}</div>
    </div>
    <footer class=\"page-footer\"><div>{{SITE_NAME}} Security Assessment</div><div>Page 1 of 3</div></footer>
  </section>
  <section class=\"page page-break\">
    <header class=\"report-header\">
      <div class=\"title\"><h1>Detailed Technical Findings</h1><p>Critical & High Risk Issues</p></div>
      <div class=\"doc-meta\"><div><strong>Target:</strong> {{TARGET_URL}}</div><div><strong>Version:</strong> {{VERSION}}</div></div>
    </header>
    {{TOP_FINDINGS_HTML}}
    <footer class=\"page-footer\"><div>{{SITE_NAME}} Security Assessment</div><div>Page 2 of 3</div></footer>
  </section>
  <section class=\"page\">
    <header class=\"report-header\">
      <div class=\"title\"><h1>Remediations & Best Practices</h1><p>Fixes and Guidance</p></div>
      <div class=\"doc-meta\"><div><strong>Target:</strong> {{TARGET_URL}}</div><div><strong>Version:</strong> {{VERSION}}</div></div>
    </header>
    <h2>Recommended Fixes</h2>
    {{REMEDIATION_HTML}}
    <h2>Best Practices</h2>
    {{BEST_PRACTICES_UL}}
    <h2>Conclusion</h2>
    {{CONCLUSION_HTML}}
    <footer class=\"page-footer\"><div>{{SITE_NAME}} Security Assessment</div><div>Page 3 of 3</div></footer>
  </section>
</body>
</html>
"""
    html_out = html_template
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


app = Flask(__name__, template_folder="templates")

@app.get("/")
def root():
    return render_template("index.html")

def discover_assets(host: str) -> List[str]:
    path = shutil.which("amass")
    if not path:
        local = os.path.join(BIN_DIR, "amass.exe")
        if os.path.isfile(local):
            path = local
    if not path:
        return [host]
    try:
        out = subprocess.run([path, "enum", "-d", host, "-silent", "-passive"], capture_output=True, text=True, timeout=180)
        lines = [x.strip() for x in out.stdout.splitlines() if x.strip()]
        uniq = list({*lines, host})
        if len(uniq) > 50:
            uniq = uniq[:50]
        return uniq
    except:
        return [host]

def run_nuclei(assets: List[str]) -> Optional[str]:
    path = shutil.which("nuclei")
    if not path:
        local = os.path.join(BIN_DIR, "nuclei.exe")
        if os.path.isfile(local):
            path = local
    if not path:
        return None
    fd, p = tempfile.mkstemp(text=True)
    try:
        with open(fd, "w") as f:
            f.write("\n".join(assets))
        out_path = os.path.join(OUTPUT_DIR, "live_scan.jsonl")
        try:
            cmd = [path, "-l", p, "-jsonl", "-o", out_path, "-silent", "-stats", "-rl", "75", "-c", "50", "-timeout", "10s", "-retries", "1"]
            if os.path.isdir(NUCLEI_TEMPLATES_DIR):
                cmd.extend(["-t", NUCLEI_TEMPLATES_DIR])
            subprocess.run(cmd, check=False)
        except:
            return None
        return out_path if os.path.isfile(out_path) else None
    finally:
        try:
            os.remove(p)
        except:
            pass

def load_kaggle_ns(host: str):
    nb_path = os.path.join(os.getcwd(), "BlackLightAI.ipynb")
    if not os.path.isfile(nb_path):
        return None
    try:
        with open(nb_path, "r", encoding="utf-8") as f:
            nb = json.load(f)
        cells = nb.get("cells", [])
        selected = []
        blocklist = (
            "apt-get", "wget ", "/usr/local/go", "go install",
            "rm -rf ", "git clone", "IFrame(", "if __name__ == \"__main__\""
        )
        for c in cells:
            if c.get("cell_type") != "code":
                continue
            src = c.get("source", "")
            if not isinstance(src, str):
                src = "".join(src)
            if any(x in src for x in blocklist):
                continue
            if any(k in src for k in (
                "HTML_TEMPLATE",
                "class GeminiClient",
                "def html_escape",
                "@dataclass\nclass Finding",
                "def parser_agent",
                "def enrich_and_score_agent",
                "def reporter_agent",
                "def export_pdf",
                "RUN_LIVE_SCAN =",
                "RAW_DIR =",
                "OUTPUT_DIR ="
            )):
                selected.append(src)
        if not selected:
            return None
        ns = {"json": json, "os": os}
        code = "\n\n".join(selected)
        try:
            exec(code, ns)
        except Exception:
            return None
        try:
            ns["RUN_LIVE_SCAN"] = True
            ns["OUTPUT_DIR"] = OUTPUT_DIR
            ns["TARGET_DOMAIN"] = host or "example.com"
        except Exception:
            pass
        return ns
    except Exception:
        return None

def run_kaggle_only(url: str, host: str) -> Optional[str]:
    ns = load_kaggle_ns(host)
    if not ns:
        return None
    parser_fn = ns.get("parser_agent")
    score_fn = ns.get("enrich_and_score_agent")
    reporter_fn = ns.get("reporter_agent")
    export_pdf_fn = ns.get("export_pdf")
    if not (callable(parser_fn) and callable(score_fn) and callable(reporter_fn)):
        return None
    scan_path = RAW_SCAN_PATH
    try:
        if os.path.isfile(UPLOADED_SCAN_PATH):
            scan_path = UPLOADED_SCAN_PATH
        elif os.path.isfile(RAW_SCAN_PATH):
            scan_path = RAW_SCAN_PATH
        else:
            assets = discover_assets(host) if host else []
            live_path = run_nuclei(assets) if assets else None
            if live_path and os.path.isfile(live_path):
                scan_path = live_path
    except Exception:
        pass
    findings = parser_fn(scan_path)
    try:
        if host:
            original = findings
            filtered = [f for f in findings if isinstance(getattr(f, "host", ""), str) and (host in getattr(f, "host", ""))]
            findings = filtered if filtered else original
    except Exception:
        pass
    findings = score_fn(findings)
    report_path = reporter_fn(findings)
    try:
        if report_path and os.path.isfile(report_path):
            with open(report_path, "r", encoding="utf-8") as f:
                html = f.read()
            site = host or "example.com"
            target = url or f"https://{site}"
            import re as _re
            html = _re.sub(r"(<title>Web Application Security Assessment Report - )(.+?)(</title>)", rf"\1{site}\3", html)
            html = _re.sub(r"(<h1>Web Application Security Assessment Report — )(.+?)(</h1>)", rf"\1{site}\3", html)
            html = _re.sub(r"(<div class=\"page-footer\">\s*<div>)(.+?)( Security Assessment</div>)", rf"\1{site}\3", html)
            html = _re.sub(r"(<p><strong>Target URL:</strong>\s*)(.+?)(</p>)", rf"\1{target}\3", html)
            html = _re.sub(r"(<div><strong>Target:</strong>\s*)(.+?)(</div>)", rf"\1{target}\3", html)
            html = _re.sub(r"(<p>A targeted security assessment was conducted on <strong>)(.+?)(</strong> to identify)", rf"\1{site}\3", html)
            html = html.replace("ExampleSite", site)
            html = html.replace("https://example.com", target)
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(html)
    except Exception:
        pass
    try:
        if callable(export_pdf_fn):
            export_pdf_fn(report_path)
    except Exception:
        pass
    return report_path if os.path.isfile(report_path) else None

@app.get("/api/tools-status")
def tools_status():
    nuc = shutil.which("nuclei")
    if not nuc:
        local = os.path.join(BIN_DIR, "nuclei.exe")
        nuc = local if os.path.isfile(local) else None
    ama = shutil.which("amass")
    if not ama:
        local = os.path.join(BIN_DIR, "amass.exe")
        ama = local if os.path.isfile(local) else None
    def ver(cmd):
        try:
            out = subprocess.run([cmd, "-version"], capture_output=True, text=True, timeout=5)
            if out.returncode != 0:
                out = subprocess.run([cmd, "--version"], capture_output=True, text=True, timeout=5)
            return (out.stdout or out.stderr).strip().splitlines()[0] if (out.stdout or out.stderr) else None
        except:
            return None
    live_path = os.path.join(OUTPUT_DIR, "live_scan.jsonl")
    size = 0
    if os.path.isfile(live_path):
        try:
            size = os.path.getsize(live_path)
        except:
            size = 0
    return jsonify({
        "nuclei_path": nuc,
        "nuclei_version": ver(nuc) if nuc else None,
        "amass_path": ama,
        "amass_version": ver(ama) if ama else None,
        "live_scan_exists": os.path.isfile(live_path),
        "live_scan_size": size,
        "uploaded_scan_exists": os.path.isfile(UPLOADED_SCAN_PATH),
        "uploaded_scan_size": os.path.getsize(UPLOADED_SCAN_PATH) if os.path.isfile(UPLOADED_SCAN_PATH) else 0,
    })

@app.post("/api/upload-scan")
def upload_scan():
    if "file" not in request.files:
        return jsonify({"error": "file is required"}), 400
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "invalid file"}), 400
    name = f.filename.lower()
    if not (name.endswith(".json") or name.endswith(".jsonl")):
        return jsonify({"error": "must be .json or .jsonl"}), 400
    tmp = tempfile.NamedTemporaryFile(delete=False)
    try:
        f.save(tmp.name)
        with open(tmp.name, "rb") as src, open(UPLOADED_SCAN_PATH, "wb") as dst:
            dst.write(src.read())
        sz = os.path.getsize(UPLOADED_SCAN_PATH) if os.path.isfile(UPLOADED_SCAN_PATH) else 0
        return jsonify({"ok": True, "path": UPLOADED_SCAN_PATH, "size": sz})
    finally:
        try:
            os.remove(tmp.name)
        except Exception:
            pass

@app.get("/api/generate-report")
def generate_report():
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400

    host = (urlparse(url).hostname or "")
    report_path = run_kaggle_only(url, host)
    if not report_path:
        return jsonify({"error": "kaggle notebook pipeline not available"}), 500

    return send_file(report_path, mimetype="text/html", as_attachment=True, download_name="report.html")

@app.get("/api/latest")
def get_latest():
    report_path = os.path.join(OUTPUT_DIR, "report.html")
    if not os.path.isfile(report_path):
        return jsonify({"error": "report not generated yet"}), 404

    return send_file(report_path, mimetype="text/html", as_attachment=True, download_name="report.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
