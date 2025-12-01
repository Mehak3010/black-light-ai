import os
import re
import json
from dataclasses import dataclass, asdict
from typing import List, Optional
from urllib.parse import urlparse
from flask import Flask, request, send_file, jsonify, render_template, abort

# ───────────────────────────────────────────────────────────── #
#   Path Config
# ───────────────────────────────────────────────────────────── #
OUTPUT_DIR = os.path.join(os.getcwd(), "artifacts")
RAW_SCAN_PATH = os.path.join(os.getcwd(), "scan.jsonl")
UPLOADED_SCAN_PATH = os.path.join(OUTPUT_DIR, "uploaded_scan.jsonl")

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ───────────────────────────────────────────────────────────── #
#   Parser & Scoring Logic
# ───────────────────────────────────────────────────────────── #
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
                cve_ids=[], cve_links=[],
                cvss=None, confidence="low",
                risk_score=0.0, notes=""
            ))

    json_write([asdict(f) for f in findings], os.path.join(OUTPUT_DIR, "findings.json"))
    return findings

SEV_BASE = {"info": 0, "low": 2, "medium": 5, "high": 8, "critical": 10}

def enrich_and_score_agent(findings: List[Finding]) -> List[Finding]:
    for f in findings:
        cves = set(re.findall(r"CVE-\d{4}-\d{4,7}", f.title))
        f.cve_ids = sorted(cves)
        f.cve_links = [f"https://nvd.nist.gov/vuln/detail/{c}" for c in f.cve_ids]
        base = SEV_BASE.get(f.severity, 0)
        bonus = 1.0 if f.cve_ids else 0.0
        f.risk_score = round(min(10.0, base * 1.0 + bonus), 2)

    json_write([asdict(f) for f in findings], os.path.join(OUTPUT_DIR, "findings_scored.json"))
    return findings

# ───────────────────────────────────────────────────────────── #
#   HTML Report Engine
# ───────────────────────────────────────────────────────────── #
HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Security Report - {{SITE_NAME}}</title>
</head>
<body>
  <h1>Security Report for {{SITE_NAME}}</h1>
  <h3>Findings:</h3>
  {{FINDINGS_TABLE}}
</body>
</html>
"""
def reporter_agent(findings: List[Finding], site_name: str, target_url: str) -> str:
    rows = ""
    for f in findings:
        rows += (
            f"<tr>"
            f"<td>{html_escape(f.title)}</td>"
            f"<td>{html_escape(f.severity)}</td>"
            f"<td>{html_escape(f.host)}</td>"
            f"<td>{f.risk_score}</td>"
            f"</tr>"
        )

    html_out = f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Security Report - {html_escape(site_name)}</title>
</head>
<body>
  <h1>Security Report - {html_escape(site_name)}</h1>
  <h3>Findings:</h3>
  <table border='1' cellpadding='6'>
    <tr>
      <th>Title</th>
      <th>Severity</th>
      <th>Host</th>
      <th>Risk</th>
    </tr>
    {rows}
  </table>
</body>
</html>
"""
    report_path = os.path.join(OUTPUT_DIR, "report.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_out)
    return report_path

# ───────────────────────────────────────────────────────────── #
#   Flask App Routes
# ───────────────────────────────────────────────────────────── #
app = Flask(__name__, template_folder="templates")

def latest_artifact() -> Optional[str]:
    html = os.path.join(OUTPUT_DIR, "report.html")
    return html if os.path.isfile(html) else None

@app.get("/")
def home():
    return render_template("index.html")

@app.get("/api/generate-report")
def generate_report():
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400

    host = (urlparse(url).hostname or "")
    site_name = host or "ExampleSite"

    scan_path = UPLOADED_SCAN_PATH if os.path.isfile(UPLOADED_SCAN_PATH) else RAW_SCAN_PATH

    findings = parser_agent(scan_path, host if host else None)
    if not findings:
        findings = parser_agent(scan_path, None)

    findings = enrich_and_score_agent(findings)

    report_path = reporter_agent(findings, site_name=site_name, target_url=url)

    return send_file(report_path, mimetype="text/html", as_attachment=True,
                     download_name="report.html")

@app.get("/api/latest")
def get_latest():
    path = latest_artifact()
    if not path:
        return jsonify({"error": "No report available"}), 404
    return send_file(path, as_attachment=True, download_name="report.html")

# ───────────────────────────────────────────────────────────── #
#   Start Server (Render compatible)
# ───────────────────────────────────────────────────────────── #
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)