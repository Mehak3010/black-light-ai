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
#   Your Original Logic (Parser + Scoring + Reporter)
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
        f.risk_score = round(min(10.0, SEV_BASE.get(f.severity, 0) * 1.0 + (1.0 if f.cve_ids else 0)), 2)
    json_write([asdict(x) for x in findings], os.path.join(OUTPUT_DIR, "findings_scored.json"))
    return findings

# Include your entire HTML_TEMPLATE + reporter_agent here (unchanged)

# ───────────────────────────────────────────────────────────── #
#   Flask App Setup
# ───────────────────────────────────────────────────────────── #
app = Flask(__name__, template_folder="templates")

def latest_artifact() -> Optional[str]:
    pdf = os.path.join(OUTPUT_DIR, "report.pdf")
    html = os.path.join(OUTPUT_DIR, "report.html")
    return pdf if os.path.isfile(pdf) else html if os.path.isfile(html) else None

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
    if not findings: findings = parser_agent(scan_path, None)
    
    findings = enrich_and_score_agent(findings)
    report_html = reporter_agent(findings, site_name=site_name, target_url=url)

    return jsonify({"status": "ok", "message": "Report generated"})

@app.get("/api/latest")
def get_latest():
    path = latest_artifact()
    if not path:
        return jsonify({"error": "no report"}), 404
    return send_file(path, as_attachment=True, download_name=os.path.basename(path))

# ───────────────────────────────────────────────────────────── #
#   Start server correctly for Render
# ───────────────────────────────────────────────────────────── #
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
