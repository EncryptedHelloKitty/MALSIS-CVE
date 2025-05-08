import json
import os
import time
import requests
import argparse
import logging
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from jinja2 import Environment, FileSystemLoader
from difflib import SequenceMatcher

# === CONFIGURATION ===
CUCKOO_API = os.getenv("CUCKOO_API", "http://localhost:8090")
CUCKOO_TOKEN = os.getenv("CUCKOO_TOKEN", "HALVCRn8FvQX5kivsFI3Cg")
DEFAULT_TIMEOUT = 300
HEADERS = {"Authorization": f"Bearer {CUCKOO_TOKEN}"}

ENTERPRISE_ATTACK_PATH = "enterprise-attack.json"  # Local copy from MITRE GitHub

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

NOISE_WORDS = {"ok", "success", "error", "microsoft", "windows", "application", "file", "data"}

# === HELPERS ===
def clean_text(text):
    text = text.lower().strip()
    text = re.sub(r"[^a-zA-Z0-9_/.:\\-]", "", text)
    if len(text) <= 3 or text in NOISE_WORDS:
        return None
    return text

def estimate_cvss(description):
    description = description.lower()
    if "remote code execution" in description or "rce" in description:
        return 9.8, "Critical"
    elif "privilege escalation" in description:
        return 8.8, "High"
    elif "information disclosure" in description:
        return 7.5, "High"
    elif "denial of service" in description:
        return 6.5, "Medium"
    else:
        return 5.0, "Medium"

def submit_to_cuckoo(file_path):
    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = requests.post(f"{CUCKOO_API}/tasks/create/file", files=files, headers=HEADERS)
            response.raise_for_status()
            task_id = response.json()["task_id"]
            logging.info(f"Submitted to Cuckoo. Task ID: {task_id}")
            return task_id
    except Exception as e:
        logging.error(f"Failed to submit file: {e}")
        return None

def wait_for_report(task_id, timeout=DEFAULT_TIMEOUT):
    logging.info(f"Waiting for report (timeout = {timeout}s)...")
    for _ in range(timeout // 5):
        try:
            resp = requests.get(f"{CUCKOO_API}/tasks/view/{task_id}", headers=HEADERS)
            status = resp.json()["task"]["status"]
            if status == "reported":
                logging.info("Report is ready.")
                return True
        except Exception:
            pass
        time.sleep(5)
    logging.error("Timeout waiting for report.")
    return False

def download_report(task_id, save_path="report.json"):
    try:
        resp = requests.get(f"{CUCKOO_API}/tasks/report/{task_id}/json", headers=HEADERS)
        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(resp.json(), f, indent=2)
        logging.info(f"Report saved to {save_path}")
        return True
    except Exception as e:
        logging.error(f"Error downloading report: {e}")
        return False

def extract_indicators_from_cuckoo(report_path="report.json"):
    indicators = set()
    if not os.path.exists(report_path):
        logging.error(f"Report not found: {report_path}")
        return []

    with open(report_path, 'r', encoding='utf-8') as f:
        report = json.load(f)

    for sig in report.get("signatures", []):
        if "description" in sig:
            cleaned = clean_text(sig["description"])
            if cleaned:
                indicators.add(cleaned)
        for mark in sig.get("marks", []):
            if isinstance(mark, dict):
                for val in mark.values():
                    if isinstance(val, str):
                        cleaned = clean_text(val)
                        if cleaned:
                            indicators.add(cleaned)

    for proc in report.get("behavior", {}).get("processes", []):
        if "process_name" in proc:
            cleaned = clean_text(proc["process_name"])
            if cleaned:
                indicators.add(cleaned)
        for call in proc.get("calls", []):
            if "api" in call:
                cleaned = clean_text(call["api"])
                if cleaned:
                    indicators.add(cleaned)
            for arg in call.get("arguments", []):
                if isinstance(arg, dict) and "value" in arg:
                    val = arg["value"]
                    if isinstance(val, str):
                        cleaned = clean_text(val)
                        if cleaned:
                            indicators.add(cleaned)

    for section in ["summary", "behavior"]:
        for key in ["files", "mutexes", "registry_keys"]:
            for item in report.get(section, {}).get(key, []):
                if isinstance(item, str):
                    cleaned = clean_text(item)
                    if cleaned:
                        indicators.add(cleaned)

    for netkey in ["hosts", "domains", "http"]:
        for entry in report.get("network", {}).get(netkey, []):
            if isinstance(entry, dict):
                for val in entry.values():
                    if isinstance(val, str):
                        cleaned = clean_text(val)
                        if cleaned:
                            indicators.add(cleaned)
            elif isinstance(entry, str):
                cleaned = clean_text(entry)
                if cleaned:
                    indicators.add(cleaned)

    indicators = list(indicators)
    logging.info(f"Extracted {len(indicators)} clean indicators.")
    return indicators

def load_mitre_attack(path=ENTERPRISE_ATTACK_PATH):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    techniques = []
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
            techniques.append({
                "id": next((ref["external_id"] for ref in obj.get("external_references", []) if "external_id" in ref), None),
                "name": obj.get("name", ""),
                "description": obj.get("description", "")
            })
    return techniques

def map_indicators_to_mitre(indicators, techniques):
    mapped = []
    for indicator in indicators:
        best_match = None
        best_score = 0
        for tech in techniques:
            score = SequenceMatcher(None, indicator, tech["name"].lower()).ratio()
            if score > best_score:
                best_score = score
                best_match = tech
        if best_score > 0.5:
            mapped.append({"indicator": indicator, "technique": best_match})
    return mapped

def map_to_cves(indicators, mitre_techniques, cve_path, top_n=10):
    with open(cve_path, encoding="utf-8") as f:
        cve_data = json.load(f)

    combined_doc = " ".join(indicators + [tech["technique"]["name"] for tech in mitre_techniques])
    cve_docs = [f"{cve['id']} {cve['description']}" for cve in cve_data]

    vectorizer = TfidfVectorizer()
    tfidf_matrix = vectorizer.fit_transform([combined_doc] + cve_docs)

    similarities = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:]).flatten()
    top_indices = similarities.argsort()[::-1][:top_n]

    top_cves = []
    for i in top_indices:
        cve = cve_data[i]
        score, risk = estimate_cvss(cve['description'])
        cve["real_score"] = score
        cve["real_risk"] = risk
        top_cves.append(cve)
    return sorted(top_cves, key=lambda x: x["real_score"], reverse=True)

def generate_html_report(cves, techniques, output_path="final_report.html"):
    env = Environment(loader=FileSystemLoader("."))
    template = env.from_string("""
    <html>
    <head>
        <title>Malware to CVE & MITRE Mapping</title>
        <style>
            body { font-family: Arial; background-color: #f9f9f9; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th { background-color: #333; color: white; padding: 10px; }
            td { padding: 10px; border: 1px solid #ccc; }
            tr:nth-child(even) { background-color: #f2f2f2; }
            .Critical { background-color: #ff4d4d; }
            .High { background-color: #ff9933; }
            .Medium { background-color: #ffcc00; }
            .Low { background-color: #99cc00; }
        </style>
    </head>
    <body>
        <h1>Malware Analysis Report</h1>

        <h2>Mapped Indicators and MITRE ATT&CK Techniques</h2>
        <table>
            <tr><th>Indicator</th><th>Technique ID</th><th>Name</th><th>Description</th></tr>
            {% for map in techniques %}
            <tr>
                <td>{{map.indicator}}</td>
                <td>{{map.technique.id}}</td>
                <td>{{map.technique.name}}</td>
                <td>{{map.technique.description}}</td>
            </tr>
            {% endfor %}
        </table>

        <h2>Top CVEs Mapped</h2>
        <table>
            <tr><th>CVE ID</th><th>Description</th><th>CVSS Score</th><th>Risk Level</th></tr>
            {% for cve in cves %}
            <tr>
                <td>{{cve.id}}</td>
                <td>{{cve.description}}</td>
                <td>{{cve.real_score}}</td>
                <td class="{{cve.real_risk}}">{{cve.real_risk}}</td>
            </tr>
            {% endfor %}
        </table>

    </body>
    </html>
    """)
    html_content = template.render(cves=cves, techniques=techniques)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

# === CLI ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cuckoo + MITRE ATT&CK + CVE Mapping Pipeline")
    parser.add_argument("--file", required=True, help="Path to file to submit to Cuckoo")
    parser.add_argument("--cves", default="nvd_cves.json", help="Path to CVE database JSON")
    parser.add_argument("--top", type=int, default=10, help="Number of top CVEs to return")
    args = parser.parse_args()

    task_id = submit_to_cuckoo(args.file)
    if task_id and wait_for_report(task_id):
        if download_report(task_id):
            indicators = extract_indicators_from_cuckoo("report.json")
            techniques = load_mitre_attack()
            mapped_techniques = map_indicators_to_mitre(indicators, techniques)
            top_cves = map_to_cves(indicators, mapped_techniques, args.cves, top_n=args.top)
            generate_html_report(top_cves, mapped_techniques, "final_report.html")
            os.system("firefox final_report.html")
