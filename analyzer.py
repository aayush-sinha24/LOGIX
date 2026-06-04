# analyzer.py
import re
import os
from collections import defaultdict, Counter
from datetime import datetime
import math

# =========================
# Signature definitions
# =========================
SIGNATURES = [
    {"id":"brute_force","name":"Authentication Failures / Brute-force",
     "regex":[r"failed password", r"authentication failure", r"invalid user", r"failed login", r"login failure"],
     "severity":8,
     "remediation":["Block offending IP(s). Enable MFA and account lockout.","Reset targeted accounts and rotate credentials."],
     "precaution":"If confirmed, isolate host and check for backdoors."},

    {"id":"sql_injection","name":"Possible SQL Injection",
     "regex":[r"union\s+select", r"or\s+'?1'?\s*=\s*'?1'?", r"select\s+.+\s+from", r"drop\s+table", r"insert\s+into"],
     "severity":8,
     "remediation":["Sanitize inputs and use parameterized queries.","Apply WAF rules and review DB logs."],
     "precaution":"Check database for suspicious queries and exports."},

    {"id":"xss","name":"Possible Cross-Site Scripting (XSS)",
     "regex":[r"<script\b", r"javascript:", r"onerror\s*=", r"document\.cookie", r"<img\s+onerror"],
     "severity":7,
     "remediation":["Sanitize output; use Content Security Policy (CSP).","Patch application to encode HTML output."],
     "precaution":"Avoid using same user session tokens until fixed."},

    {"id":"dir_traversal","name":"Directory Traversal / LFI",
     "regex":[r"\.\./\.\.", r"\.\./", r"%2e%2e", r"etc/passwd", r"\.\./\.\./"],
     "severity":8,
     "remediation":["Validate and normalize file path input.","Restrict web root access and patch file-handling code."],
     "precaution":"Inspect file system for unauthorized file access."},

    # tightened suspicious download signature (requires URL or clear download indicator)
    {"id":"suspicious_download","name":"Suspicious Download / Binary Fetch",
     "regex":[
         r"\b(?:wget|curl)\b\s+https?://",                       # wget/curl with URL
         r"Invoke-WebRequest\s+(?:-Uri|--uri)\s+https?://",      # PowerShell direct download
         r"https?://[^\s]+/[^ \n]+\.(?:exe|dll|bin|sh|ps1|bat)", # URL that ends with executable/script
         r"download\.(?:php|asp|aspx)\b",                        # suspicious server-side download endpoints
         r"powershell(?:\s.*)?-EncodedCommand"                   # encoded powershell
     ],
     "severity":9,
     "remediation":["Isolate host immediately and scan binaries offline.","Block the source domain and remove malicious files."],
     "precaution":"Do not execute suspicious files; collect for AV analysis."},

    {"id":"cmd_injection","name":"Command Injection / Reverse Shell",
     "regex":[r"/bin/bash\s+-i", r"dev/tcp", r"nc\s+\-e", r"popen\(", r"exec\(", r"reverse shell", r"0>&1"],
     "severity":10,
     "remediation":["Disconnect host from network, collect memory image.","Perform full incident response and root cause analysis."],
     "precaution":"Treat system as compromised until proven clean."},

    {"id":"ransomware","name":"Ransomware-like activity",
     "regex":[r"\.locked\b", r"FILES\.ENCRYPTED", r"ransom", r"encrypted.*files"],
     "severity":10,
     "remediation":["Disconnect host; restore from known-good backups.","Contact IR team; do not pay ransom without legal counsel."],
     "precaution":"Preserve encrypted files for forensic analysis."},

    {"id":"suspicious_user_agent","name":"Scanner / Malicious User-Agent",
     "regex":[r"sqlmap", r"nikto", r"masscan", r"python-requests", r"curl/"],
     "severity":6,
     "remediation":["Block or rate-limit the offending IPs.","Review web endpoints targeted by the scanner."],
     "precaution":"Monitor for repeated scanning and adapt WAF rules."}
]

# compile regexes for fast matching
for s in SIGNATURES:
    s["compiled"] = [re.compile(p, re.IGNORECASE) for p in s["regex"]]

# =========================
# Safe lists to avoid false positives
# =========================
SAFE_PROCESSES = {
    "explorer.exe", "svchost.exe", "services.exe", "lsass.exe",
    "wininit.exe", "winlogon.exe", "taskmgr.exe", "notepad.exe",
    "chrome.exe", "firefox.exe", "msedge.exe", "python.exe", "cmd.exe",
}

SAFE_PHRASES = {
    "process started", "process launch", "file opened", "file saved",
    "service started", "scheduled task executed", "system idle", "process start"
}

# =========================
# Utility helpers
# =========================
def extract_ip(line):
    m = re.search(r"(?:(?:\d{1,3}\.){3}\d{1,3})", line)
    return m.group(0) if m else None

# =========================
# Main analysis function
# =========================
def analyze_log(path):
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    total_lines = 0
    hits = defaultdict(list)
    auth_fail_ips = []

    # First pass: signature matching with early benign-skips
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for i, raw in enumerate(f, start=1):
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            total_lines += 1

            low = line.lower()

            # 1) Quick skip: common safe phrases unless there's a download indicator
            if any(phrase in low for phrase in SAFE_PHRASES):
                if not re.search(r"(wget|curl|https?://|download\.)", low):
                    continue

            # 2) If line mentions "process", attempt to extract process name and skip safe ones
            if "process" in low:
                m = re.search(r"process(?: started| launch| started:| launch:)?[:\s]*([^\s\(\)]+)", low)
                if m:
                    pname = os.path.basename(m.group(1)).strip()
                    # normalize
                    pname = pname.lower()
                    if pname in SAFE_PROCESSES:
                        # only analyze further if clear download-like indicator exists
                        if not re.search(r"(wget|curl|https?://|download\.)", low):
                            continue

            # 3) Run signature checks
            for s in SIGNATURES:
                for cre in s.get("compiled", []):
                    if cre.search(line):
                        ip = extract_ip(line)
                        hits[s["id"]].append((i, line, ip))
                        if s["id"] == "brute_force" and ip:
                            auth_fail_ips.append(ip)
                        # matched one regex in this signature -> stop checking other regexes for this signature
                        break

    # Build findings list
    findings = []
    for s in SIGNATURES:
        id_ = s["id"]
        if id_ in hits:
            count = len(hits[id_])

            # base confidence from frequency and severity
            base_conf = 0.35 + math.log1p(count) * (s["severity"] / 20.0)

            # boost confidence if individual evidence lines contain multiple strong keywords
            boost = 0.0
            for ln, ln_text, _ in hits[id_][:8]:
                lowln = ln_text.lower()
                keywords = 0
                for kw in ("wget","curl","http://","https://","powershell","-encodedcommand",".exe","download."):
                    if kw in lowln:
                        keywords += 1
                if keywords >= 2:
                    boost += 0.15
                elif keywords == 1:
                    boost += 0.05

            confidence = min(0.99, base_conf + boost)

            excerpt = [f"line {ln}: {ln_text}" for ln, ln_text, _ in hits[id_][:8]]
            findings.append({
                "id": id_,
                "name": s["name"],
                "severity": s["severity"],
                "count": count,
                "confidence": round(confidence, 2),
                "desc": s.get("remediation", ""),
                "remediation": s["remediation"],
                "precaution": s.get("precaution", ""),
                "excerpt": excerpt,
                "evidence": hits[id_][:20]
            })

    # Brute-force by frequency heuristic (per-IP)
    ip_counts = Counter(auth_fail_ips)
    for ip, c in ip_counts.items():
        if c >= 5:
            findings.append({
                "id": f"brute_freq_{ip}",
                "name": "Repeated Authentication Failures (by IP)",
                "severity": 8,
                "count": c,
                "confidence": 0.94,
                "desc": "High number of auth failures from single IP suggests automated brute-force.",
                "remediation": ["Block IP; enable rate-limiting/account lockouts; reset targeted accounts."],
                "precaution": "Consider MFA and checking for successful logins around same timeframe.",
                "excerpt": [f"IP {ip} had {c} failed attempts."],
                "evidence": [(None, f"{c} failures from {ip}", ip)]
            })

    # Port-scan heuristic: same IP connecting to many ports
    ip_ports = defaultdict(set)
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for raw in f:
            l = raw.strip()
            ip = extract_ip(l)
            if not ip:
                continue
            # find "port <n>" or :<n>
            for m in re.findall(r"(?:port\s+(\d{1,5}))|:(\d{2,5})", l, flags=re.IGNORECASE):
                port = m[0] or m[1]
                if port:
                    try:
                        ip_ports[ip].add(int(port))
                    except:
                        pass
    for ip, ports in ip_ports.items():
        if len(ports) >= 6:
            findings.append({
                "id": f"port_scan_{ip}",
                "name": "Possible Port Scan",
                "severity": 6,
                "count": len(ports),
                "confidence": 0.86,
                "desc": "Multiple distinct ports targeted from one IP.",
                "remediation": ["Block/investigate IP and monitor firewall logs."],
                "precaution": "Harden exposed services and use network segmentation.",
                "excerpt": [f"{ip} targeted ports: {sorted(list(ports))[:12]}"],
                "evidence": [(None, f"{len(ports)} ports", ip)]
            })

    # sort findings for best-first display
    findings = sorted(findings, key=lambda x: (x["severity"] * x["confidence"] * x["count"]), reverse=True)

    metadata = {
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
        "total_lines_processed": total_lines,
        "unique_signatures_found": len(findings)
    }

    summary = findings[0]["name"] + f" (confidence {findings[0]['confidence']})" if findings else "No clear attack patterns detected"

    return {"summary": summary, "findings": findings, "metadata": metadata}


# =========================
# Report rendering (text)
# =========================
def render_report_text(report):
    lines = []
    lines.append("=== Logix Report ===")
    lines.append(f"Analyzed at (UTC): {report['metadata'].get('analyzed_at')}")
    lines.append(f"Total lines processed: {report['metadata'].get('total_lines_processed')}")
    lines.append("")
    lines.append("SUMMARY:")
    lines.append(report.get('summary', 'No summary'))
    lines.append("")
    lines.append("DETAILED FINDINGS:")
    if not report.get('findings'):
        lines.append("No suspicious patterns detected by current rule-set.")
    for f in report.get('findings', []):
        lines.append("-" * 60)
        lines.append(f"Name: {f.get('name')}")
        lines.append(f"Severity: {f.get('severity')}")
        lines.append(f"Confidence: {f.get('confidence')}")
        lines.append(f"Count: {f.get('count')}")
        lines.append("Suggested Remediation:")
        for r in f.get('remediation', []):
            lines.append("  - " + r)
        if f.get('precaution'):
            lines.append("Immediate Precaution: " + f.get('precaution'))
        lines.append("Evidence (excerpt):")
        for e in f.get('excerpt', []):
            lines.append("  " + e)
        lines.append("")
    lines.append("")
    return "\n".join(lines)


# small CLI test
if __name__ == "__main__":
    import sys
    p = sys.argv[1] if len(sys.argv) > 1 else "sample_logs/sample.log"
    r = analyze_log(p)
    text = render_report_text(r)
    os.makedirs("reports", exist_ok=True)
    out = "reports/quick_logix_report.txt"
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)
    print("Wrote", out)
