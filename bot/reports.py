"""Single‑message report with compact code blocks."""
import re
from datetime import datetime
from bot.config import ADMIN_USERNAME

COMPLIANCE = {
    "xss": {"pci": "PCI-DSS 6.5.7", "hipaa": "164.308(a)(5)(ii)(B)"},
    "sqli": {"pci": "PCI-DSS 6.5.1", "hipaa": "164.308(a)(5)(ii)(B)"},
    "open_port": {"pci": "PCI-DSS 1.1.6", "hipaa": "164.308(a)(4)(ii)(B)"},
    "vulnerable_service": {"pci": "PCI-DSS 6.1", "hipaa": "164.308(a)(5)(ii)(B)"},
    "leaked_email": {"pci": "PCI-DSS 6.5.10", "hipaa": "164.308(a)(5)(ii)(B)"},
    "typosquatting": {"pci": "N/A", "hipaa": "164.308(a)(5)(ii)(B)"},
    "metadata_leak": {"pci": "PCI-DSS 6.5.9", "hipaa": "164.308(a)(1)(ii)(D)"},
    "social_media": {"pci": "N/A", "hipaa": "164.308(a)(5)(ii)(B)"},
}

def compute_threat_score(results):
    score = 0
    max_score = 0
    if 'nmap' in results:
        open_ports = len(re.findall(r"^\d+/tcp\s+open\s+", results.get('nmap',''), re.MULTILINE))
        vulns = len(re.findall(r"\|.*VULNERABLE.*", results.get('nmap','')))
        score += (open_ports * 5) + (vulns * 15)
        max_score += (10 * 5) + (10 * 15)
    if 'nikto' in results:
        issues = len(re.findall(r"\+ (.*)", results.get('nikto','')))
        score += issues * 10
        max_score += 10 * 10
    if 'theHarvester' in results and results['theHarvester'] != "No email":
        harvest = results['theHarvester']
        if "<html" in harvest.lower():
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", harvest)
            score += len(emails) * 10
            max_score += 20 * 10
    if 'dnstwist' in results:
        registered = len(re.findall(r"^([^ ]+)\s+registered.*", results.get('dnstwist',''), re.MULTILINE))
        score += registered * 10
        max_score += 10 * 10
    if 'metagoofil' in results and "No metadata" not in results.get('metagoofil',''):
        score += 25
        max_score += 25
    if 'sherlock' in results:
        found = len(re.findall(r"\[\+\] (.*)", results.get('sherlock','')))
        score += found * 5
        max_score += 20 * 5
    if 'dalfox' in results and "vulnerable" in results.get('dalfox','').lower():
        score += 50
        max_score += 50
    if max_score == 0:
        return 0, "LOW"
    percent = min(100, int((score / max_score) * 100))
    if percent < 10:
        level = "LOW"
    elif percent < 30:
        level = "MEDIUM"
    elif percent < 60:
        level = "HIGH"
    else:
        level = "CRITICAL"
    return percent, level

def clean_ansi(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", text)

def build_report_markdown(domain, results, detailed=False):
    """Return a single Markdown string with compact code blocks."""
    score, level = compute_threat_score(results)
    risk_emoji = {"LOW":"🟢","MEDIUM":"🟡","HIGH":"🟠","CRITICAL":"🔴"}.get(level,"⚪")

    lines = []

    # Header
    lines.append(f"🔍 Scan completed for {domain}")
    lines.append(f"{risk_emoji} Threat Score: {score}/100  |  Risk Level: {level}")
    lines.append("━━━━━━━━━━━━━━━━━━")

    # Compact summary
    if 'nmap' in results:
        ports = len(re.findall(r"^\d+/tcp\s+open\s+", results.get("nmap",""), re.MULTILINE))
        vulns = len(re.findall(r"\|.*VULNERABLE.*", results.get("nmap","")))
        lines.append(f"🛡️ Nmap: {ports} open ports, {vulns} potential vulns")
    if 'nikto' in results:
        issues = len(re.findall(r"\+ (.*)", results.get("nikto","")))
        lines.append(f"🔥 Nikto: {issues} web issues")
    if 'whatweb' in results:
        clean = re.sub(r"\x1b\[[0-9;]*m", "", results.get("whatweb",""))
        servers = re.findall(r"HTTPServer\[ (.*?) \]", clean)
        lines.append(f"🧩 Technology: {servers[0] if servers else 'No server header'}")
    if 'theHarvester' in results:
        harvest = results["theHarvester"]
        if harvest == "No email":
            lines.append("📧 theHarvester: No email set – skipped.")
        elif "<html" in harvest.lower():
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", harvest)
            lines.append(f"📧 theHarvester: {len(emails)} leaked emails found")
    if 'dnstwist' in results:
        registered = len(re.findall(r"^([^ ]+)\s+registered.*", results.get("dnstwist",""), re.MULTILINE))
        lines.append(f"🕵️ dnstwist: {registered} typosquatting domains registered")
    if 'metagoofil' in results:
        if "No metadata" in results.get("metagoofil",""):
            lines.append("📄 Metagoofil: No metadata leaks")
        else:
            lines.append("📄 Metagoofil: Metadata leaks found")
    if 'sherlock' in results:
        found = len(re.findall(r"\[\+\] (.*)", results.get("sherlock","")))
        lines.append(f"👥 Sherlock: {found} social accounts found")
    if 'dalfox' in results and "vulnerable" in results['dalfox'].lower():
        lines.append("🦠 Dalfox: XSS vulnerabilities detected!")

    if detailed:
        lines.append("")  # one blank line before detailed section

        tools = [
            ("🛡️ Nmap", 'nmap'),
            ("🔥 Nikto", 'nikto'),
            ("🧩 WhatWeb", 'whatweb'),
            ("📧 theHarvester", 'theHarvester'),
            ("🕵️ dnstwist", 'dnstwist'),
            ("📄 Metagoofil", 'metagoofil'),
            ("👥 Sherlock", 'sherlock'),
            ("🦠 Dalfox", 'dalfox'),
        ]
        for label, key in tools:
            if key in results and results[key] and "Error" not in str(results[key]):
                raw = clean_ansi(results[key])
                if key == "theHarvester" and raw in ("No email", "No results"):
                    continue
                safe = raw.replace("```", "'''")
                snippet = safe[:300]
                lines.append(label)
                lines.append("```")
                lines.append(snippet)
                lines.append("```")

        # Compliance table in a code block
        compliance_lines = ["COMPLIANCE STATUS"]
        for category, rules in COMPLIANCE.items():
            status = "✅"
            if category == "xss" and "dalfox" in results and "vulnerable" in results.get("dalfox","").lower():
                status = "❌"
            elif category == "open_port" and "open" in str(results.get("nmap","")):
                status = "❌"
            elif category == "vulnerable_service" and "VULNERABLE" in str(results.get("nmap","")):
                status = "❌"
            elif category == "leaked_email" and "theHarvester" in results and "Leaked" in str(results.get("theHarvester","")):
                status = "❌"
            elif category == "typosquatting" and "dnstwist" in results and "registered" in str(results.get("dnstwist","")).lower():
                status = "❌"
            elif category == "metadata_leak" and "metagoofil" in results and "No metadata" not in results.get("metagoofil",""):
                status = "❌"
            elif category == "social_media" and "sherlock" in results and "accounts found" in str(results.get("sherlock","")):
                status = "❌"
            compliance_lines.append(f"{status} {category}: PCI {rules['pci']} / HIPAA {rules['hipaa']}")
        lines.append("```")
        lines.extend(compliance_lines)
        lines.append("```")
        lines.append("")
        lines.append("⚠️ For full compliance documentation, contact admin.")
    else:
        lines.append("")
        lines.append(f"⚠️ This is a FREE summary. Upgrade for detailed reports.\nContact admin: @{ADMIN_USERNAME}")

    return "\n".join(lines)
