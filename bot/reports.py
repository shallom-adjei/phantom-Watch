"""Multi‑code‑block report: each tool's output in its own gray copyable box."""
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
    """Remove terminal escape codes."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)

def format_summary(domain, results, detailed=False):
    """Build the final report with separate code blocks for each tool."""
    score, level = compute_threat_score(results)
    risk_emoji = {"LOW":"🟢","MEDIUM":"🟡","HIGH":"🟠","CRITICAL":"🔴"}.get(level,"⚪")

    lines = []
    # Header
    lines.append(f"🔍 *Scan completed for {domain}*")
    lines.append(f"{risk_emoji} Threat Score: *{score}/100*  |  Risk Level: *{level}*")
    lines.append("━━━━━━━━━━━━━━━━━━")

    # Compact summary (brief)
    if 'nmap' in results:
        ports = len(re.findall(r"^\d+/tcp\s+open\s+", results.get("nmap",""), re.MULTILINE))
        vulns = len(re.findall(r"\|.*VULNERABLE.*", results.get("nmap","")))
        lines.append(f"🛡️ *Nmap*: {ports} open ports, {vulns} potential vulns")
    if 'nikto' in results:
        issues = len(re.findall(r"\+ (.*)", results.get("nikto","")))
        lines.append(f"🔥 *Nikto*: {issues} web issues")
    if 'whatweb' in results:
        clean = re.sub(r"\x1b\[[0-9;]*m", "", results.get("whatweb",""))
        servers = re.findall(r"HTTPServer\[ (.*?) \]", clean)
        lines.append(f"🧩 *Technology*: {servers[0] if servers else 'No server header'}")
    if 'theHarvester' in results:
        harvest = results["theHarvester"]
        if harvest == "No email":
            lines.append("📧 *theHarvester*: No email set – skipped.")
        elif "<html" in harvest.lower():
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", harvest)
            lines.append(f"📧 *theHarvester*: {len(emails)} leaked emails found")
    if 'dnstwist' in results:
        registered = len(re.findall(r"^([^ ]+)\s+registered.*", results.get("dnstwist",""), re.MULTILINE))
        lines.append(f"🕵️ *dnstwist*: {registered} typosquatting domains registered")
    if 'metagoofil' in results:
        if "No metadata" in results.get("metagoofil",""):
            lines.append("📄 *Metagoofil*: No metadata leaks")
        else:
            lines.append("📄 *Metagoofil*: Metadata leaks found")
    if 'sherlock' in results:
        found = len(re.findall(r"\[\+\] (.*)", results.get("sherlock","")))
        lines.append(f"👥 *Sherlock*: {found} social accounts found")
    if 'dalfox' in results and "vulnerable" in results['dalfox'].lower():
        lines.append("🦠 *Dalfox*: XSS vulnerabilities detected!")

    # If paid, add detailed blocks for each tool
    if detailed:
        lines.append("")
        lines.append("📋 *DETAILED PAID REPORT*")
        # Nmap
        if 'nmap' in results and results['nmap']:
            lines.append("🛡️ *Nmap*")
            lines.append("```")
            lines.append(clean_ansi(results['nmap'][:600]))
            lines.append("```")
        # Nikto
        if 'nikto' in results and results['nikto']:
            lines.append("🔥 *Nikto*")
            lines.append("```")
            lines.append(clean_ansi(results['nikto'][:600]))
            lines.append("```")
        # WhatWeb
        if 'whatweb' in results and results['whatweb']:
            lines.append("🧩 *WhatWeb*")
            lines.append("```")
            lines.append(clean_ansi(results['whatweb'][:400]))
            lines.append("```")
        # theHarvester
        if 'theHarvester' in results and results['theHarvester'] not in ("No email", "No results", ""):
            lines.append("📧 *theHarvester*")
            lines.append("```")
            lines.append(clean_ansi(results['theHarvester'][:400]))
            lines.append("```")
        # dnstwist
        if 'dnstwist' in results and results['dnstwist']:
            lines.append("🕵️ *dnstwist*")
            lines.append("```")
            lines.append(clean_ansi(results['dnstwist'][:400]))
            lines.append("```")
        # Metagoofil
        if 'metagoofil' in results and results['metagoofil'] and "No metadata" not in results['metagoofil']:
            lines.append("📄 *Metagoofil*")
            lines.append("```")
            lines.append(clean_ansi(results['metagoofil'][:400]))
            lines.append("```")
        # Sherlock
        if 'sherlock' in results and results['sherlock']:
            lines.append("👥 *Sherlock*")
            lines.append("```")
            lines.append(clean_ansi(results['sherlock'][:400]))
            lines.append("```")
        # Dalfox
        if 'dalfox' in results and results['dalfox'] and "vulnerable" in results['dalfox'].lower():
            lines.append("🦠 *Dalfox*")
            lines.append("```")
            lines.append(clean_ansi(results['dalfox'][:400]))
            lines.append("```")

        # Compliance table
        lines.append("")
        lines.append("📜 *Compliance Status*")
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
            lines.append(f"{status} {category}: PCI {rules['pci']} / HIPAA {rules['hipaa']}")
        lines.append("")
        lines.append("⚠️ For full compliance documentation, contact admin.")
    else:
        lines.append("")
        lines.append("⚠️ This is a FREE summary. Upgrade to Monthly/Enterprise for detailed reports with compliance mapping and exploitation proof.")

    return "\n".join(lines)
