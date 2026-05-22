"""Report generators and threat scoring."""
import re
from datetime import datetime

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

def format_summary(domain, results, detailed=False):
    score, level = compute_threat_score(results)
    risk_emoji = {"LOW":"🟢","MEDIUM":"🟡","HIGH":"🟠","CRITICAL":"🔴"}.get(level,"⚪")
    lines = [
        f"🔍 *Scan completed for {domain}*",
        f"{risk_emoji} Threat Score: *{score}/100*  |  Risk Level: *{level}*\n",
        "━━━━━━━━━━━━━━━━━━"
    ]
    # ... (the entire format_summary body – I'll provide it in the full code below)

def format_summary(domain, results, detailed=False):
    score, level = compute_threat_score(results)
    risk_emoji = {"LOW":"🟢","MEDIUM":"🟡","HIGH":"🟠","CRITICAL":"🔴"}.get(level,"⚪")
    lines = [
        f"🔍 *Scan completed for {domain}*",
        f"{risk_emoji} Threat Score: *{score}/100*  |  Risk Level: *{level}*\n",
        "━━━━━━━━━━━━━━━━━━"
    ]
    if "nmap" in results:
        ports = len(re.findall(r"^\d+/tcp\s+open\s+", results.get("nmap", ""), re.MULTILINE))
        vulns = len(re.findall(r"\|.*VULNERABLE.*", results.get("nmap", "")))
        if ports or vulns:
            lines.append(f"🛡️ *Nmap*: {ports} open ports, {vulns} potential vulns")
        else:
            lines.append("🛡️ *Nmap*: No open ports or vulns found.")
    else:
        lines.append("🛡️ *Nmap*: Not run.")
    if "nikto" in results:
        issues = len(re.findall(r"\+ (.*)", results.get("nikto", "")))
        if issues:
            lines.append(f"🔥 *Nikto*: {issues} web issues")
        else:
            lines.append("🔥 *Nikto*: No web issues found.")
    else:
        lines.append("🔥 *Nikto*: Not run.")
    if "whatweb" in results:
        clean = re.sub(r"\x1b\[[0-9;]*m", "", results.get("whatweb", ""))
        servers = re.findall(r"HTTPServer\[ (.*?) \]", clean)
        if servers:
            lines.append(f"🧩 *Technology*: {servers[0]}")
        else:
            lines.append("🧩 *Technology*: No server header detected.")
    else:
        lines.append("🧩 *Technology*: Not run.")
    if "theHarvester" in results:
        harvest = results["theHarvester"]
        if harvest == "No email":
            lines.append("📧 *theHarvester*: No email set – skipped.")
        elif "<html" in harvest.lower():
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", harvest)
            if emails:
                lines.append(f"📧 *theHarvester*: {len(emails)} leaked emails found")
            else:
                lines.append("📧 *theHarvester*: No leaked emails found.")
        else:
            lines.append("📧 *theHarvester*: No results.")
    else:
        lines.append("📧 *theHarvester*: Not run.")
    if "dnstwist" in results:
        registered = len(re.findall(r"^([^ ]+)\s+registered.*", results.get("dnstwist", ""), re.MULTILINE))
        if registered:
            lines.append(f"🕵️ *dnstwist*: {registered} typosquatting domains registered")
        else:
            lines.append("🕵️ *dnstwist*: No similar domains registered.")
    else:
        lines.append("🕵️ *dnstwist*: Not run.")
    if "metagoofil" in results:
        if "No metadata" in results.get("metagoofil", ""):
            lines.append("📄 *Metagoofil*: No metadata leaks found.")
        else:
            lines.append("📄 *Metagoofil*: Document metadata leaks found")
    else:
        lines.append("📄 *Metagoofil*: Not run.")
    if "sherlock" in results:
        found = len(re.findall(r"\[\+\] (.*)", results.get("sherlock", "")))
        if found:
            lines.append(f"👥 *Sherlock*: {found} social media accounts found")
        else:
            lines.append("👥 *Sherlock*: No accounts found.")
    else:
        lines.append("👥 *Sherlock*: Not run.")
    lines.append("")
    if detailed:
        lines.append("")
        lines.append("📋 *DETAILED PAID REPORT*")
        for tool_name, raw in results.items():
            if raw and raw not in ("No email", "No results"):
                lines.append(f"\n🛠 *{tool_name} raw excerpt:*\n```{re.sub(r"\x1b\[[0-9;]*m", "", str(raw))[:300]}```")
        lines.append("\n⚠️ For compliance mapping & exploitation proof, contact admin.")
    else:
        lines.append("")
        lines.append("⚠️ This is a FREE summary. Upgrade to Monthly/Enterprise for full reports, compliance mapping, and exploitation proof. Contact admin to upgrade.")
    # Add compliance status for detailed reports
    if detailed:
        from bot.reports import COMPLIANCE
        lines.append("")
        lines.append("📜 *Compliance Status*")
        for category, rules in COMPLIANCE.items():
            status = "✅"
            if category == "xss" and "dalfox" in results and "vulnerable" in results.get("dalfox", "").lower():
                status = "❌"
            elif category == "open_port" and "open" in str(results.get("nmap", "")):
                status = "❌"
            elif category == "vulnerable_service" and "VULNERABLE" in str(results.get("nmap", "")):
                status = "❌"
            elif category == "leaked_email" and "theHarvester" in results and "Leaked" in str(results.get("theHarvester", "")):
                status = "❌"
            elif category == "typosquatting" and "dnstwist" in results and "registered" in str(results.get("dnstwist", "")).lower():
                status = "❌"
            elif category == "metadata_leak" and "metagoofil" in results and "No metadata" not in results.get("metagoofil", ""):
                status = "❌"
            elif category == "social_media" and "sherlock" in results and "accounts found" in str(results.get("sherlock", "")):
                status = "❌"
            lines.append(f"{status} {category}: PCI {rules['pci']} / HIPAA {rules['hipaa']}")
        lines.append("")
        lines.append("⚠️ For full compliance documentation, contact admin.")
    else:
        lines.append("")
        lines.append("⚠️ This is a FREE summary. Upgrade to Monthly/Enterprise for detailed reports with compliance mapping and exploitation proof.")

    return "\n".join(lines)

# Compliance mapping
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


