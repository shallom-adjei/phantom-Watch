"""Professional terminal‑style report with detailed exploitation/remediation for paid users."""
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

def detailed_findings_plain(results):
    """Return list of plain‑text finding lines (exploitation & remediation)."""
    lines = []
    if 'nmap' in results:
        open_ports = re.findall(r"^\d+/tcp\s+open\s+(.*)", results['nmap'], re.MULTILINE)
        vulns = re.findall(r"\|.*VULNERABLE.*", results['nmap'])
        if open_ports or vulns:
            lines.append("[NMAP]")
            if open_ports:
                lines.append("  Open Ports:")
                for p in open_ports[:5]:
                    lines.append(f"    - {p}")
            if vulns:
                lines.append("  Vulnerabilities:")
                for v in vulns[:5]:
                    lines.append(f"    - {v.strip()}")
            lines.append("  Exploit: Brute‑force, outdated services, remote code execution.")
            lines.append("  Fix: Close unused ports, firewall, apply patches.\n")
        else:
            lines.append("[NMAP] No open ports or vulns detected.\n")

    if 'nikto' in results:
        issues = re.findall(r"\+ (.*)", results['nikto'])
        if issues:
            lines.append("[NIKTO]")
            for i in issues[:5]:
                lines.append(f"  - {i}")
            lines.append("  Exploit: Injection, data leak, defacement.")
            lines.append("  Fix: Update CMS/plugins, add CSP/X‑Frame‑Options.\n")
        else:
            lines.append("[NIKTO] No web issues found.\n")

    if 'theHarvester' in results and results['theHarvester'] != "No email":
        harvest = results['theHarvester']
        if "<html" in harvest.lower():
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", harvest)
            if emails:
                lines.append("[EMAIL]")
                lines.append(f"  Leaked Emails: {len(emails)}")
                lines.append(f"  {', '.join(emails[:5])}")
                lines.append("  Exploit: Phishing, credential stuffing.")
                lines.append("  Fix: SPF/DKIM/DMARC, staff training.\n")

    if 'dnstwist' in results:
        registered = re.findall(r"^([^ ]+)\s+registered.*", results['dnstwist'], re.MULTILINE)
        if registered:
            lines.append("[TYPO]")
            lines.append("  Squatting domains:")
            for d in registered[:5]:
                lines.append(f"    - {d}")
            lines.append("  Exploit: Phishing, credential theft.")
            lines.append("  Fix: Monitor registrations, buy variants.\n")
        else:
            lines.append("[TYPO] No typosquatting domains.\n")

    if 'metagoofil' in results and "No metadata" not in results.get('metagoofil',''):
        lines.append("[META] Metadata leaks found.")
        lines.append("  Exploit: Internal path/software exposure.")
        lines.append("  Fix: Strip metadata before publishing.\n")
    else:
        lines.append("[META] No metadata leaks.\n")

    if 'sherlock' in results:
        found = re.findall(r"\[\+\] (.*)", results['sherlock'])
        if found:
            lines.append("[SOCIAL]")
            lines.append("  Accounts found:")
            for f in found[:5]:
                lines.append(f"    - {f}")
            lines.append("  Exploit: Impersonation, social engineering.")
            lines.append("  Fix: Enable 2FA, review privacy settings.\n")
        else:
            lines.append("[SOCIAL] No social accounts found.\n")

    if 'dalfox' in results and "vulnerable" in results['dalfox'].lower():
        lines.append("[XSS] XSS vulnerabilities detected!")
        lines.append("  Exploit: Inject malicious scripts.")
        lines.append("  Fix: Sanitise input, use Content‑Security‑Policy.\n")

    return lines

def format_summary(domain, results, detailed=False):
    """Build the terminal‑style report in a single code block."""
    score, level = compute_threat_score(results)
    risk_emoji = {"LOW":"🟢","MEDIUM":"🟡","HIGH":"🟠","CRITICAL":"🔴"}.get(level,"⚪")

    lines = []
    lines.append("```")
    lines.append(f"PHANTOM WATCH SCAN REPORT")
    lines.append(f"Domain : {domain}")
    lines.append(f"Date   : {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"Score  : {score}/100 ({level}) {risk_emoji}")
    lines.append("=" * 40)

    # Compact summary
    if 'nmap' in results:
        ports = len(re.findall(r"^\d+/tcp\s+open\s+", results.get("nmap",""), re.MULTILINE))
        vulns = len(re.findall(r"\|.*VULNERABLE.*", results.get("nmap","")))
        lines.append(f"[nmap]   ports: {ports}, vulns: {vulns}")
    if 'nikto' in results:
        issues = len(re.findall(r"\+ (.*)", results.get("nikto","")))
        lines.append(f"[nikto]  issues: {issues}")
    if 'whatweb' in results:
        clean = re.sub(r"\x1b\[[0-9;]*m", "", results.get("whatweb",""))
        server = re.findall(r"HTTPServer\[ (.*?) \]", clean)
        lines.append(f"[whatweb] server: {server[0] if server else 'unknown'}")
    if 'theHarvester' in results:
        if results['theHarvester'] == "No email":
            lines.append("[harvester] skipped (no email)")
        else:
            harvest = results['theHarvester']
            if "<html" in harvest.lower():
                emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", harvest)
                lines.append(f"[harvester] emails: {len(emails)}")
            else:
                lines.append("[harvester] no results")
    if 'dnstwist' in results:
        registered = len(re.findall(r"^([^ ]+)\s+registered.*", results.get("dnstwist",""), re.MULTILINE))
        lines.append(f"[dnstwist] domains: {registered}")
    if 'metagoofil' in results:
        if "No metadata" in results.get("metagoofil",""):
            lines.append("[metagoofil] no leaks")
        else:
            lines.append("[metagoofil] leaks found")
    if 'sherlock' in results:
        found = len(re.findall(r"\[\+\] (.*)", results.get("sherlock","")))
        lines.append(f"[sherlock] accounts: {found}")
    if 'dalfox' in results and "vulnerable" in results['dalfox'].lower():
        lines.append("[dalfox] XSS found!")

    lines.append("")

    if detailed:
        # Detailed exploitation/remediation
        lines.extend(detailed_findings_plain(results))
        # Compliance
        lines.append("[COMPLIANCE]")
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
            lines.append(f"  {status} {category}: PCI {rules['pci']} / HIPAA {rules['hipaa']}")
        lines.append("")
        lines.append("⚠ For full compliance documentation, contact admin.")
    else:
        lines.append("ℹ FREE summary. Upgrade for detailed findings & compliance mapping.")
        lines.append(f"  Contact admin: @{ADMIN_USERNAME}")

    lines.append("```")
    return "\n".join(lines)
