"""Professional report – handles all elite tools."""
import re, json, traceback
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

    # Nmap
    if 'nmap' in results:
        open_ports = len(re.findall(r"^\d+/tcp\s+open\s+", results.get('nmap',''), re.MULTILINE))
        vulns = len(re.findall(r"\|.*VULNERABLE.*", results.get('nmap','')))
        score += (open_ports * 5) + (vulns * 15)
        max_score += (10 * 5) + (10 * 15)

    # Nikto
    if 'nikto' in results:
        issues = len(re.findall(r"\+ (.*)", results.get('nikto','')))
        score += issues * 10
        max_score += 10 * 10

    # theHarvester
    if 'theHarvester' in results and results['theHarvester'] != "No email":
        harvest = results['theHarvester']
        if "<html" in harvest.lower():
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", harvest)
            score += len(emails) * 10
            max_score += 20 * 10

    # dnstwist
    if 'dnstwist' in results:
        registered = len(re.findall(r"^([^ ]+)\s+registered.*", results.get('dnstwist',''), re.MULTILINE))
        score += registered * 10
        max_score += 10 * 10

    # Metagoofil
    if 'metagoofil' in results and "No metadata" not in results.get('metagoofil',''):
        score += 25
        max_score += 25

    # Sherlock
    if 'sherlock' in results:
        found = len(re.findall(r"\[\+\] (.*)", results.get('sherlock','')))
        score += found * 5
        max_score += 20 * 5

    # Dalfox
    if 'dalfox' in results and "vulnerable" in results.get('dalfox','').lower():
        score += 50
        max_score += 50

    # Nuclei (count distinct findings)
    if 'nuclei' in results and results['nuclei']:
        try:
            nuclei_data = json.loads(results['nuclei']) if isinstance(results['nuclei'], str) else results['nuclei']
            if isinstance(nuclei_data, list):
                nuclei_count = len(nuclei_data)
                score += nuclei_count * 20
                max_score += 10 * 20
        except:
            pass

    # FFUF (each hidden path is a mild risk)
    if 'ffuf' in results:
        paths = results['ffuf'].strip().split('\n') if results['ffuf'].strip() else []
        if paths:
            score += len(paths) * 3
            max_score += 50 * 3

    # Subfinder (subdomains increase attack surface)
    if 'subfinder' in results:
        subs = results['subfinder'].strip().split('\n') if results['subfinder'].strip() else []
        real_subs = [s for s in subs if s and not s.startswith('[')]
        score += len(real_subs) * 2
        max_score += 20 * 2

    # Subfinder + MassDNS
    if 'subfinder_massdns' in results:
        subs = results['subfinder_massdns'].strip().split('\n') if results['subfinder_massdns'].strip() else []
        score += len(subs) * 2
        max_score += 20 * 2

    # SpiderFoot (OSINT intelligence records)
    if 'spiderfoot' in results:
        sf = results['spiderfoot']
        if isinstance(sf, list):
            score += len(sf) * 3
            max_score += 50 * 3

    # ReconSpider (raw findings)
    if 'reconspider' in results and results['reconspider']:
        raw = results['reconspider']
        if raw and not raw.startswith("[!]"):
            lines_found = len(raw.split('\n'))
            score += lines_found * 2
            max_score += 100 * 2

    # Prowler (failed cloud checks are serious)
    if 'prowler' in results:
        prow = results['prowler']
        if isinstance(prow, list):
            failed = sum(1 for f in prow if f.get('Status') == 'FAIL')
            score += failed * 15
            max_score += 20 * 15

    if max_score == 0:
        return 0, "LOW"

    percent = min(100, int((score / max_score) * 100))
    if percent < 20:
        level = "LOW"
    elif percent < 50:
        level = "MEDIUM"
    elif percent < 80:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return percent, level

def clean_ansi(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", text)

def safe_code_block(content, max_len=None):
    """Return a Markdown code block with sanitised content."""
    safe = content.replace("```", "'''")
    if max_len and len(safe) > max_len:
        safe = safe[:max_len]
    return "```\n" + safe + "\n```"

def build_report_markdown(domain, results, detailed=False, deep=False, show_compliance=True):
    score, level = compute_threat_score(results)
    risk_emoji = {"LOW":"🟢","MEDIUM":"🟡","HIGH":"🟠","CRITICAL":"🔴"}.get(level,"⚪")

    lines = []
    lines.append(f"🔍 Scan completed for {domain}")
    lines.append("")
    lines.append(f"{risk_emoji} Threat Score: {score}/100  |  Risk Level: {level}")
    if deep: lines.append("🔬 Deep Scan Report")
    else: lines.append("ℹ️ Standard Scan – Upgrade to Enterprise for deep scanning.")
    lines.append("")
    lines.append("━━━━━━━━━━━━━━━━━━")

    # Brief summary – keep all existing summary lines as you had them (they work)
    # (Paste your existing summary lines here – they are correct)
    if 'nmap' in results:
        ports = len(re.findall(r"^\d+/tcp\s+open\s+", results.get("nmap",""), re.MULTILINE))
        vulns = len(re.findall(r"\|.*VULNERABLE.*", results.get("nmap","")))
        lines.append(f"🛡️ Nmap: {ports} open ports, {vulns} potential vulns")
    if 'nikto' in results:
        issues = len(re.findall(r"\+ (.*)", results.get("nikto","")))
        lines.append(f"🔥 Nikto: {issues} web issues")
    if 'whatweb' in results:
        clean = re.sub(r"\x1b\[[0-9;]*m", "", results.get("whatweb",""))
        servers = re.findall(r"HTTPServer\[(.*?)\]", clean)
        lines.append(f"🧩 Technology: {servers[0] if servers else 'No server header'}")
    if 'theHarvester' in results:
        harvest = results["theHarvester"]
        if harvest == "No email": lines.append("📧 theHarvester: No email set – skipped.")
        elif "<html" in harvest.lower():
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", harvest)
            lines.append(f"📧 theHarvester: {len(emails)} leaked emails found")
    if 'dnstwist' in results:
        registered = len(re.findall(r"^([^ ]+)\s+registered.*", results.get("dnstwist",""), re.MULTILINE))
        lines.append(f"🕵️ dnstwist: {registered} typosquatting domains registered (other permutations not live)")
    if 'metagoofil' in results:
        if "No metadata" in results.get("metagoofil",""): lines.append("📄 Metagoofil: No metadata leaks")
        else: lines.append("📄 Metagoofil: Metadata leaks found")
    if 'sherlock' in results:
        found = len(re.findall(r"\[\+\] (.*)", results.get("sherlock","")))
        lines.append(f"👥 Sherlock: {found} social accounts found")
    if 'dalfox' in results:
        if "vulnerable" in results.get('dalfox', '').lower():
            lines.append("🦠 Dalfox: XSS vulnerabilities detected!")
        else:
            lines.append("🦠 Dalfox: No XSS found.")
    if 'nuclei' in results and results['nuclei'] and "Error" not in str(results['nuclei']) and results['nuclei'].strip():
        lines.append("🧬 Nuclei: Vulnerabilities detected (see detailed report)")
    if 'subfinder' in results:
        subs = results['subfinder'].strip().split('\n') if results['subfinder'].strip() else []
        real_subs = [s for s in subs if s and not s.startswith('[') and s != domain]
        if real_subs: lines.append(f"🌐 Subfinder: {len(real_subs)} subdomains discovered")
        else: lines.append("🌐 Subfinder: No subdomains found.")
    if 'ffuf' in results:
        paths = results['ffuf'].strip().split('\n') if results['ffuf'].strip() else []
        if paths: lines.append(f"🌀 FFUF: {len(paths)} hidden paths discovered")
        else: lines.append("🌀 FFUF: No hidden paths found.")
    if 'subfinder_massdns' in results:
        subs = results['subfinder_massdns'].strip().split('\n') if results['subfinder_massdns'].strip() else []
        if subs: lines.append(f"📡 Subdomain Discovery: {len(subs)} live subdomains")
        else: lines.append("📡 Subdomain Discovery: No live subdomains.")
    if 'spiderfoot' in results:
        sf = results['spiderfoot']
        if isinstance(sf, list):
            lines.append(f"🕸️ SpiderFoot: {len(sf)} intelligence records")
        elif isinstance(sf, dict) and 'error' in sf:
            lines.append(f"🕸️ SpiderFoot: {sf['error']}")
        else:
            lines.append("🕸️ SpiderFoot: Scan completed (see detailed report)")
    if 'reconspider' in results:
        raw = results['reconspider']
        if raw and not raw.startswith("[!]"):
            lines.append("🕷️ ReconSpider: Investigation completed")
        else:
            lines.append("🕷️ ReconSpider: No findings")
    if 'prowler' in results:
        prow = results['prowler']
        if isinstance(prow, list):
            failed = sum(1 for f in prow if f.get('Status') == 'FAIL')
            lines.append(f"☁️ Prowler: {failed}/{len(prow)} checks failed")
        elif isinstance(prow, dict) and 'error' in prow:
            lines.append(f"☁️ Prowler: {prow['error']}")
        else:
            lines.append("☁️ Prowler: Audit completed (see detailed report)")

    # Detailed paid report
    if detailed:
        lines.append("")
        lines.append("━━━━━━━━━━━━━━━━━━")
        lines.append("📋 DETAILED PAID REPORT")
        lines.append("━━━━━━━━━━━━━━━━━━")

        tools = [
            ("🛡️ Nmap", 'nmap'),
            ("🔥 Nikto", 'nikto'),
            ("🧩 WhatWeb", 'whatweb'),
            ("📧 theHarvester", 'theHarvester'),
            ("🕵️ dnstwist", 'dnstwist'),
            ("📄 Metagoofil", 'metagoofil'),
            ("👥 Sherlock", 'sherlock'),
            ("🦠 Dalfox", 'dalfox'),
            ("🌐 Subfinder", 'subfinder'),
            ("🌀 FFUF Hidden Paths", 'ffuf'),
            ("📡 Subdomain Discovery", 'subfinder_massdns'),
            ("🕸️ SpiderFoot", 'spiderfoot'),
            ("🕷️ ReconSpider", 'reconspider'),
            ("☁️ Prowler", 'prowler'),
        ]
        for label, key in tools:
            if key in results and "Error" not in str(results.get(key, "")):
                raw = results[key]

                # Tool‑specific handling (full output, no slicing)
                if key == "reconspider" and isinstance(raw, str):
                    if raw.strip().startswith("__________"):
                        snippet = "No findings."
                    else:
                        snippet = clean_ansi(raw) if raw.strip() else "No findings."
                elif key == "dnstwist":
                    lines_raw = raw.strip().split('\n')
                    registered = [l for l in lines_raw if "registered" in l]
                    snippet = "\n".join(registered) if registered else "No typosquatting domains registered."
                elif key == "subfinder":
                    lines_raw = raw.strip().split('\n')
                    real_subs = [l for l in lines_raw if l and not l.startswith('[') and l != domain]
                    snippet = "\n".join(real_subs) if real_subs else "No live subdomains found."
                elif key == "spiderfoot":
                    if isinstance(raw, dict) and "error" in raw:
                        snippet = raw["error"]
                    elif isinstance(raw, list):
                        snippet = json.dumps(raw, indent=2) if raw else "No findings."
                    else:
                        snippet = clean_ansi(str(raw)) if raw else "No findings."
                elif key == "prowler":
                    if isinstance(raw, dict) and raw.get("status") == "skipped":
                        snippet = raw.get("message", "Cloud audit skipped.")
                    else:
                        snippet = json.dumps(raw, indent=2) if isinstance(raw, (dict, list)) else clean_ansi(str(raw))
                elif isinstance(raw, (dict, list)):
                    snippet = json.dumps(raw, indent=2)
                else:
                    snippet = clean_ansi(str(raw)) if raw else "No findings."

                # Wrap in code block (no max length limit)
                lines.append(label)
                lines.append("```")
                lines.append(snippet.replace("```", "'''"))
                lines.append("```")

        # Nuclei explicit block (always show if run)
        if 'nuclei' in results:
            nuclei_out = results['nuclei']
            if not nuclei_out or "Error" in nuclei_out:
                nuclei_text = "No vulnerabilities detected – target may be behind Cloudflare/WAF (403 Forbidden) or no issues found."
            else:
                nuclei_text = clean_ansi(nuclei_out).replace("```", "'''")[:500]
            lines.append("🧬 Nuclei Findings")
            lines.append(safe_code_block(nuclei_text))

        # Compliance table (only for full scans)
        if show_compliance:
            lines.append("")
            lines.append("📜 Compliance")
            compliance_lines = ["COMPLIANCE STATUS"]
            for category, rules in COMPLIANCE.items():
                status = "✅"
                if category == "xss" and "dalfox" in results and "vulnerable" in results.get("dalfox","").lower(): status = "❌"
                elif category == "open_port" and "open" in str(results.get("nmap","")): status = "❌"
                elif category == "vulnerable_service" and "VULNERABLE" in str(results.get("nmap","")): status = "❌"
                elif category == "leaked_email" and "theHarvester" in results and "Leaked" in str(results.get("theHarvester","")): status = "❌"
                elif category == "typosquatting" and "dnstwist" in results and "registered" in str(results.get("dnstwist","")).lower(): status = "❌"
                elif category == "metadata_leak" and "metagoofil" in results and "No metadata" not in results.get("metagoofil",""): status = "❌"
                elif category == "social_media" and "sherlock" in results and "accounts found" in str(results.get("sherlock","")): status = "❌"
                compliance_lines.append(f"{status} {category}: PCI {rules['pci']} / HIPAA {rules['hipaa']}")
            lines.append(safe_code_block("\n".join(compliance_lines)))
            lines.append("")
            lines.append("⚠️ For full compliance documentation, contact admin.")
    else:
        lines.append("")
        lines.append(f"⚠️ This is a FREE summary. Upgrade for detailed reports.\nContact admin: @{ADMIN_USERNAME}")

    return "\n".join(lines)
