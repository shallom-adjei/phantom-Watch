#!/usr/bin/env python3
"""Replace the format_summary function with a full-tool version."""
import re

with open("phantomwatch.py", "r") as f:
    content = f.read()

# Pattern to match the entire format_summary function (from def to the next def at top-level)
pattern = r'def format_summary\(domain, results\):.*?(?=\n(?:async )?def )'
replacement = '''def format_summary(domain, results):
    lines = [f"🔍 Scan completed for {domain}\\n"]
    # Nmap
    if 'nmap' in results:
        ports = len(re.findall(r"^\\d+/tcp\\s+open\\s+", results.get('nmap',''), re.MULTILINE))
        vulns = len(re.findall(r"\\|.*VULNERABLE.*", results.get('nmap','')))
        if ports or vulns:
            lines.append(f"🛡️ Nmap: {ports} open ports, {vulns} potential vulns")
        else:
            lines.append("🛡️ Nmap: No open ports or vulns found.")
    else:
        lines.append("🛡️ Nmap: Not run.")
    # Nikto
    if 'nikto' in results:
        issues = len(re.findall(r"\\+ (.*)", results.get('nikto','')))
        if issues:
            lines.append(f"🔥 Nikto: {issues} web issues")
        else:
            lines.append("🔥 Nikto: No web issues found.")
    else:
        lines.append("🔥 Nikto: Not run.")
    # WhatWeb
    if 'whatweb' in results:
        clean = re.sub(r'\\x1b\\[[0-9;]*m', '', results.get('whatweb',''))
        servers = re.findall(r'HTTPServer\\[ (.*?) \\]', clean)
        if servers:
            lines.append(f"🧩 Technology: {servers[0]}")
        else:
            lines.append("🧩 Technology: No server header detected.")
    else:
        lines.append("🧩 Technology: Not run.")
    # theHarvester
    if 'theHarvester' in results:
        harvest = results['theHarvester']
        if harvest == "No email":
            lines.append("📧 theHarvester: No email set – skipped.")
        elif "<html" in harvest.lower():
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", harvest)
            if emails:
                lines.append(f"📧 Emails leaked: {len(emails)}")
            else:
                lines.append("📧 theHarvester: No leaked emails found.")
        else:
            lines.append("📧 theHarvester: No results.")
    else:
        lines.append("📧 theHarvester: Not run.")
    # dnstwist
    if 'dnstwist' in results:
        registered = len(re.findall(r"^([^ ]+)\\s+registered.*", results.get('dnstwist',''), re.MULTILINE))
        if registered:
            lines.append(f"🕵️ Typosquatting: {registered} domains registered")
        else:
            lines.append("🕵️ Typosquatting: No similar domains registered.")
    else:
        lines.append("🕵️ dnstwist: Not run.")
    # Metagoofil
    if 'metagoofil' in results:
        if "No metadata" in results.get('metagoofil',''):
            lines.append("📄 Metagoofil: No metadata leaks found.")
        else:
            lines.append("📄 Document metadata leaks found")
    else:
        lines.append("📄 Metagoofil: Not run.")
    # Sherlock
    if 'sherlock' in results:
        found = len(re.findall(r"\\[\\+\\] (.*)", results.get('sherlock','')))
        if found:
            lines.append(f"👥 Social media: {found} accounts found")
        else:
            lines.append("👥 Social media: No accounts found.")
    else:
        lines.append("👥 Sherlock: Not run.")
    lines.append("\\n⚠️ Upgrade to Monthly/Enterprise for full PDF reports & compliance mapping.")
    return "\\n".join(lines)'''

new_content, count = re.subn(pattern, replacement, content, flags=re.DOTALL)
if count == 0:
    print("❌ Could not find format_summary. Please check the script.")
else:
    with open("phantomwatch.py", "w") as f:
        f.write(new_content)
    print("✅ format_summary replaced with full-tool version.")
