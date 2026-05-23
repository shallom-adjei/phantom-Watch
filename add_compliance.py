#!/usr/bin/env python3
import re
with open("bot/reports.py", "r") as f:
    content = f.read()

# Insert compliance table generation right before the final return in format_summary
old_return = '    return "\\n".join(lines)'
new_return = '''    # Add compliance status for detailed reports
    if detailed:
        from bot.reports import COMPLIANCE
        lines.append("")
        lines.append("📜 *Compliance Status*")
        for category, rules in COMPLIANCE.items():
            status = "✅"
            if category == "xss" and "dalfox" in results and "vulnerable" in results.get("dalfox", "").lower():
                status = "❌"
            elif category == "open_port" and any("open" in str(results.get("nmap", ""))):
                status = "❌"
            elif category == "vulnerable_service" and any("VULNERABLE" in str(results.get("nmap", ""))):
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

    return "\\n".join(lines)'''

content = content.replace(old_return, new_return)
with open("bot/reports.py", "w") as f:
    f.write(content)
print("✅ Compliance status now shown in detailed reports.")
