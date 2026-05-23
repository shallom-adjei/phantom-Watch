#!/usr/bin/env python3
import re
with open("bot/reports.py", "r") as f:
    content = f.read()

# Remove the raw-excerpt block that is currently injected for detailed reports
# We'll replace the entire if detailed: ... else: ... block with a simple compliance addition.
old_detail_block = '''    if detailed:
        lines.append("")
        lines.append("📋 *DETAILED PAID REPORT*")
        for tool_name, raw in results.items():
            if raw and raw not in ("No email", "No results"):
                lines.append(f"\\n🛠 *{tool_name} raw excerpt:*\\n```{re.sub(r\"\\x1b\\[[0-9;]*m\", \"\", str(raw).replace('```', \"'''\"))[:300]}```")
        lines.append("\\n⚠️ For compliance mapping & exploitation proof, contact admin.")
    else:
        lines.append("")
        lines.append("⚠️ This is a FREE summary. Upgrade to Monthly/Enterprise for detailed reports with compliance mapping and exploitation proof. Contact admin to upgrade.")

    return "\\n".join(lines)'''

new_detail_block = '''    # Add compliance status for detailed reports
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
        lines.append("⚠️ This is a FREE summary. Upgrade to Monthly/Enterprise for detailed reports with compliance mapping and exploitation proof. Contact admin to upgrade.")

    return "\\n".join(lines)'''

content = content.replace(old_detail_block, new_detail_block)
with open("bot/reports.py", "w") as f:
    f.write(content)
print("✅ Report style restored – clean summary + compliance table for paid users.")
