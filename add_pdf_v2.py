#!/usr/bin/env python3
"""Add DETAILED PDF reports with compliance mapping. Fix syntax error."""

with open("phantomwatch.py", "r") as f:
    lines = f.readlines()

# ===== 1. Add fpdf2 import after existing imports =====
import_line = None
for i, line in enumerate(lines):
    if "from telegram.ext import" in line:
        import_line = i
        break
if import_line:
    lines.insert(import_line + 5, "from fpdf import FPDF\n")

# ===== 2. Add COMPLIANCE dictionary and DETAILED PDF function before main_menu =====
insert_pos = 136  # 0-indexed, after format_summary and before main_menu

pdf_code = [
    '\n',
    '# Compliance mapping\n',
    'COMPLIANCE = {\n',
    '    "xss": {"pci": "PCI-DSS 6.5.7", "hipaa": "164.308(a)(5)(ii)(B)"},\n',
    '    "sqli": {"pci": "PCI-DSS 6.5.1", "hipaa": "164.308(a)(5)(ii)(B)"},\n',
    '    "open_port": {"pci": "PCI-DSS 1.1.6", "hipaa": "164.308(a)(4)(ii)(B)"},\n',
    '    "vulnerable_service": {"pci": "PCI-DSS 6.1", "hipaa": "164.308(a)(5)(ii)(B)"},\n',
    '    "leaked_email": {"pci": "PCI-DSS 6.5.10", "hipaa": "164.308(a)(5)(ii)(B)"},\n',
    '    "typosquatting": {"pci": "N/A", "hipaa": "164.308(a)(5)(ii)(B)"},\n',
    '    "metadata_leak": {"pci": "PCI-DSS 6.5.9", "hipaa": "164.308(a)(1)(ii)(D)"},\n',
    '    "social_media": {"pci": "N/A", "hipaa": "164.308(a)(5)(ii)(B)"},\n',
    '}\n',
    '\n',
    'def generate_pdf_report(domain, results, plan):\n',
    '    pdf = FPDF()\n',
    '    pdf.add_page()\n',
    '    pdf.add_font("DejaVu", "", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", uni=True)\n',
    '    pdf.add_font("DejaVu", "B", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", uni=True)\n',
    '\n',
    '    pdf.set_font("DejaVu", "B", 16)\n',
    '    pdf.cell(0, 10, "PHANTOM WATCH Security Report", ln=True, align="C")\n',
    '    pdf.set_font("DejaVu", "", 10)\n',
    '    pdf.cell(0, 10, f"Domain: {domain}", ln=True)\n',
    '    pdf.cell(0, 10, f"Date: {datetime.now().strftime(\'%Y-%m-%d %H:%M\')}", ln=True)\n',
    '    pdf.ln(5)\n',
    '\n',
    '    # ---- DETAILED FINDINGS ----\n',
    '    pdf.set_font("DejaVu", "B", 12)\n',
    '    pdf.cell(0, 10, "Detailed Findings", ln=True)\n',
    '    pdf.set_font("DejaVu", "", 9)\n',
    '\n',
    '    # Nmap\n',
    '    if \'nmap\' in results:\n',
    '        raw = results[\'nmap\']\n',
    '        open_ports = re.findall(r"^\\d+/tcp\\s+open\\s+(.*)", raw, re.MULTILINE)\n',
    '        vulns = re.findall(r"\\|.*VULNERABLE.*", raw)\n',
    '        if open_ports:\n',
    '            pdf.set_font("DejaVu", "B", 10)\n',
    '            pdf.cell(0, 6, "Open Ports:", ln=True)\n',
    '            pdf.set_font("DejaVu", "", 9)\n',
    '            for p in open_ports[:10]:\n',
    '                pdf.multi_cell(0, 5, f"• {p}")\n',
    '        if vulns:\n',
    '            pdf.set_font("DejaVu", "B", 10)\n',
    '            pdf.cell(0, 6, "Potential Vulnerabilities:", ln=True)\n',
    '            pdf.set_font("DejaVu", "", 9)\n',
    '            for v in vulns[:5]:\n',
    '                pdf.multi_cell(0, 5, f"• {v.strip()}")\n',
    '        if not open_ports and not vulns:\n',
    '            pdf.cell(0, 6, "No open ports or vulnerabilities detected.", ln=True)\n',
    '\n',
    '    # Nikto\n',
    '    if \'nikto\' in results:\n',
    '        findings = re.findall(r"\\+ (.*)", results[\'nikto\'])\n',
    '        if findings:\n',
    '            pdf.set_font("DejaVu", "B", 10)\n',
    '            pdf.cell(0, 6, "Web Application Issues:", ln=True)\n',
    '            pdf.set_font("DejaVu", "", 9)\n',
    '            for f in findings[:10]:\n',
    '                pdf.multi_cell(0, 5, f"• {f}")\n',
    '        else:\n',
    '            pdf.cell(0, 6, "No web application issues found.", ln=True)\n',
    '\n',
    '    # WhatWeb\n',
    '    if \'whatweb\' in results:\n',
    '        clean = re.sub(r\'\\x1b\\[[0-9;]*m\', \'\', results[\'whatweb\'])\n',
    '        pdf.cell(0, 6, f"Technology: {clean[:200]}", ln=True)\n',
    '\n',
    '    # theHarvester\n',
    '    if \'theHarvester\' in results and results[\'theHarvester\'] != "No email":\n',
    '        harvest = results[\'theHarvester\']\n',
    '        if "<html" in harvest.lower():\n',
    '            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", harvest)\n',
    '            if emails:\n',
    '                pdf.set_font("DejaVu", "B", 10)\n',
    '                pdf.cell(0, 6, f"Leaked Emails ({len(emails)}):", ln=True)\n',
    '                pdf.set_font("DejaVu", "", 9)\n',
    '                pdf.multi_cell(0, 5, ", ".join(emails[:10]))\n',
    '\n',
    '    # dnstwist\n',
    '    if \'dnstwist\' in results:\n',
    '        registered = re.findall(r"^([^ ]+)\\s+registered.*", results[\'dnstwist\'], re.MULTILINE)\n',
    '        if registered:\n',
    '            pdf.set_font("DejaVu", "B", 10)\n',
    '            pdf.cell(0, 6, "Typosquatting Domains:", ln=True)\n',
    '            pdf.set_font("DejaVu", "", 9)\n',
    '            for d in registered[:5]:\n',
    '                pdf.multi_cell(0, 5, f"• {d}")\n',
    '\n',
    '    # Metagoofil\n',
    '    if \'metagoofil\' in results and "No metadata" not in results.get(\'metagoofil\',\'\'):\n',
    '        pdf.set_font("DejaVu", "B", 10)\n',
    '        pdf.cell(0, 6, "Document Metadata Leaks:", ln=True)\n',
    '        pdf.set_font("DejaVu", "", 9)\n',
    '        pdf.multi_cell(0, 5, results[\'metagoofil\'][:500])\n',
    '\n',
    '    # Sherlock\n',
    '    if \'sherlock\' in results:\n',
    '        found = re.findall(r"\\[\\+\\] (.*)", results[\'sherlock\'])\n',
    '        if found:\n',
    '            pdf.set_font("DejaVu", "B", 10)\n',
    '            pdf.cell(0, 6, "Social Media Accounts:", ln=True)\n',
    '            pdf.set_font("DejaVu", "", 9)\n',
    '            for f in found[:10]:\n',
    '                pdf.multi_cell(0, 5, f"• {f}")\n',
    '\n',
    '    # ---- COMPLIANCE TABLE ----\n',
    '    pdf.ln(5)\n',
    '    pdf.set_font("DejaVu", "B", 12)\n',
    '    pdf.cell(0, 10, "Compliance Status", ln=True)\n',
    '    pdf.set_font("DejaVu", "", 9)\n',
    '    for category, rules in COMPLIANCE.items():\n',
    '        if category == "xss" and \'dalfox\' in results and "vulnerable" in results.get(\'dalfox\',\'\').lower():\n',
    '            status = "❌"\n',
    '        elif category == "open_port" and any("open" in str(results.get(\'nmap\',\'\'))):\n',
    '            status = "❌"\n',
    '        elif category == "vulnerable_service" and any("VULNERABLE" in str(results.get(\'nmap\',\'\'))):\n',
    '            status = "❌"\n',
    '        elif category == "leaked_email" and \'theHarvester\' in results and "Leaked" in str(results.get(\'theHarvester\',\'\')):\n',
    '            status = "❌"\n',
    '        else:\n',
    '            status = "✅"\n',
    '        pdf.cell(0, 6, f"{status} {category}: PCI {rules[\'pci\']} / HIPAA {rules[\'hipaa\']}", ln=True)\n',
    '\n',
    '    buf = io.BytesIO()\n',
    '    pdf.output(buf)\n',
    '    buf.seek(0)\n',
    '    return buf\n',
    '\n',
]

for line in reversed(pdf_code):
    lines.insert(insert_pos, line)

# ===== 3. Add "import io" at the top if not already present =====
if "import io" not in "".join(lines):
    for i, line in enumerate(lines):
        if line.startswith("import subprocess"):
            lines[i] = line.replace("import subprocess", "import subprocess, io")
            break

# ===== 4. Modify scan completion to send PDF for monthly/enterprise =====
# Find the line that sends summary and insert PDF sending after it.
target_line = None
for i, line in enumerate(lines):
    if "await context.bot.send_message(chat_id=chat_id, text=summary, parse_mode='Markdown')" in line:
        target_line = i
        break

if target_line:
    pdf_sending_code = [
        '            # Send PDF for monthly/enterprise plans\n',
        '            c.execute("SELECT plan FROM clients WHERE username=?", (username,))\n',
        '            row = c.fetchone()\n',
        '            plan = row[0] if row else "free"\n',
        '            if plan in ("monthly", "enterprise"):\n',
        '                try:\n',
        '                    pdf_buf = generate_pdf_report(domain, results, plan)\n',
        '                    pdf_buf.name = f"PhantomWatch-{domain}-report.pdf"\n',
        '                    await context.bot.send_document(chat_id=chat_id, document=pdf_buf, caption="📎 Detailed compliance report")\n',
        '                except Exception as e:\n',
        '                    await context.bot.send_message(chat_id=chat_id, text=f"⚠️ PDF generation failed: {e}")\n',
    ]
    for line in reversed(pdf_sending_code):
        lines.insert(target_line + 1, line)

with open("phantomwatch.py", "w") as f:
    f.writelines(lines)

print("✅ DETAILED PDF reports with full findings & compliance mapping added.")
