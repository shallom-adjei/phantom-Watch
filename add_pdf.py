#!/usr/bin/env python3
"""Add PDF report generation and compliance mapping to phantomwatch.py"""

with open("phantomwatch.py", "r") as f:
    lines = f.readlines()

# ===== 1. Add fpdf2 import after existing imports =====
# Find the line with "import telegram.error" or similar, and add after it
import_line = None
for i, line in enumerate(lines):
    if "from telegram.ext import" in line:
        import_line = i
        break
if import_line:
    # Insert after the last import line (just before the CONFIG section)
    lines.insert(import_line + 5, "from fpdf import FPDF\n")

# ===== 2. Add COMPLIANCE dictionary and PDF function before main_menu =====
# We'll insert them right before line 137 (def main_menu)
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
    '    # Use DejaVu fonts (system-installed)\n',
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
    '    # Findings summary\n',
    '    findings = []\n',
    '    if \'nmap\' in results:\n',
    '        vulns = len(re.findall(r"\\|.*VULNERABLE.*", results.get(\'nmap\',\'\')))\n',
    '        ports = len(re.findall(r"^\\d+/tcp\\s+open\\s+", results.get(\'nmap\',\'\'), re.MULTILINE))\n',
    '        if ports: findings.append(f"{ports} open ports")\n',
    '        if vulns: findings.append(f"{vulns} vulnerabilities")\n',
    '    if \'nikto\' in results:\n',
    '        issues = len(re.findall(r"\\+ (.*)", results.get(\'nikto\',\'\')))\n',
    '        if issues: findings.append(f"{issues} web issues")\n',
    '    if \'dalfox\' in results and "vulnerable" in results.get(\'dalfox\',\'\').lower():\n',
    '        findings.append("XSS vulnerabilities detected")\n',
    '    pdf.set_font("DejaVu", "B", 12)\n',
    '    pdf.cell(0, 10, "Findings Summary", ln=True)\n',
    '    pdf.set_font("DejaVu", "", 10)\n',
    '    for f in findings:\n',
    '        pdf.cell(0, 6, f"• {f}", ln=True)\n',
    '\n',
    '    # Compliance table\n',
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

# Insert the new code
for line in reversed(pdf_code):
    lines.insert(insert_pos, line)

# ===== 3. Add "import io" at the top if not already present =====
if "import io" not in "".join(lines):
    for i, line in enumerate(lines):
        if line.startswith("import subprocess"):
            lines[i] = line.replace("import subprocess", "import subprocess, io")
            break

# ===== 4. Modify the scan completion block to send PDF for monthly/enterprise =====
# Find the lines that send the summary and add PDF sending after it.
# We'll locate "summary = format_summary(domain, results)" and insert after the block.
target_line = None
for i, line in enumerate(lines):
    if 'await context.bot.send_message(chat_id=chat_id, text=summary, parse_mode='Markdown')' in line:
        target_line = i
        break

if target_line:
    # Insert after that line (i+1)
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

# Save
with open("phantomwatch.py", "w") as f:
    f.writelines(lines)

print("✅ PDF reports with compliance mapping added. Monthly/Enterprise clients will now receive PDFs.")
