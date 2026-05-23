#!/usr/bin/env python3
"""Remove PDF generation, add detailed in-chat reports for paying clients."""

import re

with open("phantomwatch.py", "r") as f:
    content = f.read()

# ---- 1. Remove PDF imports ----
content = re.sub(r'from fpdf import FPDF\n', '', content)
content = re.sub(r'from fpdf\.enums import XPos, YPos\n', '', content)

# ---- 2. Remove generate_pdf_report function (from def to next top-level def) ----
content = re.sub(
    r'def generate_pdf_report\(domain, results, plan\):.*?(?=\n(?:def |# -))',
    '',
    content,
    flags=re.DOTALL
)

# ---- 3. Remove the PDF sending block in SCAN_DOMAIN ----
old_pdf_block = """            # PDF for monthly/enterprise ONLY
            if plan in ("monthly", "enterprise"):
                try:
                    pdf_buf = generate_pdf_report(domain, results, plan)
                    pdf_buf.name = f"PhantomWatch-{domain}-report.pdf"
                    await context.bot.send_document(chat_id=chat_id, document=pdf_buf, caption="📎 Detailed compliance report")
                except Exception as e:
                    await context.bot.send_message(chat_id=chat_id, text=f"⚠️ PDF generation failed: {e}")"""
new_pdf_block = "            # Detailed report is sent immediately above (no PDF)"
content = content.replace(old_pdf_block, new_pdf_block)

# ---- 4. Upgrade format_summary to accept a 'detailed' flag ----
old_summary_def = "def format_summary(domain, results):"
new_summary_def = "def format_summary(domain, results, detailed=False):"
content = content.replace(old_summary_def, new_summary_def)

# Inside the function, add extra detail when detailed=True
# Find the line where we append the final upgrade note and add detail before it.
old_upgrade_note = '    lines.append("")\n    lines.append("⚠️ This is a FREE summary. Upgrade to Monthly/Enterprise for detailed PDF reports with compliance mapping and exploitation proof.")'
new_upgrade_note = '''    if detailed:
        lines.append("")
        lines.append("📋 *DETAILED REPORT* (Paid Plan)")
        # Add a more granular breakdown for each tool
        for tool_name, raw in results.items():
            if tool_name == "nmap" and raw:
                # Already covered above, but we can add raw output excerpt
                lines.append(f"\\n🛡️ *Nmap Raw Output (excerpt):*\\n```{raw[:300]}```")
            elif tool_name == "nikto" and raw:
                lines.append(f"\\n🔥 *Nikto Raw Output (excerpt):*\\n```{raw[:300]}```")
            elif tool_name == "whatweb" and raw:
                lines.append(f"\\n🧩 *WhatWeb Raw Output:*\\n```{raw[:300]}```")
            elif tool_name == "theHarvester" and raw and raw != "No email":
                lines.append(f"\\n📧 *theHarvester Raw Output:*\\n```{raw[:300]}```")
            elif tool_name == "dnstwist" and raw:
                lines.append(f"\\n🕵️ *dnstwist Raw Output:*\\n```{raw[:300]}```")
            elif tool_name == "metagoofil" and raw and "No metadata" not in raw:
                lines.append(f"\\n📄 *Metagoofil Raw Output:*\\n```{raw[:300]}```")
            elif tool_name == "sherlock" and raw:
                lines.append(f"\\n👥 *Sherlock Raw Output:*\\n```{raw[:300]}```")
        lines.append("")
        lines.append("⚠️ This is a PAID report. For compliance mapping and exploitation proof, contact admin.")
    else:
        lines.append("")
        lines.append("⚠️ This is a FREE summary. Upgrade to Monthly/Enterprise for detailed reports with compliance mapping and exploitation proof.")'''
content = content.replace(old_upgrade_note, new_upgrade_note)

# ---- 5. In the scan completion block, pass detailed=True for paid plans ----
# Find where we call format_summary and modify it
old_summary_call = "            summary = format_summary(domain, results)"
new_summary_call = '''            c.execute("SELECT plan FROM clients WHERE username=?", (username,))
            row = c.fetchone()
            plan = row[0] if row else "free"
            detailed = plan in ("monthly", "enterprise")
            summary = format_summary(domain, results, detailed)'''
content = content.replace(old_summary_call, new_summary_call)

# ---- 6. Remove any leftover XPos/YPos comments ----
content = re.sub(r'# XPos,YPos not needed with multi_cell\n', '', content)

with open("phantomwatch.py", "w") as f:
    f.write(content)

print("✅ PDF removed. Paid clients now receive detailed in-chat reports.")
