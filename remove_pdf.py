#!/usr/bin/env python3
import re
with open("phantomwatch.py", "r") as f:
    content = f.read()

# 1. Remove FPDF import
content = re.sub(r'from fpdf import FPDF\n', '', content)
content = re.sub(r'from fpdf\.enums import XPos, YPos\n', '', content)

# 2. Remove the generate_pdf_report function (from def to next def)
content = re.sub(r'def generate_pdf_report\(domain, results, plan\):.*?(?=\n(?:def |# -))', '', content, flags=re.DOTALL)

# 3. Remove PDF sending block in SCAN_DOMAIN
old_pdf_block = """            # PDF for monthly/enterprise ONLY
            if plan in ("monthly", "enterprise"):
                try:
                    pdf_buf = generate_pdf_report(domain, results, plan)
                    pdf_buf.name = f"PhantomWatch-{domain}-report.pdf"
                    await context.bot.send_document(chat_id=chat_id, document=pdf_buf, caption="📎 Detailed compliance report")
                except Exception as e:
                    await context.bot.send_message(chat_id=chat_id, text=f"⚠️ PDF generation failed: {e}")"""
content = content.replace(old_pdf_block, "            # PDF reports are available on paid plans.\n            # Contact admin to upgrade.")

# 4. Update the upgrade message in the summary
old_note = "⚠️ This is a FREE summary. Upgrade to Monthly/Enterprise for detailed PDF reports with compliance mapping and exploitation proof."
new_note = "⚠️ This is a FREE summary. Upgrade to Monthly/Enterprise for full reports, compliance mapping, and exploitation proof. Contact admin to upgrade."
content = content.replace(old_note, new_note)

# 5. Remove any leftover XPos/YPos references
content = re.sub(r'# XPos,YPos not needed with multi_cell\n', '', content)

with open("phantomwatch.py", "w") as f:
    f.write(content)
print("✅ PDF generation removed. Bot is now fully stable.")
