#!/usr/bin/env python3
import re

with open("bot/reports.py", "r") as f:
    content = f.read()

# 1. Update the detailed tools loop to show empty blocks
old_loop = '''        for label, key in tools:
            if key in results and results[key] and "Error" not in str(results[key]):
                raw = clean_ansi(results[key])
                if key == "theHarvester" and raw in ("No email", "No results"): continue
                safe = raw.replace("```", "'''")
                snippet = safe[:300]
                lines.append(label)
                lines.append("```")
                lines.append(snippet)
                lines.append("```")'''

new_loop = '''        for label, key in tools:
            if key in results and "Error" not in str(results.get(key, "")):
                raw = clean_ansi(results[key]) if results[key] else ""
                if key == "theHarvester" and raw in ("No email", "No results"): continue
                safe = raw.replace("```", "'''")[:300]
                lines.append(label)
                lines.append("```")
                if safe.strip():
                    lines.append(safe)
                else:
                    lines.append("No findings.")
                lines.append("```")'''

if old_loop in content:
    content = content.replace(old_loop, new_loop)
else:
    print("Old loop not found – may need manual check.")

# 2. Always show Dalfox summary line
old_dalfox = '''    if 'dalfox' in results and "vulnerable" in results['dalfox'].lower():
        lines.append("🦠 Dalfox: XSS vulnerabilities detected!")'''

new_dalfox = '''    if 'dalfox' in results:
        if "vulnerable" in results.get('dalfox', '').lower():
            lines.append("🦠 Dalfox: XSS vulnerabilities detected!")
        else:
            lines.append("🦠 Dalfox: No XSS found.")'''

content = content.replace(old_dalfox, new_dalfox)

# 3. Add show_compliance parameter
old_sig = 'def build_report_markdown(domain, results, detailed=False, deep=False):'
new_sig = 'def build_report_markdown(domain, results, detailed=False, deep=False, show_compliance=True):'
content = content.replace(old_sig, new_sig)

# Wrap compliance table with show_compliance
# find the compliance block start
old_comp = '        # Compliance table'
new_comp = '        if show_compliance:\n            # Compliance table'
content = content.replace(old_comp, new_comp)

# Also indent the entire compliance block (we need to increase indentation by 4 spaces)
# Instead, we'll just add the if before the block and add an extra indent to each line manually.
# Simpler: find the compliance block from "# Compliance table" to "lines.append("⚠️ For full..." and wrap it.
# We'll do a regex replacement.
pattern = r'(        # Compliance table\n.*?)(            lines.append\(""\)
            lines.append\("⚠️ For full compliance documentation, contact admin."\))'
replacement = r'        if show_compliance:\n            \1\2'
content = re.sub(pattern, replacement, content, flags=re.DOTALL)

with open("bot/reports.py", "w") as f:
    f.write(content)

# 4. Update handlers_client.py to pass show_compliance
with open("bot/handlers_client.py", "r") as f:
    hc = f.read()

# Find the call to build_report_markdown and add show_compliance parameter
old_call = 'report_md = build_report_markdown(domain, results, detailed, deep)'
new_call = '            show_compliance = (context.user_data.get("scan_type") == "full")\n            report_md = build_report_markdown(domain, results, detailed, deep, show_compliance)'
hc = hc.replace(old_call, new_call)

with open("bot/handlers_client.py", "w") as f:
    f.write(hc)

print("✅ All report and scan logic fixes applied.")
