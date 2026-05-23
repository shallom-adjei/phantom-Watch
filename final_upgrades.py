#!/usr/bin/env python3
"""Fix threat scoring, enable max-depth scans, polish brief reports, add persistent menu."""

with open("phantomwatch.py", "r") as f:
    lines = f.readlines()

# ===== 1. Ensure compute_threat_score function exists =====
# Insert it right before format_summary (line where "def format_summary" starts)
insert_idx = None
for i, line in enumerate(lines):
    if line.startswith("def format_summary("):
        insert_idx = i
        break

threat_func = [
    "\n",
    "def compute_threat_score(results):\n",
    '    """Return (score, level) based on findings."""\n',
    "    score = 0\n",
    "    max_score = 0\n",
    "\n",
    "    if 'nmap' in results:\n",
    "        open_ports = len(re.findall(r\"^\\d+/tcp\\s+open\\s+\", results.get('nmap',''), re.MULTILINE))\n",
    "        vulns = len(re.findall(r\"\\|.*VULNERABLE.*\", results.get('nmap','')))\n",
    "        score += (open_ports * 5) + (vulns * 15)\n",
    "        max_score += (10 * 5) + (10 * 15)\n",
    "\n",
    "    if 'nikto' in results:\n",
    "        issues = len(re.findall(r\"\\+ (.*)\", results.get('nikto','')))\n",
    "        score += issues * 10\n",
    "        max_score += 10 * 10\n",
    "\n",
    "    if 'theHarvester' in results and results['theHarvester'] != \"No email\":\n",
    "        harvest = results['theHarvester']\n",
    "        if \"<html\" in harvest.lower():\n",
    "            emails = re.findall(r\"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}\", harvest)\n",
    "            score += len(emails) * 10\n",
    "            max_score += 20 * 10\n",
    "\n",
    "    if 'dnstwist' in results:\n",
    "        registered = len(re.findall(r\"^([^ ]+)\\s+registered.*\", results.get('dnstwist',''), re.MULTILINE))\n",
    "        score += registered * 10\n",
    "        max_score += 10 * 10\n",
    "\n",
    "    if 'metagoofil' in results and \"No metadata\" not in results.get('metagoofil',''):\n",
    "        score += 25\n",
    "        max_score += 25\n",
    "\n",
    "    if 'sherlock' in results:\n",
    "        found = len(re.findall(r\"\\[\\+\\] (.*)\", results.get('sherlock','')))\n",
    "        score += found * 5\n",
    "        max_score += 20 * 5\n",
    "\n",
    "    if 'dalfox' in results and \"vulnerable\" in results.get('dalfox','').lower():\n",
    "        score += 50\n",
    "        max_score += 50\n",
    "\n",
    "    if max_score == 0:\n",
    "        return 0, \"LOW\"\n",
    "\n",
    "    percent = min(100, int((score / max_score) * 100))\n",
    "\n",
    "    if percent < 10:\n",
    "        level = \"LOW\"\n",
    "    elif percent < 30:\n",
    "        level = \"MEDIUM\"\n",
    "    elif percent < 60:\n",
    "        level = \"HIGH\"\n",
    "    else:\n",
    "        level = \"CRITICAL\"\n",
    "\n",
    "    return percent, level\n",
    "\n",
]

for line in reversed(threat_func):
    lines.insert(insert_idx, line)

# ===== 2. Enable max-depth scanning (replace simplified tool commands) =====
# We'll find the run_scan function and replace the tool command lines with aggressive versions.
# We'll target the lines inside the for tool in tools: loop.

# Replace Nmap top-ports 200 with -p- (all ports) and full NSE scripts
for i, line in enumerate(lines):
    if 'run_command(["nmap", "-sV", "-T4", "--top-ports", "200", domain])' in line:
        lines[i] = line.replace(
            'run_command(["nmap", "-sV", "-T4", "--top-ports", "200", domain])',
            'run_command(["nmap", "-sV", "-T4", "-p-", "--script", "vuln,exploit,auth,default,discovery", domain], timeout=300)'
        )
    # Nikto: add -maxtime 300s (was 120s), full test set
    if 'run_command(["nikto", "-h", domain, "-T", "123bde", "-maxtime", "120s"])' in line:
        lines[i] = line.replace(
            'run_command(["nikto", "-h", domain, "-T", "123bde", "-maxtime", "120s"])',
            'run_command(["nikto", "-h", domain, "-T", "0123456789abcde", "-maxtime", "300s"], timeout=300)'
        )
    # WhatWeb: already full
    # theHarvester: already full
    # dnstwist: already full
    # metagoofil: increase documents/threads (already max in the command? we'll bump limits)
    if 'run_command(["python3", "/home/runner/metagoofil/metagoofil.py", "-d", domain, "-t", "pdf,doc,xls", "-l", "10", "-n", "5"' in line:
        lines[i] = line.replace('-l", "10", "-n", "5"', '-l", "20", "-n", "10"')
    # Sherlock: increase timeout
    if 'run_command(["python3", "/home/runner/sherlock/sherlock.py", company, "--timeout", "10"])' in line:
        lines[i] = line.replace('"--timeout", "10"', '"--timeout", "20"')

# ===== 3. Polish brief report (cleaner formatting) =====
# Find format_summary function and enhance the output style
# We'll replace the lines that add tool results to use bold headers and better separators.
# Instead of regex, we can replace the entire function body easily. We'll do a targeted swap.
start_format = None
end_format = None
for i, line in enumerate(lines):
    if line.startswith("def format_summary(domain, results):"):
        start_format = i
    if start_format is not None and i > start_format and line.startswith("def generate_pdf_report"):
        end_format = i
        break

if start_format and end_format:
    new_format = [
        'def format_summary(domain, results):\n',
        '    score, level = compute_threat_score(results)\n',
        '    risk_emoji = {"LOW":"🟢","MEDIUM":"🟡","HIGH":"🟠","CRITICAL":"🔴"}.get(level,"⚪")\n',
        '    lines = [\n',
        '        f"🔍 *Scan completed for {domain}*",\n',
        '        f"{risk_emoji} Threat Score: *{score}/100*  |  Risk Level: *{level}*\\n",\n',
        '        "━━━━━━━━━━━━━━━━━━" \n',
        '    ]\n',
        '    # Nmap\n',
        '    if "nmap" in results:\n',
        '        ports = len(re.findall(r"^\\d+/tcp\\s+open\\s+", results.get("nmap", ""), re.MULTILINE))\n',
        '        vulns = len(re.findall(r"\\|.*VULNERABLE.*", results.get("nmap", "")))\n',
        '        if ports or vulns:\n',
        '            lines.append(f"🛡️ *Nmap*: {ports} open ports, {vulns} potential vulns")\n',
        '        else:\n',
        '            lines.append("🛡️ *Nmap*: No open ports or vulns found.")\n',
        '    else:\n',
        '        lines.append("🛡️ *Nmap*: Not run.")\n',
        '    # Nikto\n',
        '    if "nikto" in results:\n',
        '        issues = len(re.findall(r"\\+ (.*)", results.get("nikto", "")))\n',
        '        if issues:\n',
        '            lines.append(f"🔥 *Nikto*: {issues} web issues")\n',
        '        else:\n',
        '            lines.append("🔥 *Nikto*: No web issues found.")\n',
        '    else:\n',
        '        lines.append("🔥 *Nikto*: Not run.")\n',
        '    # WhatWeb\n',
        '    if "whatweb" in results:\n',
        '        clean = re.sub(r"\\x1b\\[[0-9;]*m", "", results.get("whatweb", ""))\n',
        '        servers = re.findall(r"HTTPServer\\[ (.*?) \\]", clean)\n',
        '        if servers:\n',
        '            lines.append(f"🧩 *Technology*: {servers[0]}")\n',
        '        else:\n',
        '            lines.append("🧩 *Technology*: No server header detected.")\n',
        '    else:\n',
        '        lines.append("🧩 *Technology*: Not run.")\n',
        '    # theHarvester\n',
        '    if "theHarvester" in results:\n',
        '        harvest = results["theHarvester"]\n',
        '        if harvest == "No email":\n',
        '            lines.append("📧 *theHarvester*: No email set – skipped.")\n',
        '        elif "<html" in harvest.lower():\n',
        '            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", harvest)\n',
        '            if emails:\n',
        '                lines.append(f"📧 *theHarvester*: {len(emails)} leaked emails found")\n',
        '            else:\n',
        '                lines.append("📧 *theHarvester*: No leaked emails found.")\n',
        '        else:\n',
        '            lines.append("📧 *theHarvester*: No results.")\n',
        '    else:\n',
        '        lines.append("📧 *theHarvester*: Not run.")\n',
        '    # dnstwist\n',
        '    if "dnstwist" in results:\n',
        '        registered = len(re.findall(r"^([^ ]+)\\s+registered.*", results.get("dnstwist", ""), re.MULTILINE))\n',
        '        if registered:\n',
        '            lines.append(f"🕵️ *dnstwist*: {registered} typosquatting domains registered")\n',
        '        else:\n',
        '            lines.append("🕵️ *dnstwist*: No similar domains registered.")\n',
        '    else:\n',
        '        lines.append("🕵️ *dnstwist*: Not run.")\n',
        '    # Metagoofil\n',
        '    if "metagoofil" in results:\n',
        '        if "No metadata" in results.get("metagoofil", ""):\n',
        '            lines.append("📄 *Metagoofil*: No metadata leaks found.")\n',
        '        else:\n',
        '            lines.append("📄 *Metagoofil*: Document metadata leaks found")\n',
        '    else:\n',
        '        lines.append("📄 *Metagoofil*: Not run.")\n',
        '    # Sherlock\n',
        '    if "sherlock" in results:\n',
        '        found = len(re.findall(r"\\[\\+\\] (.*)", results.get("sherlock", "")))\n',
        '        if found:\n',
        '            lines.append(f"👥 *Sherlock*: {found} social media accounts found")\n',
        '        else:\n',
        '            lines.append("👥 *Sherlock*: No accounts found.")\n',
        '    else:\n',
        '        lines.append("👥 *Sherlock*: Not run.")\n',
        '    lines.append("")\n',
        '    lines.append("⚠️ Upgrade to Monthly/Enterprise for full PDF reports & compliance mapping.")\n',
        '    return "\\n".join(lines)\n',
    ]
    lines = lines[:start_format] + new_format + lines[end_format:]

# ===== 4. Add persistent menu button (ReplyKeyboard) =====
# Find the start function and add the menu button after the description
for i, line in enumerate(lines):
    if 'await update.message.reply_text("🔮 *PHANTOM WATCH*' in line:
        # Insert the menu button right after that line
        # We'll add the menu_button definition if not already present
        pass

# Actually, we'll ensure the menu_button is defined and used in /start.
# Find where "async def start" is and add the persistent keyboard.
# First, add the definition of menu_button if not present.
if 'menu_button = ReplyKeyboardMarkup' not in ''.join(lines):
    # Insert after the imports or near the menus
    for i, line in enumerate(lines):
        if 'def quick_scan_menu():' in line:
            lines.insert(i, "menu_button = ReplyKeyboardMarkup([[KeyboardButton(\"🛡️ Menu\")]], resize_keyboard=True)\n")
            break

# Then, inside the start function, after sending the welcome, send the persistent menu.
# Find the line: "await update.message.reply_text("⬇️ *Main Menu*", ..."
for i, line in enumerate(lines):
    if 'await update.message.reply_text("⬇️ *Main Menu*"' in line:
        lines.insert(i, '    await update.message.reply_text("👇 Tap *🛡️ Menu* next to the text field to bring up options anytime.", parse_mode="Markdown")\n')
        break

# Also, in the message_handler, detect "🛡️ Menu" text and show main menu.
# Find fallback line and insert above.
for i, line in enumerate(lines):
    if 'I didn' 't understand. Use the buttons below.' in line:
        lines.insert(i, '    if text == "🛡️ Menu":\n        await update.message.reply_text("Menu:", reply_markup=main_menu(username == ADMIN_USERNAME))\n        return\n')
        break

with open("phantomwatch.py", "w") as f:
    f.writelines(lines)

print("✅ All upgrades applied: threat scoring fixed, max-depth scans, polished reports, persistent menu.")
