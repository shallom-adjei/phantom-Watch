#!/usr/bin/env python3
"""Add threat scoring and operational progress bars to phantomwatch.py"""

with open("phantomwatch.py", "r") as f:
    content = f.read()

# ===== 1. Add threat scoring function before format_summary =====
threat_scoring = '''
def compute_threat_score(results):
    """Return (score, level) based on findings."""
    score = 0
    max_score = 0

    # Nmap
    if 'nmap' in results:
        open_ports = len(re.findall(r"^\\d+/tcp\\s+open\\s+", results.get('nmap',''), re.MULTILINE))
        vulns = len(re.findall(r"\\|.*VULNERABLE.*", results.get('nmap','')))
        score += (open_ports * 5) + (vulns * 15)
        max_score += (10 * 5) + (10 * 15)  # assume max 10 ports and 10 vulns

    # Nikto
    if 'nikto' in results:
        issues = len(re.findall(r"\\+ (.*)", results.get('nikto','')))
        score += issues * 10
        max_score += 10 * 10

    # theHarvester
    if 'theHarvester' in results and results['theHarvester'] != "No email":
        harvest = results['theHarvester']
        if "<html" in harvest.lower():
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", harvest)
            score += len(emails) * 10
            max_score += 20 * 10

    # dnstwist
    if 'dnstwist' in results:
        registered = len(re.findall(r"^([^ ]+)\\s+registered.*", results.get('dnstwist',''), re.MULTILINE))
        score += registered * 10
        max_score += 10 * 10

    # Metagoofil
    if 'metagoofil' in results and "No metadata" not in results.get('metagoofil',''):
        score += 25
        max_score += 25

    # Sherlock
    if 'sherlock' in results:
        found = len(re.findall(r"\\[\\+\\] (.*)", results.get('sherlock','')))
        score += found * 5
        max_score += 20 * 5

    # Dalfox (if ever added)
    if 'dalfox' in results and "vulnerable" in results.get('dalfox','').lower():
        score += 50
        max_score += 50

    if max_score == 0:
        return 0, "LOW"

    percent = min(100, int((score / max_score) * 100))

    if percent < 10:
        level = "LOW"
    elif percent < 30:
        level = "MEDIUM"
    elif percent < 60:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return percent, level
'''

# Insert after format_summary, before COMPLIANCE
content = content.replace("# Compliance mapping", threat_scoring + "\n\n# Compliance mapping")

# ===== 2. Modify format_summary to show threat score at the top =====
old_summary_start = '    lines = [f"🔍 *Scan completed for {domain}*\\n"]'
new_summary_start = '''    score, level = compute_threat_score(results)
    risk_emoji = {"LOW":"🟢","MEDIUM":"🟡","HIGH":"🟠","CRITICAL":"🔴"}.get(level,"⚪")
    lines = [
        f"🔍 *Scan completed for {domain}*",
        f"{risk_emoji} Threat Score: *{score}/100*  |  Risk Level: *{level}*\\n"
    ]'''

content = content.replace(old_summary_start, new_summary_start)

# ===== 3. Update progress messages to be operational =====
# Replace the old sync_progress callbacks in run_scan
# We'll replace the old progress messages with numbered ones
old_messages = [
    ('f"Running {tool}..."', 'progress_callback(f"Running {tool}...")'),
    ('"Running nmap..."', None),  # not used directly
]
# We'll replace the entire for-loop progress callback and add numbered steps.
# Actually, we modify the scan engine's progress calls directly.

# Replace generic "Running {tool}..." with numbered steps
old_progress_call = 'if progress_callback:\n            progress_callback(f"Running {tool}...")'
new_progress_call = '''if progress_callback:
            step = { "nmap":1, "nikto":2, "whatweb":3, "theHarvester":4, "dnstwist":5, "metagoofil":6, "sherlock":7, "dalfox":8 }.get(tool, 0)
            messages = {
                1: "⚡ [1/7] Mapping infrastructure & ports...",
                2: "🕵️ [2/7] Probing web server security...",
                3: "🔎 [3/7] Fingerprinting technologies...",
                4: "📧 [4/7] Harvesting public OSINT data...",
                5: "🔄 [5/7] Hunting typosquatting domains...",
                6: "📄 [6/7] Extracting document metadata...",
                7: "👤 [7/7] Searching social media footprint...",
                8: "🦠 [8/8] Scanning for XSS vulnerabilities..."
            }
            progress_callback(messages.get(step, f"Running {tool}..."))'''

content = content.replace(old_progress_call, new_progress_call)

# Also update the run_scan function signature's default tools list to include 8 if dalfox is present
# Not strictly necessary, but we'll leave it as is.

# ===== 4. Save =====
with open("phantomwatch.py", "w") as f:
    f.write(content)

print("✅ Threat scoring and operational progress bars added.")
