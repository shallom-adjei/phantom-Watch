#!/usr/bin/env python3
"""Migrate phantomwatch.py to modular bot/ folder."""
import re, os, shutil

# Create target directories
for d in ['bot']:
    os.makedirs(d, exist_ok=True)

with open("phantomwatch.py") as f:
    content = f.read()

# Helper: extract top-level function code
def extract_func(name, after=None):
    pattern = rf'^def {name}\(.*?\):(?:\n(?:    .*?\n|))+'
    match = re.search(pattern, content, re.MULTILINE)
    if not match:
        # try async def
        pattern = rf'^async def {name}\(.*?\):(?:\n(?:    .*?\n|))+'
        match = re.search(pattern, content, re.MULTILINE)
    return match.group(0) if match else None

def extract_async_func(name):
    return extract_func(name)  # same pattern

# ---- database.py ----
db_code = '''"""Database helpers."""
import sqlite3
from datetime import datetime, timedelta

DB_FILE = "phantom_clients.db"
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
c = conn.cursor()

def is_client(username: str) -> bool:
    c.execute("SELECT 1 FROM clients WHERE username=?", (username,))
    return c.fetchone() is not None

def is_active(username: str) -> bool:
    c.execute("SELECT plan, expiry, scan_used FROM clients WHERE username=?", (username,))
    row = c.fetchone()
    if not row:
        return False
    plan, expiry, scan_used = row
    if plan == "free":
        if scan_used:
            return False
        if expiry and expiry < datetime.now().strftime("%Y-%m-%d"):
            return False
        return True
    if expiry and expiry < datetime.now().strftime("%Y-%m-%d"):
        return False
    return True

def add_client(username: str, plan: str = "free", months: int = 0):
    expiry = ""
    if plan == "free":
        expiry = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d")
    elif months > 0:
        expiry = (datetime.now() + timedelta(days=30 * months)).strftime("%Y-%m-%d")
    c.execute("INSERT OR REPLACE INTO clients VALUES (?,?,?,?,?)", (username, plan, expiry, "", 0))
    conn.commit()

def generate_token() -> str:
    import random, string
    return "".join(random.choices(string.ascii_letters + string.digits, k=20))

def verify_domain(domain: str, token: str) -> bool:
    import subprocess
    try:
        r = subprocess.run(
            ["curl", "-s", "-m", "15", f"http://{domain}/verify.txt"],
            capture_output=True, text=True,
        )
        return r.stdout.strip() == token
    except:
        return False
'''

with open("bot/database.py", "w") as f:
    f.write(db_code)

# ---- scanners.py ----
scanners_code = '''"""Scan engine."""
import subprocess, os, shutil

def run_command(cmd, timeout=150):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except:
        return "[!] Error"

def run_scan(domain, email="", progress_callback=None, tools=None):
    if tools is None:
        tools = ["nmap","nikto","whatweb","theHarvester","dnstwist","metagoofil","sherlock"]
    results = {}
    step_map = {"nmap":1,"nikto":2,"whatweb":3,"theHarvester":4,"dnstwist":5,"metagoofil":6,"sherlock":7}
    for tool in tools:
        step = step_map.get(tool,0)
        if progress_callback:
            progress_callback(f"⚡ [{step}/7] Running {tool}...")
        if tool == "nmap":
            results["nmap"] = run_command(["nmap","-sV","-T4","--top-ports","200",domain], timeout=180)
        elif tool == "nikto":
            results["nikto"] = run_command(["nikto","-h",domain,"-T","0123456789abcde","-maxtime","300s"], timeout=300)
        elif tool == "whatweb":
            results["whatweb"] = run_command(["whatweb",domain])
        elif tool == "theHarvester":
            if email:
                run_command(["theHarvester","-d",domain,"-b","google","-f",f"report_{domain}.html"])
                if os.path.exists(f"report_{domain}.html"):
                    with open(f"report_{domain}.html") as f: results["theHarvester"] = f.read()
                    os.remove(f"report_{domain}.html")
                else:
                    results["theHarvester"] = "No results"
            else:
                results["theHarvester"] = "No email"
        elif tool == "dnstwist":
            results["dnstwist"] = run_command(["dnstwist",domain], timeout=120)
        elif tool == "metagoofil":
            raw = run_command(["python3","/home/runner/metagoofil/metagoofil.py","-d",domain,"-t","pdf,doc,xls","-l","20","-n","10","-o",f"/tmp/meta_{domain}","-f",f"meta_{domain}.html"], timeout=300)
            meta_report = f"/tmp/meta_{domain}/meta_{domain}.html"
            if os.path.exists(meta_report):
                with open(meta_report) as f: results["metagoofil"] = f.read()
                shutil.rmtree(f"/tmp/meta_{domain}")
            else:
                results["metagoofil"] = "No metadata found"
        elif tool == "sherlock":
            company = domain.split(".")[0]
            results["sherlock"] = run_command(["sherlock",company,"--timeout","20"], timeout=200)
    return results
'''

with open("bot/scanners.py", "w") as f:
    f.write(scanners_code)

# ---- reports.py ----
reports_code = '''"""Report generators and threat scoring."""
import re
from datetime import datetime

COMPLIANCE = {
    "xss": {"pci": "PCI-DSS 6.5.7", "hipaa": "164.308(a)(5)(ii)(B)"},
    "sqli": {"pci": "PCI-DSS 6.5.1", "hipaa": "164.308(a)(5)(ii)(B)"},
    "open_port": {"pci": "PCI-DSS 1.1.6", "hipaa": "164.308(a)(4)(ii)(B)"},
    "vulnerable_service": {"pci": "PCI-DSS 6.1", "hipaa": "164.308(a)(5)(ii)(B)"},
    "leaked_email": {"pci": "PCI-DSS 6.5.10", "hipaa": "164.308(a)(5)(ii)(B)"},
    "typosquatting": {"pci": "N/A", "hipaa": "164.308(a)(5)(ii)(B)"},
    "metadata_leak": {"pci": "PCI-DSS 6.5.9", "hipaa": "164.308(a)(1)(ii)(D)"},
    "social_media": {"pci": "N/A", "hipaa": "164.308(a)(5)(ii)(B)"},
}

def compute_threat_score(results):
    score = 0
    max_score = 0
    if 'nmap' in results:
        open_ports = len(re.findall(r"^\\d+/tcp\\s+open\\s+", results.get('nmap',''), re.MULTILINE))
        vulns = len(re.findall(r"\\|.*VULNERABLE.*", results.get('nmap','')))
        score += (open_ports * 5) + (vulns * 15)
        max_score += (10 * 5) + (10 * 15)
    if 'nikto' in results:
        issues = len(re.findall(r"\\+ (.*)", results.get('nikto','')))
        score += issues * 10
        max_score += 10 * 10
    if 'theHarvester' in results and results['theHarvester'] != "No email":
        harvest = results['theHarvester']
        if "<html" in harvest.lower():
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", harvest)
            score += len(emails) * 10
            max_score += 20 * 10
    if 'dnstwist' in results:
        registered = len(re.findall(r"^([^ ]+)\\s+registered.*", results.get('dnstwist',''), re.MULTILINE))
        score += registered * 10
        max_score += 10 * 10
    if 'metagoofil' in results and "No metadata" not in results.get('metagoofil',''):
        score += 25
        max_score += 25
    if 'sherlock' in results:
        found = len(re.findall(r"\\[\\+\\] (.*)", results.get('sherlock','')))
        score += found * 5
        max_score += 20 * 5
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

def format_summary(domain, results, detailed=False):
    score, level = compute_threat_score(results)
    risk_emoji = {"LOW":"🟢","MEDIUM":"🟡","HIGH":"🟠","CRITICAL":"🔴"}.get(level,"⚪")
    lines = [
        f"🔍 *Scan completed for {domain}*",
        f"{risk_emoji} Threat Score: *{score}/100*  |  Risk Level: *{level}*\\n",
        "━━━━━━━━━━━━━━━━━━"
    ]
    # ... (the entire format_summary body – I'll provide it in the full code below)
'''
# To avoid pasting the entire long function, we'll copy it from the current file.
# In the actual migration, we'll extract it. For this script, I'll embed the complete function.

# Actually, we can read it from phantomwatch.py
with open("phantomwatch.py") as f:
    orig = f.read()
    # extract format_summary function
    match = re.search(r'def format_summary\(domain, results, detailed=False\):(.*?)(?=\n(?:def |async def |# -))', orig, re.DOTALL)
    if match:
        reports_code += '\n' + match.group(0) + '\n'

with open("bot/reports.py", "w") as f:
    f.write(reports_code)

print("✅ Modules created: database, scanners, reports.")
print("Next step: create menus.py, handlers_admin.py, handlers_client.py, and main.py.")
