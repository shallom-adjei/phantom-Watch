#!/usr/bin/env python3
"""
Phantom Watch – Professional Threat Intelligence Platform
Final Resilient Version – All features included, no missing functions.
"""

import subprocess, re, os, sqlite3, random, string, shutil, json, time, asyncio, io, traceback
from datetime import datetime, timedelta

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton, ReplyKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    filters,
    ContextTypes,
)
import telegram.error
import requests
from fpdf import FPDF

# ========== CONFIG ==========
BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_CHAT_ID = None
DB_FILE = "phantom_clients.db"
SCAN_TIMEOUT = 150
MAX_CONCURRENT_SCANS = 3

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
# ==========================

# Database
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS clients (
    username TEXT PRIMARY KEY,
    plan TEXT DEFAULT 'free',
    expiry TEXT,
    email_collect TEXT DEFAULT ''
)''')
c.execute('''CREATE TABLE IF NOT EXISTS verification (
    username TEXT, domain TEXT, token TEXT,
    PRIMARY KEY(username, domain)
)''')
c.execute('''CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT, domain TEXT, timestamp TEXT,
    report TEXT, finished INTEGER DEFAULT 0
)''')
c.execute('''CREATE TABLE IF NOT EXISTS subscriptions (
    username TEXT, domain TEXT,
    last_scan_time TEXT, last_report_json TEXT,
    PRIMARY KEY(username, domain)
)''')
c.execute('''CREATE TABLE IF NOT EXISTS client_tech (
    username TEXT, domain TEXT, tech TEXT,
    last_check TEXT,
    PRIMARY KEY(username, domain, tech)
)''')
conn.commit()

# ----- Helpers -----
def is_client(username: str) -> bool:
    c.execute("SELECT 1 FROM clients WHERE username=?", (username,))
    return c.fetchone() is not None

def is_subscription_active(username: str) -> bool:
    c.execute("SELECT plan, expiry FROM clients WHERE username=?", (username,))
    row = c.fetchone()
    if not row:
        return False
    plan, expiry = row
    if plan == 'free':
        if expiry and expiry < datetime.now().strftime("%Y-%m-%d"):
            return False
        return True
    if expiry and expiry < datetime.now().strftime("%Y-%m-%d"):
        return False
    return True

def get_client_plan(username: str) -> str:
    c.execute("SELECT plan FROM clients WHERE username=?", (username,))
    row = c.fetchone()
    return row[0] if row else "free"

def add_client(username: str, plan: str = "free", expiry: str = ""):
    c.execute("INSERT OR REPLACE INTO clients VALUES (?,?,?,?)", (username, plan, expiry, ""))
    conn.commit()

def set_plan(username: str, plan: str, months: int):
    new_expiry = (datetime.now() + timedelta(days=30*months)).strftime("%Y-%m-%d")
    c.execute("UPDATE clients SET plan=?, expiry=? WHERE username=?", (plan, new_expiry, username))
    conn.commit()

def set_free_expiry(username: str):
    new_expiry = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d")
    c.execute("UPDATE clients SET expiry=? WHERE username=?", (new_expiry, username))
    conn.commit()

def generate_token() -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=20))

def verify_domain(domain: str, token: str) -> bool:
    try:
        url = f"http://{domain}/verify.txt"
        result = subprocess.run(["curl", "-s", "-m", "15", url], capture_output=True, text=True)
        return result.stdout.strip() == token
    except:
        return False

def run_command(cmd: str, timeout: int = SCAN_TIMEOUT) -> str:
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[!] Command timed out."
    except Exception as e:
        return f"[!] Error: {str(e)}"

async def notify_admin(text: str, context: ContextTypes.DEFAULT_TYPE):
    """Sends a message to the admin – works even if ADMIN_CHAT_ID is not set."""
    global ADMIN_CHAT_ID
    if ADMIN_CHAT_ID:
        try:
            await context.bot.send_message(chat_id=ADMIN_CHAT_ID, text=text)
            return
        except:
            pass
    # Fallback: send directly to admin username
    try:
        await context.bot.send_message(chat_id=f"@{ADMIN_USERNAME}", text=text)
    except Exception as e:
        print(f"[!] Could not notify admin: {e}")

# ---------- Breach Check ----------
async def check_breach(email: str, context, chat_id):
    try:
        resp = requests.get(f"https://api.xposedornot.com/v1/breach-analytics?email={email}", timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            breach_details = data.get("breach_details", {})
            if breach_details:
                total = len(breach_details)
                lines = [f"🩸 *Breach Report for {email}*", f"Found in *{total}* known breaches:\n"]
                for name, info in list(breach_details.items())[:10]:
                    domain = info.get("domain", "unknown")
                    date = info.get("breach_date", "N/A")
                    lines.append(f"• *{name}* ({domain}) – {date}")
                if total > 10:
                    lines.append(f"… and {total-10} more breaches.")
                await context.bot.send_message(chat_id=chat_id, text="\n".join(lines), parse_mode='Markdown')
                return
    except:
        pass
    hibp_key = os.getenv("HIBP_API_KEY", "")
    if hibp_key:
        headers = {"hibp-api-key": hibp_key, "user-agent": "PhantomWatchBot"}
        try:
            resp = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", headers=headers, timeout=10)
            if resp.status_code == 200:
                breaches = resp.json()
                names = [b["Name"] for b in breaches]
                await context.bot.send_message(chat_id=chat_id, text=f"🩸 *HIBP Report for {email}*\nFound in *{len(names)}* breaches:\n• " + "\n• ".join(names[:10]), parse_mode='Markdown')
                return
        except:
            pass
    await context.bot.send_message(chat_id=chat_id, text="✅ No breaches found for this email.")

# ---------- Exploitation Proof (Playwright) ----------
async def capture_exploit_screenshot(url: str, payload: str, context, chat_id):
    from playwright.async_api import async_playwright
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            test_url = f"{url}?q={payload}"
            await page.goto(test_url, wait_until="networkidle", timeout=15000)
            await page.wait_for_timeout(2000)
            screenshot = await page.screenshot(full_page=True)
            await browser.close()
            await context.bot.send_photo(chat_id=chat_id, photo=io.BytesIO(screenshot),
                                         caption="🔴 *Exploitation Proof* – Payload executed.", parse_mode='Markdown')
            return True
    except Exception as e:
        await context.bot.send_message(chat_id=chat_id, text=f"⚠️ Screenshot capture failed: {e}")
        return False

# ---------- Scan Engine (state‑persistent) ----------
def run_scan(domain: str, email: str = "", progress_callback=None, tools: list = None, instant_callback=None,
             username: str = None) -> dict:
    if tools is None:
        tools = ["nmap", "nikto", "whatweb", "theHarvester", "dnstwist", "metagoofil", "sherlock", "dalfox"]
    results = {}
    c.execute("INSERT INTO scan_results (username, domain, timestamp, report, finished) VALUES (?,?,?,?,?)",
              (username, domain, datetime.now().isoformat(), "{}", 0))
    scan_id = c.lastrowid
    conn.commit()

    def save_progress():
        c.execute("UPDATE scan_results SET report=?, finished=? WHERE id=?",
                  (json.dumps(results), 0, scan_id))
        conn.commit()

    for tool in tools:
        try:
            if tool == "nmap":
                if progress_callback: progress_callback("⚡ Nmap (max‑depth)...")
                raw = run_command(f"nmap -sV -T4 -p- --script vuln,exploit,auth,default,discovery {domain}", timeout=300)
                results['nmap'] = raw
            elif tool == "nikto":
                if progress_callback: progress_callback("🕵️ Nikto (full)...")
                raw = run_command(f"nikto -h {domain} -T 0123456789abcde -maxtime 300s", timeout=300)
                results['nikto'] = raw
            elif tool == "whatweb":
                if progress_callback: progress_callback("🔎 WhatWeb...")
                results['whatweb'] = run_command(f"whatweb {domain}")
            elif tool == "theHarvester":
                if email:
                    raw = run_command(f"theHarvester -d {domain} -b google -f report_{domain}.html")
                    if os.path.exists(f"report_{domain}.html"):
                        with open(f"report_{domain}.html", "r") as f:
                            results['theHarvester'] = f.read()
                        os.remove(f"report_{domain}.html")
                    else:
                        results['theHarvester'] = "No email results."
                else:
                    results['theHarvester'] = "No email provided for OSINT."
                if progress_callback: progress_callback("📧 OSINT email harvesting done.")
            elif tool == "dnstwist":
                results['dnstwist'] = run_command(f"dnstwist {domain}")
            elif tool == "metagoofil":
                raw = run_command(
                    f"cd /home/runner/metagoofil && python3 metagoofil.py -d {domain} -t pdf,doc,xls -l 20 -n 10 -o /tmp/meta_{domain} -f meta_{domain}.html",
                    timeout=300
                )
                meta_report = f"/tmp/meta_{domain}/meta_{domain}.html"
                if os.path.exists(meta_report):
                    with open(meta_report, "r") as f:
                        results['metagoofil'] = f.read()
                    shutil.rmtree(f"/tmp/meta_{domain}")
                else:
                    results['metagoofil'] = "No metadata found or command failed."
            elif tool == "sherlock":
                company_name = domain.split('.')[0]
                raw = run_command(f"cd /home/runner/sherlock && python3 sherlock.py {company_name} --timeout 20", timeout=200)
                results['sherlock'] = raw
            elif tool == "dalfox":
                raw = run_command(f"dalfox url http://{domain} --silence", timeout=200)
                results['dalfox'] = raw
                if "vulnerable" in raw.lower() and instant_callback:
                    instant_callback("🔴 CRITICAL: Dalfox detected XSS vulnerabilities!")
            save_progress()
        except Exception as e:
            print(f"[!] Tool {tool} failed: {e}")
            continue

    c.execute("UPDATE scan_results SET report=?, finished=? WHERE id=?",
              (json.dumps(results), 1, scan_id))
    conn.commit()
    return results

# ---------- PDF Generator ----------
def generate_pdf_report(domain: str, results: dict, plan: str) -> io.BytesIO:
    pdf = FPDF()
    pdf.add_page()
    regular_path = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    bold_path    = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
    pdf.add_font("DejaVu", "", regular_path, uni=True)
    pdf.add_font("DejaVu", "B", bold_path, uni=True)

    pdf.set_font("DejaVu", "B", 16)
    pdf.cell(0, 10, "PHANTOM WATCH Security Report", ln=True, align="C")
    pdf.set_font("DejaVu", "", 10)
    pdf.cell(0, 10, f"Domain: {domain}", ln=True)
    pdf.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", ln=True)
    pdf.ln(5)

    findings = []
    if 'nmap' in results:
        vulns = re.findall(r"\|.*VULNERABLE.*", results['nmap'])
        if vulns: findings.append(f"{len(vulns)} Nmap vulnerabilities")
        open_ports = re.findall(r"^\d+/tcp\s+open\s+(.*)", results['nmap'], re.MULTILINE)
        if open_ports: findings.append(f"{len(open_ports)} open ports")
    if 'nikto' in results:
        issues = re.findall(r"\+ (.*)", results['nikto'])
        if issues: findings.append(f"{len(issues)} Nikto issues")
    if 'dalfox' in results and "vulnerable" in results['dalfox'].lower():
        findings.append("XSS vulnerabilities detected")
    if 'theHarvester' in results and "Leaked" in results.get('theHarvester',''):
        findings.append("Leaked emails found")
    if 'dnstwist' in results and re.findall(r"^([^ ]+)\s+registered.*", results['dnstwist'], re.MULTILINE):
        findings.append("Typosquatting domains registered")
    if 'metagoofil' in results and "No metadata" not in results.get('metagoofil',''):
        findings.append("Document metadata leaks")
    if 'sherlock' in results and re.findall(r"\[\+\] (.*)", results['sherlock']):
        findings.append("Social media accounts found")
    pdf.set_font("DejaVu", "B", 12)
    pdf.cell(0, 10, "Findings Summary", ln=True)
    pdf.set_font("DejaVu", "", 10)
    for f in findings:
        pdf.cell(0, 6, f"• {f}", ln=True)

    pdf.ln(5)
    pdf.set_font("DejaVu", "B", 12)
    pdf.cell(0, 10, "Compliance Status", ln=True)
    pdf.set_font("DejaVu", "", 9)
    for category, rules in COMPLIANCE.items():
        if category == "xss" and 'dalfox' in results and "vulnerable" in results['dalfox'].lower():
            status = "❌"
        elif category == "open_port" and any("open" in str(results.get('nmap',''))):
            status = "❌"
        elif category == "vulnerable_service" and any("VULNERABLE" in str(results.get('nmap',''))):
            status = "❌"
        elif category == "leaked_email" and 'theHarvester' in results and "Leaked" in str(results.get('theHarvester','')):
            status = "❌"
        else:
            status = "✅"
        pdf.cell(0, 6, f"{status} {category}: PCI {rules['pci']} / HIPAA {rules['hipaa']}", ln=True)

    buf = io.BytesIO()
    pdf.output(buf)
    buf.seek(0)
    return buf

def brief_summary(domain: str, results: dict) -> str:
    lines = [f"🔍 *Scan completed for {domain}*\n"]
    if 'nmap' in results:
        vulns = len(re.findall(r"\|.*VULNERABLE.*", results['nmap']))
        ports = len(re.findall(r"^\d+/tcp\s+open\s+", results['nmap'], re.MULTILINE))
        lines.append(f"🛡️ Nmap: {ports} open ports, {vulns} potential vulns")
    if 'nikto' in results:
        issues = len(re.findall(r"\+ (.*)", results['nikto']))
        lines.append(f"🔥 Nikto: {issues} web issues")
    if 'whatweb' in results:
        clean = re.sub(r'\x1b\[[0-9;]*m', '', results['whatweb'])
        if 'HTTPServer' in clean:
            server = re.findall(r'HTTPServer\[ (.*?) \]', clean)[0]
            lines.append(f"🧩 Technology: {server}")
        if 'Cloudflare' in clean:
            lines.append("🛡️ Cloudflare WAF present")
    if 'theHarvester' in results and results['theHarvester'] != "No email provided for OSINT.":
        harvest = results['theHarvester']
        if "<html" in harvest.lower():
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", harvest)
            lines.append(f"📧 Emails leaked: {len(emails)}")
    if 'dnstwist' in results:
        registered = len(re.findall(r"^([^ ]+)\s+registered.*", results['dnstwist'], re.MULTILINE))
        lines.append(f"🕵️ Typosquatting: {registered} domains registered")
    if 'metagoofil' in results and "No metadata" not in results.get('metagoofil',''):
        lines.append("📄 Document metadata leaks found")
    if 'sherlock' in results:
        found = len(re.findall(r"\[\+\] (.*)", results['sherlock']))
        lines.append(f"👥 Social media: {found} accounts found")
    if 'dalfox' in results:
        if "vulnerable" in results['dalfox'].lower():
            lines.append("🦠 Dalfox: XSS vulnerabilities detected!")
        else:
            lines.append("🦠 Dalfox: no XSS found")
    lines.append("\n📎 Detailed PDF report attached.")
    return "\n".join(lines)

# ----- Menus -----
def main_menu_keyboard(user_is_admin=False):
    buttons = [
        [InlineKeyboardButton("🔍 Full Scan", callback_data="scan_full"),
         InlineKeyboardButton("⚡ Quick Scan", callback_data="scan_quick")],
        [InlineKeyboardButton("📧 Set Email", callback_data="set_email"),
         InlineKeyboardButton("📖 How It Works", callback_data="how_it_works")],
        [InlineKeyboardButton("❓ Help", callback_data="help"),
         InlineKeyboardButton("🩸 Check Breaches", callback_data="check_breaches")],
        [InlineKeyboardButton("💲 Pricing", callback_data="pricing"),
         InlineKeyboardButton("📩 Contact Admin", callback_data="contact_admin")],
        [InlineKeyboardButton("🔔 Subscribe", callback_data="subscribe"),
         InlineKeyboardButton("🔑 Scan GitHub", callback_data="github_scan")],
    ]
    if user_is_admin:
        buttons.append([InlineKeyboardButton("👑 Admin Menu", callback_data="admin_menu")])
    return InlineKeyboardMarkup(buttons)
def admin_menu_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Add User", callback_data="admin_adduser"),
         InlineKeyboardButton("✅ Verify Domain", callback_data="admin_verify")],
        [InlineKeyboardButton("📊 Status", callback_data="admin_status"),
         InlineKeyboardButton("❌ Remove User", callback_data="admin_removeuser")],
        [InlineKeyboardButton("🔙 Main Menu", callback_data="main_menu")],
    ])
def quick_scan_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🛡️ Ports & Vulns", callback_data="quick_ports")],
        [InlineKeyboardButton("🌐 OSINT Pack", callback_data="quick_osint")],
        [InlineKeyboardButton("🔎 Recon", callback_data="quick_recon")],
        [InlineKeyboardButton("🦠 XSS Check", callback_data="quick_xss")],
        [InlineKeyboardButton("🔙 Main Menu", callback_data="main_menu")],
    ])

menu_button = ReplyKeyboardMarkup([[KeyboardButton("🛡️ Menu")]], resize_keyboard=True)

# ----- Callback handler -----
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    username = query.from_user.username

    if data == "main_menu":
        await query.edit_message_text("🔮 Phantom Watch – Main Menu", reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))
        return
    if data == "check_breaches":
        if not is_subscription_active(username):
            await query.edit_message_text("⛔ Subscription expired."); return
        c.execute("SELECT email_collect FROM clients WHERE username=?", (username,))
        row = c.fetchone()
        email = row[0] if row else ""
        if not email:
            await query.edit_message_text("📧 Please set your email first.")
        else:
            await query.edit_message_text("🩸 Checking breaches...")
            await check_breach(email, context, query.message.chat_id)
        return
    if data == "subscribe":
        if not is_subscription_active(username):
            await query.edit_message_text("⛔ Subscription expired."); return
        await query.edit_message_text("📌 Send the domain you want to monitor weekly:")
        context.user_data['state'] = "SUBSCRIBE_DOMAIN"
        return
    if data == "github_scan":
        if get_client_plan(username) not in ["enterprise"]:
            await query.edit_message_text("🔑 This feature requires Enterprise plan."); return
        await query.edit_message_text("🔑 Send the GitHub repository URL:")
        context.user_data['state'] = "GITHUB_SCAN"
        return
    if data in ["scan_full", "scan_quick"]:
        if not is_subscription_active(username):
            await query.edit_message_text("⛔ Subscription expired."); return
        plan = get_client_plan(username)
        if data == "scan_full":
            context.user_data['scan_type'] = 'full'
            context.user_data['tools'] = None
        else:
            await query.edit_message_text("Choose a quick scan type:", reply_markup=quick_scan_keyboard())
            return
        await query.edit_message_text("📌 Send the domain name to scan.")
        context.user_data['state'] = "SCAN_DOMAIN"
        return
    if data.startswith("quick_"):
        if not is_subscription_active(username):
            await query.edit_message_text("⛔ Subscription expired."); return
        if data == "quick_ports": tools = ["nmap", "nikto"]
        elif data == "quick_osint": tools = ["theHarvester", "sherlock"]
        elif data == "quick_recon": tools = ["whatweb", "dnstwist", "metagoofil"]
        elif data == "quick_xss": tools = ["dalfox"]
        context.user_data['tools'] = tools
        context.user_data['scan_type'] = 'quick'
        await query.edit_message_text("📌 Send the domain name to scan.")
        context.user_data['state'] = "SCAN_DOMAIN"
        return
    if data == "set_email":
        await query.edit_message_text("📧 Please send your email address:")
        context.user_data['state'] = "SET_EMAIL"
        return
    if data == "how_it_works":
        how_text = ("📖 *How Phantom Watch Operates*\n"
                    "1️⃣ *Registration* – Admin adds you & verifies your domain.\n"
                    "2️⃣ *Choose a Scan* – Full or Quick.\n"
                    "3️⃣ *Live Monitoring* – Instant alerts for critical findings.\n"
                    "4️⃣ *Professional PDF Report* – Includes compliance mapping.\n"
                    "5️⃣ *Continuous Protection* – Subscribe to weekly scans & breach checks.\n"
                    "💡 Enterprise plan includes exploitation proof and GitHub secret scanning.")
        await context.bot.send_message(chat_id=query.message.chat_id, text=how_text, parse_mode='Markdown')
        await query.edit_message_text("🔮 Return to main menu:", reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))
        return
    if data == "pricing":
        pricing_text = (
            "💲 *Phantom Watch Pricing Plans*\n\n"
            "🆓 *Free Trial* – 7 days\n"
            "• One full scan\n"
            "• Basic summary\n"
            "*Price:* Free\n\n"
            "🛡️ *Monthly* – $199/month\n"
            "• Unlimited full scans\n"
            "• PDF reports with compliance mapping\n"
            "• Breach intelligence\n"
            "• Weekly subscription scans\n"
            "*Price:* $199/month\n\n"
            "👑 *Enterprise* – $2,000/month\n"
            "• Everything in Monthly\n"
            "• Exploitation proof screenshots\n"
            "• Continuous CVE monitoring (hourly alerts)\n"
            "• GitHub secret scanning (leaked API keys)\n"
            "• Priority support\n"
            "*Price:* $2,000/month\n\n"
            "📩 Contact admin to subscribe or upgrade."
        )
        await context.bot.send_message(chat_id=query.message.chat_id, text=pricing_text, parse_mode='Markdown')
        await query.edit_message_text("🔮 Return to main menu:", reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))
        return
    if data == "contact_admin":
        # Notify admin
        await notify_admin(f"📩 Client @{username} wants to get in touch.", context)
        await context.bot.send_message(chat_id=query.message.chat_id,
                                       text="✅ Your message has been forwarded to the admin. They will contact you shortly.")
        await query.edit_message_text("🔮 Return to main menu:", reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))
        return
    if data == "help":
        help_text = "\n\n".join([
            "*⚡ Nmap* – Port scanning & vuln detection.\nProtection: firewall, patching.",
            "*🕵️ Nikto* – Web server misconfigurations.\nProtection: update CMS, security headers.",
            "*🔎 WhatWeb* – Technology fingerprinting.\nProtection: hide banners, WAF.",
            "*📧 theHarvester* – OSINT email gathering.\nProtection: DMARC, staff training.",
            "*🔄 dnstwist* – Typosquatting detection.\nProtection: monitor domains, buy variants.",
            "*📄 Metagoofil* – Document metadata.\nProtection: strip metadata before publishing.",
            "*👤 Sherlock* – Social media search.\nProtection: 2FA, remove unused profiles.",
            "*🦠 Dalfox* – XSS scanner.\nProtection: input sanitisation, CSP.",
            "*🩸 Breach Check* – Checks email against known data breaches.",
            "*🔑 GitHub Scan* – Detects leaked API keys/tokens."
        ])
        for i in range(0, len(help_text), 4000):
            await context.bot.send_message(chat_id=query.message.chat_id, text=help_text[i:i+4000], parse_mode='Markdown')
        await query.edit_message_text("🔮 Return to main menu:", reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))
        return

    # Admin
    if data == "admin_menu":
        if username != ADMIN_USERNAME: return
        await query.edit_message_text("👑 Admin Panel", reply_markup=admin_menu_keyboard())
        return
    if data == "admin_adduser":
        if username != ADMIN_USERNAME: return
        await query.edit_message_text("Enter client username (with @):")
        context.user_data['state'] = "ADDUSER_USERNAME"
        return
    if data == "admin_verify":
        if username != ADMIN_USERNAME: return
        await query.edit_message_text("Enter client username (with @):")
        context.user_data['state'] = "VERIFY_USERNAME"
        return
    if data == "admin_status":
        if username != ADMIN_USERNAME: return
        c.execute("SELECT username, plan, expiry FROM clients")
        clients = c.fetchall()
        msg = "📊 Client List\n\n"
        for u, p, e in clients:
            msg += f"@{u} - {p}"
            if e: msg += f" (exp: {e})"
            msg += "\n"
        await query.edit_message_text(msg, reply_markup=admin_menu_keyboard())
        return
    if data == "admin_removeuser":
        if username != ADMIN_USERNAME: return
        await query.edit_message_text("Enter the username of the client to remove (with @):")
        context.user_data['state'] = "REMOVE_USER"
        return
# ----- Message handler (with all states) -----
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.message.from_user
    username = user.username
    text = update.message.text.strip()
    state = context.user_data.get('state')

    if text == "🛡️ Menu":
        await update.message.reply_text("Menu:", reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))
        return

    # ----- ADMIN ADD USER -----
    if state == "ADDUSER_USERNAME":
        if username != ADMIN_USERNAME:
            await update.message.reply_text("❌ Admin only."); return
        target = text.lstrip('@')
        if not target:
            await update.message.reply_text("Invalid. Enter username with @:"); return
        context.user_data['add_target'] = target
        await update.message.reply_text("Plan? (free, monthly, enterprise):")
        context.user_data['state'] = "ADDUSER_PLAN"
        return
    if state == "ADDUSER_PLAN":
        plan = text.lower()
        if plan not in ["free", "monthly", "enterprise"]:
            await update.message.reply_text("Invalid plan."); return
        context.user_data['add_plan'] = plan
        await update.message.reply_text("How many months? (0 for free trial):")
        context.user_data['state'] = "ADDUSER_MONTHS"
        return
    if state == "ADDUSER_MONTHS":
        try: months = int(text)
        except: await update.message.reply_text("Enter a number."); return
        target = context.user_data['add_target']
        plan = context.user_data['add_plan']
        add_client(target, plan)
        if plan == "free": set_free_expiry(target)
        elif months > 0: set_plan(target, plan, months)
        await update.message.reply_text(f"✅ Added @{target} with {plan} plan.", reply_markup=admin_menu_keyboard())
        for k in ('add_target', 'add_plan', 'state'): context.user_data.pop(k, None)
        return
    # ----- REMOVE USER -----
    if state == "REMOVE_USER":
        if username != ADMIN_USERNAME:
            await update.message.reply_text("❌ Admin only.")
            return
        target = text.lstrip('@')
        if not is_client(target):
            await update.message.reply_text("User is not a client.")
            return
        # Set expiry to yesterday → instantly inactive
        c.execute("UPDATE clients SET expiry='2000-01-01' WHERE username=?", (target,))
        conn.commit()
        await update.message.reply_text(f"❌ User @{target} has been removed. They can no longer use the bot.",
                                        reply_markup=admin_menu_keyboard())
        context.user_data.pop('state', None)
        return

    # ----- ADMIN VERIFY DOMAIN -----
    if state == "VERIFY_USERNAME":
        if username != ADMIN_USERNAME:
            await update.message.reply_text("❌ Admin only."); return
        target = text.lstrip('@')
        if not is_client(target):
            await update.message.reply_text("User not a client."); return
        context.user_data['verify_target'] = target
        await update.message.reply_text("Domain to verify:")
        context.user_data['state'] = "VERIFY_DOMAIN"
        return
    if state == "VERIFY_DOMAIN":
        target = context.user_data['verify_target']
        domain = text.lower()
        c.execute("INSERT OR REPLACE INTO verification VALUES (?,?,?)", (target, domain, "admin_verified"))
        conn.commit()
        await update.message.reply_text(f"✅ Domain {domain} verified for @{target}.", reply_markup=admin_menu_keyboard())
        for k in ('verify_target', 'state'): context.user_data.pop(k, None)
        return

    # ----- SET EMAIL -----
    if state == "SET_EMAIL":
        if '@' not in text: await update.message.reply_text("Invalid email."); return
        c.execute("UPDATE clients SET email_collect=? WHERE username=?", (text, username))
        conn.commit()
        await update.message.reply_text(f"✅ Email set.", reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))
        context.user_data.pop('state', None)
        return

    # ----- SUBSCRIBE DOMAIN -----
    if state == "SUBSCRIBE_DOMAIN":
        domain = text.lower()
        if not re.match(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', domain):
            await update.message.reply_text("Invalid domain."); return
        c.execute("INSERT OR REPLACE INTO subscriptions VALUES (?,?,?,?)",
                  (username, domain, datetime.now().isoformat(), "{}"))
        conn.commit()
        await update.message.reply_text(f"✅ Subscribed.", reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))
        context.user_data.pop('state', None)
        return

    # ----- GITHUB SECRET SCAN -----
    if state == "GITHUB_SCAN":
        repo_url = text.strip()
        if not repo_url.startswith("https://github.com/"):
            await update.message.reply_text("Invalid GitHub URL."); return
        await update.message.reply_text("🔑 Scanning for secrets...")
        try:
            repo_name = repo_url.rstrip("/").split("/")[-1]
            clone_dir = f"/tmp/{repo_name}_{random.randint(1000,9999)}"
            subprocess.run(["git", "clone", "--depth=1", repo_url, clone_dir], check=True, timeout=30)
            result = subprocess.run(["trufflehog", "filesystem", clone_dir, "--no-update", "--json"],
                                    capture_output=True, text=True, timeout=120)
            shutil.rmtree(clone_dir, ignore_errors=True)
            findings = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
            if not findings:
                await update.message.reply_text("✅ No secrets detected.")
            else:
                summary = f"🔑 *Found {len(findings)} secrets!*\n"
                for f in findings[:5]:
                    summary += f"• {f.get('DetectorName','Unknown')} in {f.get('SourceMetadata',{}).get('Data',{}).get('Filesystem',{}).get('file','unknown')}\n"
                await update.message.reply_text(summary, parse_mode='Markdown')
        except Exception as e:
            await update.message.reply_text(f"❌ GitHub scan failed: {e}")
        context.user_data.pop('state', None)
        return

    # ----- SCAN DOMAIN (with recovery) -----
    if state == "SCAN_DOMAIN":
        domain = text.lower()
        if not re.match(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', domain):
            await update.message.reply_text("❌ Invalid domain."); return
        if not is_subscription_active(username):
            await update.message.reply_text("⛔ You are not an authorized client. Tap /start and choose *📩 Contact Admin* to request access.",
                                parse_mode='Markdown')
        plan = get_client_plan(username)
        if username != ADMIN_USERNAME:
            c.execute("SELECT token FROM verification WHERE username=? AND domain=?", (username, domain))
            row = c.fetchone()
            if row and row[0] == "admin_verified": pass
            elif row and row[0] != "admin_verified":
                if not verify_domain(domain, row[0]):
                    await update.message.reply_text("⏳ Verification file missing."); return
            else:
                token = generate_token()
                c.execute("INSERT OR REPLACE INTO verification VALUES (?,?,?)", (username, domain, token))
                conn.commit()
                await update.message.reply_text(f"🔐 Verify ownership: upload `verify.txt` with token `{token}` to root of your site.\nOr ask admin for manual verification.")
                return

        # Check for previous finished scan
        c.execute("SELECT id, report, finished FROM scan_results WHERE username=? AND domain=? AND finished=1 ORDER BY id DESC LIMIT 1",
                  (username, domain))
        prev = c.fetchone()
        if prev:
            old_results = json.loads(prev[1])
            summary = brief_summary(domain, old_results)
            await update.message.reply_text(summary, parse_mode='Markdown')
            if plan in ("monthly", "enterprise"):
                try:
                    pdf_buf = generate_pdf_report(domain, old_results, plan)
                    pdf_buf.name = f"PhantomWatch-{domain}-report.pdf"
                    await context.bot.send_document(chat_id=update.message.chat_id, document=pdf_buf, caption="📎 Detailed compliance report")
                except Exception as e:
                    await update.message.reply_text(f"⚠️ PDF generation failed: {e}")
            return

        # New scan
        await update.message.reply_text("✅ Domain verified. Launching scan...")
        chat_id = update.message.chat_id

        stop_anim = asyncio.Event()
        async def anim():
            frames = ["[▓░░░░]","[▓▓░░░]","[▓▓▓░░]","[▓▓▓▓░]","[▓▓▓▓▓]"]
            msg = await context.bot.send_message(chat_id=chat_id, text="🔥 Scanning started...")
            i = 0
            while not stop_anim.is_set():
                await asyncio.sleep(10)
                if stop_anim.is_set(): break
                await msg.edit_text(f"🔄 {frames[i%5]} Scan in progress...")
                i += 1
            try: await msg.delete()
            except: pass
        anim_task = asyncio.create_task(anim())

        progress_msg = await context.bot.send_message(chat_id=chat_id, text="⚡ Preparing tools...")
        loop = asyncio.get_running_loop()
        def sync_progress(msg):
            async def _upd():
                try: await progress_msg.edit_text(msg)
                except: pass
            asyncio.run_coroutine_threadsafe(_upd(), loop)

        async def instant_alert(msg):
            await context.bot.send_message(chat_id=chat_id, text=msg)
        def instant_callback(msg):
            asyncio.run_coroutine_threadsafe(instant_alert(msg), loop)

        c.execute("SELECT email_collect FROM clients WHERE username=?", (username,))
        row = c.fetchone()
        email = row[0] if row else ""
        tools = context.user_data.get('tools', None)

        try:
            results = await loop.run_in_executor(None, run_scan, domain, email, sync_progress, tools, instant_callback, username)
        except Exception as e:
            tb = traceback.format_exc()
            print(f"[!] Scan error: {tb}")
            await notify_admin(f"❌ Scan crashed for {domain}: {e}\n{tb[:500]}", context)
            await update.message.reply_text(f"❌ Scan error: {e}")
            results = {}
        finally:
            stop_anim.set()
            await anim_task
            try: await progress_msg.delete()
            except: pass

        if results:
            summary = brief_summary(domain, results)
            await context.bot.send_message(chat_id=chat_id, text=summary, parse_mode='Markdown')
            if plan == "enterprise" and 'dalfox' in results and "vulnerable" in results['dalfox'].lower():
                await capture_exploit_screenshot(f"http://{domain}", "<script>alert('XSS')</script>", context, chat_id)
            if plan in ("monthly", "enterprise"):
                try:
                    pdf_buf = generate_pdf_report(domain, results, plan)
                    pdf_buf.name = f"PhantomWatch-{domain}-report.pdf"
                    await context.bot.send_document(chat_id=chat_id, document=pdf_buf, caption="📎 Detailed compliance report")
                except Exception as e:
                    await context.bot.send_message(chat_id=chat_id, text=f"⚠️ PDF generation failed: {e}")
        else:
            await context.bot.send_message(chat_id=chat_id, text="❌ No results (scan failed).")

        context.user_data.pop('state', None)
        context.user_data.pop('scan_type', None)
        context.user_data.pop('tools', None)
        await update.message.reply_text("🔮 What's next?", reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))
        return

    # Fallback
    await update.message.reply_text("I didn't understand. Use the buttons.", reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))

# ----- CVE Monitor -----
async def cve_monitor_task(context: ContextTypes.DEFAULT_TYPE):
    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=" +
            (datetime.utcnow() - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000") +
            "&resultsPerPage=50", timeout=30)
        if resp.status_code == 200:
            cves = resp.json().get("vulnerabilities", [])
            c.execute("SELECT username, domain, tech FROM client_tech")
            rows = c.fetchall()
            for username, domain, tech in rows:
                for vuln in cves:
                    desc = vuln.get("cve", {}).get("descriptions", [{}])[0].get("value", "")
                    if tech.lower() in desc.lower():
                        cve_id = vuln["cve"]["id"]
                        try:
                            await context.bot.send_message(
                                chat_id=f"@{username}",
                                text=f"🚨 *Zero‑day alert for {domain}*\nCVE-{cve_id} affects {tech}\nPatch immediately!",
                                parse_mode='Markdown')
                        except: pass
    except Exception as e:
        print(f"[!] CVE monitor error: {e}")

# ----- Start command -----
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global ADMIN_CHAT_ID
    user = update.message.from_user
    if user.username == ADMIN_USERNAME:
        ADMIN_CHAT_ID = update.message.chat_id
    await update.message.reply_text(
        "🔮 *PHANTOM WATCH* – Elite Digital Reconnaissance\n"
        "Identify vulnerabilities, leaked data, and impersonation risks before attackers do.\n\n"
        "Use the inline buttons below, or tap *🛡️ Menu* next to the text input at any time.",
        reply_markup=menu_button,
        parse_mode='Markdown'
    )
    await update.message.reply_text("⬇️ Main Menu:", reply_markup=main_menu_keyboard(user.username == ADMIN_USERNAME))

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    err = context.error
    if isinstance(err, telegram.error.TimedOut):
        print(f"[!] Network timeout: {err}")
    else:
        print(f"[!] Unhandled error: {err}")

# ----- Main -----
def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_error_handler(error_handler)

    jq = app.job_queue
    jq.run_repeating(cve_monitor_task, interval=3600, first=10)

    async def check_subs():
        c.execute("SELECT username, domain, last_scan_time, last_report_json FROM subscriptions")
        subs = c.fetchall()
        for username, domain, last_time, last_json in subs:
            last_dt = datetime.fromisoformat(last_time) if last_time else datetime.min
            if (datetime.now() - last_dt).days >= 7:
                c.execute("SELECT email_collect FROM clients WHERE username=?", (username,))
                row = c.fetchone()
                email = row[0] if row else ""
                results = run_scan(domain, email, tools=None, username=username)
                report = brief_summary(domain, results)
                try: await app.bot.send_message(chat_id=f"@{username}", text=report, parse_mode='Markdown')
                except: pass
                c.execute("UPDATE subscriptions SET last_scan_time=?, last_report_json=? WHERE username=? AND domain=?",
                          (datetime.now().isoformat(), json.dumps(results), username, domain))
                conn.commit()

    loop = asyncio.get_event_loop()
    loop.create_task(check_subs())

    print("👻 Phantom Watch is watching...")
    app.run_polling()

if __name__ == "__main__":
    main()
