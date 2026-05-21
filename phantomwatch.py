#!/usr/bin/env python3
"""
Phantom Watch – Elite Digital Reconnaissance with Max-Depth, Breach Intel, Continuous Monitoring
"""

import subprocess, re, os, sqlite3, random, string, shutil, json, time, asyncio
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

# ========== CONFIGURATION ==========
BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_CHAT_ID = None
DB_FILE = "phantom_clients.db"
SCAN_TIMEOUT = 150
MAX_CONCURRENT_SCANS = 5
# ===================================

# Conversation states
(
    ADDUSER_USERNAME,
    ADDUSER_PLAN,
    ADDUSER_MONTHS,
    VERIFY_USERNAME,
    VERIFY_DOMAIN,
    SCAN_DOMAIN,
    SET_EMAIL,
    SUBSCRIBE_DOMAIN,
) = range(8)

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
    report TEXT
)''')
c.execute('''CREATE TABLE IF NOT EXISTS subscriptions (
    username TEXT, domain TEXT,
    last_scan_time TEXT, last_report_json TEXT,
    PRIMARY KEY(username, domain)
)''')
conn.commit()

# ---------- Helpers ----------
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

def add_client(username: str, plan: str = "free", expiry: str = ""):
    c.execute("INSERT OR REPLACE INTO clients VALUES (?,?,?,?)",
              (username, plan, expiry, ""))
    conn.commit()

def set_plan(username: str, plan: str, months: int):
    new_expiry = (datetime.now() + timedelta(days=30*months)).strftime("%Y-%m-%d")
    c.execute("UPDATE clients SET plan=?, expiry=? WHERE username=?",
              (plan, new_expiry, username))
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
    global ADMIN_CHAT_ID
    if ADMIN_CHAT_ID:
        try:
            await context.bot.send_message(chat_id=ADMIN_CHAT_ID, text=text)
        except Exception as e:
            print(f"[!] Could not notify admin: {e}")

# ---------- Breach Check (free XposedOrNot + optional HIBP) ----------
async def check_breach(email: str, context: ContextTypes.DEFAULT_TYPE, chat_id: int):
    """Check breaches using XposedOrNot (free, no key) + optional HIBP fallback."""
    # XposedOrNot
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
    except Exception:
        pass

    # Fallback HIBP (if API key configured)
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
        except Exception:
            pass

    await context.bot.send_message(chat_id=chat_id, text="✅ No breaches found for this email.")

# ---------- Animated Progress Bar ----------
async def send_animation(chat_id, context, stop_event):
    frames = ["[▓░░░░░░░░] 10%", "[▓▓░░░░░░░] 20%", "[▓▓▓░░░░░░] 30%", "[▓▓▓▓░░░░░] 40%",
              "[▓▓▓▓▓░░░░] 50%", "[▓▓▓▓▓▓░░░] 60%", "[▓▓▓▓▓▓▓░░] 70%", "[▓▓▓▓▓▓▓▓░] 80%",
              "[▓▓▓▓▓▓▓▓▓] 90%", "[▓▓▓▓▓▓▓▓▓] 99%"]
    idx = 0
    msg = await context.bot.send_message(chat_id=chat_id, text="🔥 Scanning started...")
    while not stop_event.is_set():
        await asyncio.sleep(10)
        if stop_event.is_set():
            break
        frame = frames[idx % len(frames)]
        try:
            await msg.edit_text(f"🔄 {frame} Scan in progress...")
        except:
            pass
        idx += 1
    try:
        await msg.delete()
    except:
        pass

# ---------- Scan Engine (max depth, includes Dalfox) ----------
def run_scan(domain: str, email: str = "", progress_callback=None, tools: list = None, instant_callback=None) -> dict:
    if tools is None:
        tools = ["nmap", "nikto", "whatweb", "theHarvester", "dnstwist", "metagoofil", "sherlock", "dalfox"]
    results = {}
    for tool in tools:
        if tool == "nmap":
            if progress_callback: progress_callback("⚡ Nmap (max‑depth) scanning ports & vulns...")
            raw = run_command(f"nmap -sV -T4 -p- --script vuln,exploit,auth,default,discovery {domain}", timeout=300)
            results['nmap'] = raw
            if instant_callback:
                vulns = re.findall(r"\|.*VULNERABLE.*", raw)
                if vulns:
                    instant_callback(f"🔴 CRITICAL Nmap: {len(vulns)} potential vulnerabilities found!")
        elif tool == "nikto":
            if progress_callback: progress_callback("🕵️ Nikto (full) web server analysis...")
            raw = run_command(f"nikto -h {domain} -T 0123456789abcde -maxtime 300s", timeout=300)
            results['nikto'] = raw
            if instant_callback:
                findings = re.findall(r"\+ (.*)", raw)
                if findings:
                    instant_callback(f"🕵️ Nikto found {len(findings)} issues so far...")
        elif tool == "whatweb":
            if progress_callback: progress_callback("🔎 WhatWeb detecting technologies...")
            results['whatweb'] = run_command(f"whatweb {domain}")
        elif tool == "theHarvester":
            if email:
                results['theHarvester'] = run_command(f"theHarvester -d {domain} -b google -f report_{domain}.html")
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
            if progress_callback: progress_callback("🔄 dnstwist checking similar domains...")
            results['dnstwist'] = run_command(f"dnstwist {domain}")
            if instant_callback:
                registered = re.findall(r"^([^ ]+)\s+registered.*", results['dnstwist'], re.MULTILINE)
                if registered:
                    instant_callback(f"🔄 dnstwist: {len(registered)} typosquatting domains registered!")
        elif tool == "metagoofil":
            if progress_callback: progress_callback("📄 Metagoofil extracting metadata (deep)...")
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
            if progress_callback: progress_callback("👤 Sherlock searching social media...")
            company_name = domain.split('.')[0]
            raw = run_command(f"cd /home/runner/sherlock && python3 sherlock.py {company_name} --timeout 20", timeout=200)
            results['sherlock'] = raw
            if instant_callback:
                found = re.findall(r"\[\+\] (.*)", raw)
                if found:
                    instant_callback(f"👤 Sherlock: {len(found)} social media accounts found.")
        elif tool == "dalfox":
            if progress_callback: progress_callback("🦠 Dalfox scanning for XSS...")
            raw = run_command(f"dalfox url http://{domain} --silence", timeout=200)
            results['dalfox'] = raw
            if instant_callback:
                if "vulnerable" in raw.lower():
                    instant_callback("🔴 CRITICAL: Dalfox detected XSS vulnerabilities!")
    report_text = json.dumps(results, indent=2)
    c.execute("INSERT INTO scan_results (username, domain, timestamp, report) VALUES (?,?,?,?)",
              ("reserved", domain, datetime.now().isoformat(), report_text))
    conn.commit()
    return results

# ==================== BOLD REPORT (Diff-capable) ====================
def format_report(domain: str, results: dict, previous_results: dict = None) -> str:
    now = datetime.now().strftime('%Y-%m-%d %H:%M')
    lines = []
    lines.append(f"🔍 *PHANTOM WATCH SECURITY REPORT*")
    lines.append(f"Domain: `{domain}`")
    lines.append(f"Generated: {now}")
    if previous_results:
        lines.append("📌 *Changes since last scan* – only new/updated findings shown.")
    lines.append("─" * 35)

    def add_finding(title, raw, regex, label, exploit, remediation):
        if not raw:
            return
        items = re.findall(regex, raw, re.MULTILINE)
        if not items:
            return
        if previous_results and title in previous_results:
            prev_raw = previous_results.get(title, "")
            prev_items = re.findall(regex, prev_raw, re.MULTILINE)
            items = [i for i in items if i not in prev_items]
            if not items:
                return
        lines.append(f"\n{title}")
        for item in items[:5]:
            lines.append(f"  • *Finding:* {item}")
            lines.append(f"    *Exploitation:* {exploit}")
            lines.append(f"    *Remediation:* {remediation}")
        if len(items) > 5:
            lines.append(f"  ... and {len(items)-5} more.")

    # Technology stack
    if 'whatweb' in results:
        clean = re.sub(r'\x1b\[[0-9;]*m', '', results['whatweb'])
        lines.append("\n🧩 *TECHNOLOGY STACK*")
        server = re.findall(r'HTTPServer\[ (.*?) \]', clean)
        if server: lines.append(f"  • Web Server: {server[0]}")
        ips = re.findall(r'IP\[ ([^\]]+) \]', clean)
        if ips: lines.append(f"  • IPs: {', '.join(ips[:3])}")
        if 'Cloudflare' in clean: lines.append("  • Cloudflare detected (WAF)")

    add_finding("🛡️ NETWORK & PORTS (Nmap)", results.get('nmap'),
                r"^\d+/tcp\s+open\s+(.*)", "Open port",
                "Attackers can brute‑force or exploit outdated services.",
                "Close unnecessary ports, use firewall, keep services updated, restrict admin access.")
    add_finding("⚠️ Nmap VULNERABILITIES", results.get('nmap'),
                r"\|.*VULNERABLE.*", "Vulnerability",
                "Exploitable service (CVE).", "Apply patches immediately, review CVE details.")
    add_finding("🔥 NIKTO WEB ISSUES", results.get('nikto'),
                r"\+ (.*)", "Nikto finding",
                "Outdated software, missing headers, or dangerous files.",
                "Update all components, add security headers (CSP, X‑Frame‑Options), remove backup files.")
    add_finding("🦠 DALFOX XSS", results.get('dalfox'),
                r"\[.*\]\s+.*", "XSS vulnerability",
                "Inject malicious scripts into website.",
                "Sanitise input/output, use Content‑Security‑Policy, escape output.")

    if 'theHarvester' in results and results['theHarvester'] != "No email provided for OSINT.":
        harvest = results['theHarvester']
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", harvest) if "<html" in harvest.lower() else []
        if emails:
            lines.append("\n📧 *EMAIL & OSINT LEAKS*")
            lines.append(f"  • Leaked emails ({len(emails)}): {', '.join(emails[:5])}")
            lines.append("    *Exploitation:* Phishing, credential stuffing.")
            lines.append("    *Remediation:* Implement SPF/DKIM/DMARC, train staff.")
        else:
            lines.append("\n📧 *EMAIL & OSINT* – No emails harvested (set email for deeper scan).")
    elif 'theHarvester' in results:
        lines.append("\n📧 *EMAIL & OSINT* – Email not provided, skipped.")

    add_finding("🕵️ TYPOSQUATTING", results.get('dnstwist'),
                r"^([^ ]+)\s+registered.*", "Registered domain",
                "Phishing site could steal credentials.", "Monitor registrations, buy similar domains, report abuse.")

    if 'metagoofil' in results and results['metagoofil'] != "No metadata found or command failed.":
        meta = results['metagoofil']
        lines.append("\n📄 *DOCUMENT METADATA*")
        if 'usernames' in meta.lower() or 'path' in meta.lower():
            lines.append("  • Sensitive info (usernames/paths) found in public documents.")
            lines.append("    *Exploitation:* Reveals internal structure for targeted attacks.")
            lines.append("    *Remediation:* Strip metadata before publishing.")

    add_finding("👥 SOCIAL MEDIA", results.get('sherlock'),
                r"\[\+\] (.*)", "Account found",
                "Impersonation, social engineering.", "Enable 2FA, review privacy settings, remove unused profiles.")

    lines.append("\n" + "─" * 35)
    lines.append("*Report generated by Phantom Watch – Elite Reconnaissance*")
    return "\n".join(lines)

# ==================== BUTTON MENUS ====================
def main_menu_keyboard(user_is_admin=False):
    buttons = [
        [InlineKeyboardButton("🔍 Full Scan", callback_data="scan_full"),
         InlineKeyboardButton("⚡ Quick Scan", callback_data="scan_quick")],
        [InlineKeyboardButton("📧 Set Email", callback_data="set_email"),
         InlineKeyboardButton("📖 How It Works", callback_data="how_it_works")],
        [InlineKeyboardButton("❓ Help", callback_data="help"),
         InlineKeyboardButton("🩸 Check Breaches", callback_data="check_breaches")],
        [InlineKeyboardButton("🔔 Subscribe", callback_data="subscribe")],
    ]
    if user_is_admin:
        buttons.append([InlineKeyboardButton("👑 Admin Menu", callback_data="admin_menu")])
    return InlineKeyboardMarkup(buttons)

def admin_menu_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Add User", callback_data="admin_adduser"),
         InlineKeyboardButton("✅ Verify Domain", callback_data="admin_verify")],
        [InlineKeyboardButton("📊 Status", callback_data="admin_status"),
         InlineKeyboardButton("🔙 Main Menu", callback_data="main_menu")],
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

# ==================== CALLBACK HANDLER ====================
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
            await query.edit_message_text("⛔ Subscription expired.")
            return
        c.execute("SELECT email_collect FROM clients WHERE username=?", (username,))
        row = c.fetchone()
        email = row[0] if row else ""
        if not email:
            await query.edit_message_text("📧 Please set your email first using the *Set Email* button.", parse_mode='Markdown')
        else:
            await query.edit_message_text("🩸 Checking breaches...")
            await check_breach(email, context, query.message.chat_id)
        return

    if data == "subscribe":
        if not is_subscription_active(username):
            await query.edit_message_text("⛔ Subscription expired.")
            return
        await query.edit_message_text("📌 Send the domain you want to monitor weekly:")
        context.user_data['state'] = SUBSCRIBE_DOMAIN
        return

    if data in ["scan_full", "scan_quick"]:
        if not is_subscription_active(username):
            await query.edit_message_text("⛔ Subscription expired.")
            return
        if data == "scan_full":
            context.user_data['scan_type'] = 'full'
            context.user_data['tools'] = None
        else:
            await query.edit_message_text("Choose a quick scan type:", reply_markup=quick_scan_keyboard())
            return
        await query.edit_message_text("📌 Send the domain name (e.g., example.com) to scan.")
        context.user_data['state'] = SCAN_DOMAIN
        return

    if data.startswith("quick_"):
        if not is_subscription_active(username):
            await query.edit_message_text("⛔ Subscription expired.")
            return
        if data == "quick_ports": tools = ["nmap", "nikto"]
        elif data == "quick_osint": tools = ["theHarvester", "sherlock"]
        elif data == "quick_recon": tools = ["whatweb", "dnstwist", "metagoofil"]
        elif data == "quick_xss": tools = ["dalfox"]
        context.user_data['tools'] = tools
        context.user_data['scan_type'] = 'quick'
        await query.edit_message_text("📌 Send the domain name to scan.")
        context.user_data['state'] = SCAN_DOMAIN
        return

    if data == "set_email":
        await query.edit_message_text("📧 Please send your email address:")
        context.user_data['state'] = SET_EMAIL
        return

    if data == "how_it_works":
        how_text = (
            "📖 *How Phantom Watch Operates*\n"
            "1️⃣ *Registration* – Admin adds you & verifies your domain.\n"
            "2️⃣ *Choose a Scan* – Full (all tools) or Quick (targeted).\n"
            "3️⃣ *Live Monitoring* – Instant alerts for critical findings.\n"
            "4️⃣ *Detailed Report* – Bold highlights, exploitation & remediation steps.\n"
            "5️⃣ *Continuous Protection* – Subscribe to weekly scans & breach checks.\n"
            "💡 Set your email to enable breach intelligence."
        )
        await context.bot.send_message(chat_id=query.message.chat_id, text=how_text, parse_mode='Markdown')
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
            "*🩸 Breach Check* – Checks email against known data breaches.\nProtection: change compromised passwords, enable 2FA."
        ])
        for i in range(0, len(help_text), 4000):
            await context.bot.send_message(chat_id=query.message.chat_id, text=help_text[i:i+4000], parse_mode='Markdown')
        await query.edit_message_text("🔮 Return to main menu:", reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))
        return

    # Admin menus
    if data == "admin_menu":
        if username != ADMIN_USERNAME:
            await query.edit_message_text("❌ Admin only.")
            return
        await query.edit_message_text("👑 Admin Panel", reply_markup=admin_menu_keyboard())
        return

    if data == "admin_adduser":
        if username != ADMIN_USERNAME: return
        await query.edit_message_text("Enter the Telegram username of the client (with @):")
        context.user_data['state'] = ADDUSER_USERNAME
        return

    if data == "admin_verify":
        if username != ADMIN_USERNAME: return
        await query.edit_message_text("Enter the username of the client (with @):")
        context.user_data['state'] = VERIFY_USERNAME
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

# ==================== MESSAGE HANDLER (ALL STATES) ====================
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.message.from_user
    username = user.username
    text = update.message.text.strip()
    state = context.user_data.get('state')

    # Persistent menu button
    if text == "🛡️ Menu":
        await update.message.reply_text("Menu:", reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))
        return

    # ----- ADMIN ADD USER WIZARD -----
    if state == ADDUSER_USERNAME:
        if username != ADMIN_USERNAME:
            await update.message.reply_text("❌ Admin only.")
            return
        target = text.lstrip('@')
        if not target:
            await update.message.reply_text("Invalid. Enter username with @:")
            return
        context.user_data['add_target'] = target
        await update.message.reply_text("Plan? (free, monthly, enterprise):")
        context.user_data['state'] = ADDUSER_PLAN
        return

    if state == ADDUSER_PLAN:
        plan = text.lower()
        if plan not in ["free", "monthly", "enterprise"]:
            await update.message.reply_text("Invalid plan. Use free, monthly, or enterprise:")
            return
        context.user_data['add_plan'] = plan
        await update.message.reply_text("How many months? (0 for default free trial):")
        context.user_data['state'] = ADDUSER_MONTHS
        return

    if state == ADDUSER_MONTHS:
        try:
            months = int(text)
        except:
            await update.message.reply_text("Enter a number (0-12):")
            return
        target = context.user_data['add_target']
        plan = context.user_data['add_plan']
        add_client(target, plan)
        if plan == "free":
            set_free_expiry(target)
        elif months > 0:
            set_plan(target, plan, months)
        await update.message.reply_text(f"✅ Added @{target} with {plan} plan for {months} months.",
                                        reply_markup=admin_menu_keyboard())
        for k in ('add_target', 'add_plan', 'state'):
            context.user_data.pop(k, None)
        return

    # ----- ADMIN VERIFY DOMAIN WIZARD -----
    if state == VERIFY_USERNAME:
        if username != ADMIN_USERNAME:
            await update.message.reply_text("❌ Admin only.")
            return
        target = text.lstrip('@')
        if not is_client(target):
            await update.message.reply_text("User not a client. Add them first.")
            return
        context.user_data['verify_target'] = target
        await update.message.reply_text("Domain to verify (e.g., example.com):")
        context.user_data['state'] = VERIFY_DOMAIN
        return

    if state == VERIFY_DOMAIN:
        target = context.user_data['verify_target']
        domain = text.lower()
        c.execute("INSERT OR REPLACE INTO verification VALUES (?,?,?)",
                  (target, domain, "admin_verified"))
        conn.commit()
        await update.message.reply_text(f"✅ Domain {domain} manually verified for @{target}.",
                                        reply_markup=admin_menu_keyboard())
        for k in ('verify_target', 'state'):
            context.user_data.pop(k, None)
        return

    # ----- CLIENT SET EMAIL -----
    if state == SET_EMAIL:
        if '@' not in text:
            await update.message.reply_text("Invalid email. Send again:")
            return
        c.execute("UPDATE clients SET email_collect=? WHERE username=?", (text, username))
        conn.commit()
        await update.message.reply_text(f"✅ Email set to {text}.", reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))
        context.user_data.pop('state', None)
        return

    # ----- CLIENT SUBSCRIBE DOMAIN -----
    if state == SUBSCRIBE_DOMAIN:
        domain = text.lower()
        if not re.match(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', domain):
            await update.message.reply_text("Invalid domain.")
            return
        c.execute("INSERT OR REPLACE INTO subscriptions VALUES (?,?,?,?)",
                  (username, domain, datetime.now().isoformat(), "{}"))
        conn.commit()
        await update.message.reply_text(f"✅ Subscribed to weekly scans for {domain}. You'll receive diff reports here.",
                                        reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))
        context.user_data.pop('state', None)
        return

    # ----- CLIENT SENDS DOMAIN FOR SCAN -----
    if state == SCAN_DOMAIN:
        domain = text.lower()
        if not re.match(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', domain):
            await update.message.reply_text("❌ Invalid domain. Please try again.")
            return

        if not is_subscription_active(username):
            await update.message.reply_text("⛔ Subscription expired or not authorized.")
            return

        # Verification
        if username != ADMIN_USERNAME:
            c.execute("SELECT token FROM verification WHERE username=? AND domain=?", (username, domain))
            row = c.fetchone()
            if row and row[0] == "admin_verified":
                pass
            elif row and row[0] != "admin_verified":
                if not verify_domain(domain, row[0]):
                    await update.message.reply_text("⏳ Verification file missing. Upload verify.txt or ask admin.")
                    return
            else:
                token = generate_token()
                c.execute("INSERT OR REPLACE INTO verification VALUES (?,?,?)", (username, domain, token))
                conn.commit()
                await update.message.reply_text(
                    f"🔐 Verify ownership: upload `verify.txt` with token `{token}` to root of your site.\n"
                    "Or ask admin for manual verification."
                )
                return

        # Concurrency control
        sem = context.bot_data.setdefault("scan_semaphore", asyncio.Semaphore(MAX_CONCURRENT_SCANS))
        if sem.locked():
            await update.message.reply_text("⏳ Server is busy. Please wait a moment and try again.")
            return

        await sem.acquire()
        try:
            await update.message.reply_text("✅ Domain verified. Launching scan...")
            chat_id = update.message.chat_id

            stop_anim = asyncio.Event()
            anim_task = asyncio.create_task(send_animation(chat_id, context, stop_anim))

            progress_msg = await context.bot.send_message(chat_id=chat_id, text="⚡ Preparing tools...")
            loop = asyncio.get_running_loop()
            def sync_progress(msg):
                async def _upd():
                    try:
                        await progress_msg.edit_text(msg)
                    except:
                        pass
                asyncio.run_coroutine_threadsafe(_upd(), loop)

            # Instant critical alert callback
            async def instant_alert(msg):
                await context.bot.send_message(chat_id=chat_id, text=msg)

            def instant_callback(msg):
                asyncio.run_coroutine_threadsafe(instant_alert(msg), loop)

            c.execute("SELECT email_collect FROM clients WHERE username=?", (username,))
            row = c.fetchone()
            email = row[0] if row else ""
            tools = context.user_data.get('tools', None)

            try:
                results = await loop.run_in_executor(None, run_scan, domain, email, sync_progress, tools, instant_callback)
            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                print(f"[!] Scan error: {tb}")
                await notify_admin(f"❌ Scan crashed for {domain}: {e}", context)
                await update.message.reply_text(f"❌ Scan encountered an error: {e}")
                results = {}
            finally:
                stop_anim.set()
                await anim_task
                try:
                    await progress_msg.delete()
                except:
                    pass
        finally:
            sem.release()

        report_text = format_report(domain, results) if results else "❌ No results (scan failed)."
        max_len = 4000
        for i in range(0, len(report_text), max_len):
            chunk = report_text[i:i+max_len]
            await context.bot.send_message(chat_id=chat_id, text=chunk, parse_mode='Markdown')

        context.user_data.pop('state', None)
        context.user_data.pop('scan_type', None)
        context.user_data.pop('tools', None)
        await update.message.reply_text("🔮 What's next?", reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))
        return

    # Fallback: show menu
    await update.message.reply_text("I didn't understand. Use the buttons below, or tap *🛡️ Menu* next to the text field.",
                                    reply_markup=main_menu_keyboard(username == ADMIN_USERNAME), parse_mode='Markdown')

# ==================== COMMAND HANDLERS ====================
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

# ==================== BACKGROUND SUBSCRIPTION SCANNER ====================
async def scan_subscriptions(app):
    c.execute("SELECT username, domain, last_scan_time, last_report_json FROM subscriptions")
    subs = c.fetchall()
    for username, domain, last_time, last_json in subs:
        last_dt = datetime.fromisoformat(last_time) if last_time else datetime.min
        if (datetime.now() - last_dt).days >= 7:
            c.execute("SELECT email_collect FROM clients WHERE username=?", (username,))
            row = c.fetchone()
            email = row[0] if row else ""
            results = run_scan(domain, email, tools=None)
            prev = json.loads(last_json) if last_json and last_json != "{}" else None
            report = format_report(domain, results, previous_results=prev)
            try:
                await app.bot.send_message(chat_id=f"@{username}", text=report, parse_mode='Markdown')
            except:
                pass
            c.execute("UPDATE subscriptions SET last_scan_time=?, last_report_json=? WHERE username=? AND domain=?",
                      (datetime.now().isoformat(), json.dumps(results), username, domain))
            conn.commit()

# ==================== MAIN ====================
def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_error_handler(error_handler)

    loop = asyncio.get_event_loop()
    loop.create_task(scan_subscriptions(app.bot))

    print("👻 Phantom Watch is watching...")
    app.run_polling()

if __name__ == "__main__":
    main()
