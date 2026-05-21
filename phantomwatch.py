#!/usr/bin/env python3
"""
Phantom Watch – Elite Digital Reconnaissance System
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
) = range(7)

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

# ---------- Scan Engine ----------
def run_scan(domain: str, email: str = "", progress_callback=None, tools: list = None) -> dict:
    if tools is None:
        tools = ["nmap", "nikto", "whatweb", "theHarvester", "dnstwist", "metagoofil", "sherlock"]
    results = {}
    for tool in tools:
        if tool == "nmap":
            if progress_callback: progress_callback("⚡ Nmap scanning ports & vulns...")
            results['nmap'] = run_command(f"nmap -sV -T4 --script vuln --top-ports 200 {domain}")
        elif tool == "nikto":
            if progress_callback: progress_callback("🕵️ Nikto web server analysis...")
            results['nikto'] = run_command(f"nikto -h {domain} -T 123bde -maxtime 120s")
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
        elif tool == "metagoofil":
            if progress_callback: progress_callback("📄 Metagoofil extracting metadata...")
            results['metagoofil'] = run_command(
                f"cd /home/runner/metagoofil && python3 metagoofil.py -d {domain} -t pdf,doc,xls -l 10 -n 5 -o /tmp/meta_{domain} -f meta_{domain}.html"
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
            results['sherlock'] = run_command(f"cd /home/runner/sherlock && python3 sherlock.py {company_name} --timeout 10")
    report_text = json.dumps(results, indent=2)
    c.execute("INSERT INTO scan_results (username, domain, timestamp, report) VALUES (?,?,?,?)",
              ("reserved", domain, datetime.now().isoformat(), report_text))
    conn.commit()
    return results

# ==================== REPORT WITH BOLD HIGHLIGHTS ====================
def format_report(domain: str, results: dict) -> str:
    """Structured report with bold labels for easy reading. Markdown enabled."""
    now = datetime.now().strftime('%Y-%m-%d %H:%M')
    report = []
    report.append(f"🔍 *PHANTOM WATCH SECURITY REPORT*")
    report.append(f"Domain: `{domain}`")
    report.append(f"Generated: {now}")
    report.append("─" * 35)

    # ---------- TECHNOLOGY STACK ----------
    if 'whatweb' in results:
        clean = re.sub(r'\x1b\[[0-9;]*m', '', results['whatweb'])
        server = re.findall(r'HTTPServer\[ (.*?) \]', clean)
        has_cloudflare = 'Cloudflare' in clean or 'cloudflare' in clean
        has_403 = '403' in clean
        ips = re.findall(r'IP\[ ([^\]]+) \]', clean)
        report.append("\n🧩 *TECHNOLOGY STACK*")
        if server: report.append(f"  • Web Server : {server[0]}")
        if has_cloudflare: report.append("  • CDN/WAF    : Cloudflare (extra protection)")
        if has_403: report.append("  • Access     : 403 Forbidden (good hardening)")
        if ips: report.append(f"  • IPs Found  : {', '.join(ips[:3])}")
        if not (server or has_cloudflare or has_403 or ips):
            report.append("  No detailed technology info captured.")

    # ---------- NETWORK & PORT EXPOSURE ----------
    if 'nmap' in results:
        report.append("\n" + "─" * 35)
        report.append("🛡️ *NETWORK & PORT EXPOSURE (Nmap)*")
        open_ports = re.findall(r"^\d+/tcp\s+open\s+(.*)", results['nmap'], re.MULTILINE)
        vulns = re.findall(r"\|.*VULNERABLE.*", results['nmap'])
        if open_ports:
            for port_line in open_ports[:5]:
                report.append(f"  • *Finding:* Open port {port_line}")
                report.append(f"    *Exploitation:* Attackers can exploit outdated services, brute‑force, or gain unauthorised access.")
                report.append(f"    *Remediation:* Close if not needed, apply firewall, patch regularly, use VPN for admin ports.")
        if vulns:
            for v in vulns[:3]:
                clean_v = v.replace('|','').strip()
                report.append(f"  • *Finding:* Vulnerability detected – {clean_v}")
                report.append(f"    *Exploitation:* May allow remote code execution, data theft, or service disruption.")
                report.append(f"    *Remediation:* Apply latest patches, review CVE details, run thorough pentest.")
        if not open_ports and not vulns:
            report.append("  No open ports or known vulns detected.")

    # ---------- WEB APPLICATION ISSUES (Nikto) ----------
    if 'nikto' in results:
        report.append("\n" + "─" * 35)
        report.append("🔥 *WEB APPLICATION ISSUES (Nikto)*")
        findings = re.findall(r"\+ (.*)", results['nikto'])
        if findings:
            for f in findings[:5]:
                report.append(f"  • *Finding:* {f}")
                report.append(f"    *Exploitation:* Outdated software, missing headers, or sensitive files can lead to injection, data leaks, or defacement.")
                report.append(f"    *Remediation:* Update all components, add security headers (CSP, X‑Frame‑Options), remove backup/test files.")
        else:
            report.append("  No specific issues found.")

    # ---------- EMAIL & OSINT LEAKS ----------
    if 'theHarvester' in results and results['theHarvester'] != "No email provided for OSINT.":
        report.append("\n" + "─" * 35)
        report.append("📧 *EMAIL & OSINT LEAKS (theHarvester)*")
        harvest = results['theHarvester']
        emails = []
        if "<html" in harvest.lower():
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", harvest)
        if emails:
            report.append(f"  • *Finding:* Leaked emails ({len(emails)}) – {', '.join(emails[:5])}")
            report.append(f"    *Exploitation:* Phishing, credential stuffing, social engineering.")
            report.append(f"    *Remediation:* Implement SPF/DKIM/DMARC, train staff, use generic contact forms.")
        else:
            report.append("  No emails harvested (set email for deeper scan).")
    elif 'theHarvester' in results:
        report.append("\n" + "─" * 35)
        report.append("📧 *EMAIL & OSINT LEAKS (theHarvester)*")
        report.append("  No email provided – email OSINT skipped.")

    # ---------- TYPOSQUATTING ----------
    if 'dnstwist' in results:
        report.append("\n" + "─" * 35)
        report.append("🕵️ *TYPOSQUATTING RISK (dnstwist)*")
        registered = re.findall(r"^([^ ]+)\s+registered.*", results['dnstwist'], re.MULTILINE)
        if registered:
            for d in registered[:5]:
                report.append(f"  • *Finding:* Similar domain registered – {d}")
                report.append(f"    *Exploitation:* Phishing site could steal customer credentials.")
                report.append(f"    *Remediation:* Monitor registrations, consider buying similar domains, report to registrar.")
        else:
            report.append("  No suspicious similar domains registered.")

    # ---------- DOCUMENT METADATA ----------
    if 'metagoofil' in results and 'No dangerous' not in results['metagoofil']:
        report.append("\n" + "─" * 35)
        report.append("📄 *DOCUMENT METADATA EXPOSURE (Metagoofil)*")
        meta = results['metagoofil']
        if 'usernames' in meta.lower() or 'path' in meta.lower():
            report.append("  • *Finding:* Sensitive info (usernames/paths) found in public documents.")
        else:
            report.append(f"  • *Finding:* {meta[:200]}")
        report.append(f"    *Exploitation:* Metadata reveals internal paths/software for targeted attacks.")
        report.append(f"    *Remediation:* Strip metadata before publishing, avoid internal names in public docs.")
    elif 'metagoofil' in results:
        report.append("\n" + "─" * 35)
        report.append("📄 *DOCUMENT METADATA (Metagoofil)*")
        report.append("  No leaks detected.")

    # ---------- SOCIAL MEDIA ----------
    if 'sherlock' in results:
        report.append("\n" + "─" * 35)
        report.append("👥 *SOCIAL MEDIA PRESENCE (Sherlock)*")
        found = re.findall(r"\[\+\] (.*)", results['sherlock'])
        if found:
            for line in found[:5]:
                report.append(f"  • *Finding:* Account found – {line}")
            report.append(f"    *Exploitation:* Impersonation, social engineering, password guessing.")
            report.append(f"    *Remediation:* Review privacy settings, enable 2FA, remove unused profiles.")
        else:
            report.append("  No accounts detected for the domain name.")

    report.append("\n" + "─" * 35)
    report.append("*Report generated by Phantom Watch – Elite Reconnaissance*")
    report.append("_Always consult a professional for full assessment._")
    return "\n".join(report)

# ==================== TOOL HELP TEXT ====================
TOOL_HELP = {
    "nmap": (
        "*⚡ Nmap (Network Mapper)*\n"
        "Scans for open ports, running services, OS detection, and known vulnerabilities.\n"
        "Used by hackers to find entry points like outdated SSH, RDP, or vulnerable web servers.\n"
        "*Protection:* Close unnecessary ports, use a firewall, keep services updated, and hide version banners."
    ),
    "nikto": (
        "*🕵️ Nikto*\n"
        "Scans web servers for dangerous files, misconfigurations, outdated software, and insecure headers.\n"
        "Attackers exploit these to inject code, deface sites, or steal data.\n"
        "*Protection:* Regularly update CMS/plugins, add security headers (CSP, X-Frame-Options), and remove default files."
    ),
    "whatweb": (
        "*🔎 WhatWeb*\n"
        "Identifies technologies used on a website (CMS, frameworks, analytics, CDN, etc.).\n"
        "Hackers fingerprint the stack to launch targeted attacks against known vulnerabilities.\n"
        "*Protection:* Mask technology signatures (e.g., modify headers), keep all components patched, and use a WAF."
    ),
    "theHarvester": (
        "*📧 theHarvester*\n"
        "Gathers emails, subdomains, IPs, and other OSINT from public sources.\n"
        "Threat actors use this for phishing campaigns, credential stuffing, and social engineering.\n"
        "*Protection:* Implement DMARC/SPF/DKIM, use generic contact forms, and train staff to recognise phishing."
    ),
    "dnstwist": (
        "*🔄 dnstwist*\n"
        "Detects typosquatting domains (e.g., googlle.com) that could be used to impersonate your brand.\n"
        "Phishers register look‑alike domains to steal customer credentials.\n"
        "*Protection:* Monitor domain registrations, purchase similar domains, and report fraudulent ones to the registrar."
    ),
    "metagoofil": (
        "*📄 Metagoofil*\n"
        "Extracts metadata from public documents (PDF, DOC, XLS) to find usernames, software versions, and paths.\n"
        "This info helps attackers craft precise social engineering attacks or exploit internal software.\n"
        "*Protection:* Strip metadata before publishing, avoid including internal paths or personal names in public files."
    ),
    "sherlock": (
        "*👤 Sherlock*\n"
        "Checks if a username is registered on various social media platforms.\n"
        "Hackers use this to impersonate brands, gather intelligence, or launch targeted phishing via social channels.\n"
        "*Protection:* Secure social accounts with 2FA, review privacy settings, and remove unused profiles."
    ),
}

def get_full_help_text() -> str:
    return "\n\n".join(TOOL_HELP.values())

# ==================== BUTTON MENUS (compact, two buttons per row) ====================
def main_menu_keyboard(user_is_admin=False):
    buttons = [
        [InlineKeyboardButton("🔍 Full Scan", callback_data="scan_full"),
         InlineKeyboardButton("⚡ Quick Scan", callback_data="scan_quick")],
        [InlineKeyboardButton("📧 Set Email", callback_data="set_email"),
         InlineKeyboardButton("📖 How It Works", callback_data="how_it_works")],
        [InlineKeyboardButton("❓ Help", callback_data="help")],
    ]
    if user_is_admin:
        buttons.append([InlineKeyboardButton("👑 Admin Menu", callback_data="admin_menu")])
    return InlineKeyboardMarkup(buttons)

def admin_menu_keyboard():
    buttons = [
        [InlineKeyboardButton("➕ Add User", callback_data="admin_adduser"),
         InlineKeyboardButton("✅ Verify Domain", callback_data="admin_verify")],
        [InlineKeyboardButton("📊 Status", callback_data="admin_status"),
         InlineKeyboardButton("🔙 Main Menu", callback_data="main_menu")],
    ]
    return InlineKeyboardMarkup(buttons)

def quick_scan_keyboard():
    buttons = [
        [InlineKeyboardButton("🛡️ Ports & Vulns", callback_data="quick_ports")],
        [InlineKeyboardButton("🌐 OSINT Pack", callback_data="quick_osint")],
        [InlineKeyboardButton("🔎 Recon", callback_data="quick_recon")],
        [InlineKeyboardButton("🔙 Main Menu", callback_data="main_menu")],
    ]
    return InlineKeyboardMarkup(buttons)

# Persistent menu button next to text field
menu_button = ReplyKeyboardMarkup(
    [[KeyboardButton("🛡️ Menu")]], resize_keyboard=True, one_time_keyboard=False
)

# ==================== CALLBACK HANDLER ====================
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    username = query.from_user.username

    if data == "main_menu":
        await query.edit_message_text("🔮 Phantom Watch – Main Menu", reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))
        return

    if data in ["scan_full", "scan_quick"]:
        if not is_subscription_active(username):
            await query.edit_message_text("⛔ Subscription expired. Contact admin.")
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
        if data == "quick_ports":
            tools = ["nmap", "nikto"]
        elif data == "quick_osint":
            tools = ["theHarvester", "sherlock"]
        elif data == "quick_recon":
            tools = ["whatweb", "dnstwist", "metagoofil"]
        else:
            tools = None
        context.user_data['scan_type'] = 'quick'
        context.user_data['tools'] = tools
        await query.edit_message_text("📌 Send the domain name to scan.")
        context.user_data['state'] = SCAN_DOMAIN
        return

    if data == "set_email":
        if not is_subscription_active(username):
            await query.edit_message_text("⛔ Subscription expired.")
            return
        await query.edit_message_text("📧 Please send your email address:")
        context.user_data['state'] = SET_EMAIL
        return

    if data == "how_it_works":
        how_text = (
            "📖 *How Phantom Watch Operates*\n\n"
            "1️⃣ *Registration* – The administrator adds your Telegram account and verifies ownership of your domain.\n"
            "2️⃣ *Scan Selection* – Choose a comprehensive *Full Scan* (all reconnaissance modules) or a *Quick Scan* for specific areas.\n"
            "3️⃣ *Live Monitoring* – Watch real‑time progress as each security tool runs. You'll know exactly what is being checked.\n"
            "4️⃣ *Detailed Report* – Receive a structured report highlighting every finding, how it could be exploited, and clear remediation steps.\n"
            "5️⃣ *Continuous Protection* – Use the insights to close vulnerabilities before malicious actors discover them.\n\n"
            "💡 *Recommendation:* Set your email via the 📧 button to uncover exposed credentials associated with your domain."
        )
        await context.bot.send_message(chat_id=query.message.chat_id, text=how_text, parse_mode='Markdown')
        await query.edit_message_text("🔮 Return to main menu:", reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))
        return

    if data == "help":
        help_text = get_full_help_text()
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

# ==================== MESSAGE HANDLER (states) ====================
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.message.from_user
    username = user.username
    text = update.message.text.strip()
    state = context.user_data.get('state')

    # Persistent menu button tap
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

            c.execute("SELECT email_collect FROM clients WHERE username=?", (username,))
            row = c.fetchone()
            email = row[0] if row else ""
            tools = context.user_data.get('tools', None)

            try:
                results = await loop.run_in_executor(None, run_scan, domain, email, sync_progress, tools)
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

        # Build report and send with Markdown for bold
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

    # Fallback
    await update.message.reply_text(
        "I didn't understand. Use the buttons, or tap *🛡️ Menu* next to the text field.",
        reply_markup=main_menu_keyboard(username == ADMIN_USERNAME),
        parse_mode='Markdown'
    )

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

# ==================== MAIN ====================
def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_error_handler(error_handler)

    print("👻 Phantom Watch is watching...")
    app.run_polling()

if __name__ == "__main__":
    main()
