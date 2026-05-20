#!/usr/bin/env python3
"""
Phantom Watch – Automated Security Reconnaissance Bot (Menu-Enhanced)
"""

import subprocess, re, os, sqlite3, random, string, shutil, json, time
from datetime import datetime, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    filters,
    ContextTypes,
)
import telegram.error
import asyncio

# ========== CONFIGURATION ==========
BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_CHAT_ID = None
DB_FILE = "phantom_clients.db"
SCAN_TIMEOUT = 180
# ===================================

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

# ---------- Helper Functions (unchanged) ----------
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

# ---------- Scan Engine (with progress callback) ----------
def run_scan(domain: str, email: str = "", progress_callback=None, tools: list = None) -> dict:
    if tools is None:
        tools = ["nmap", "nikto", "whatweb", "theHarvester", "dnstwist", "metagoofil", "sherlock"]
    results = {}
    print(f"[*] Starting scan for {domain}")

    if "nmap" in tools:
        print("[*] Running Nmap...")
        results['nmap'] = run_command(f"nmap -sV -T4 --script vuln --top-ports 200 {domain}")
        if progress_callback:
            progress_callback("✅ Nmap finished.")

    if "nikto" in tools:
        print("[*] Running Nikto...")
        results['nikto'] = run_command(f"nikto -h {domain} -T 123bde -maxtime 120s")
        if progress_callback:
            progress_callback("✅ Nikto done.")

    if "whatweb" in tools:
        print("[*] Running WhatWeb...")
        results['whatweb'] = run_command(f"whatweb {domain}")
        if progress_callback:
            progress_callback("✅ WhatWeb completed.")

    if "theHarvester" in tools:
        if email:
            print("[*] Running theHarvester...")
            results['theHarvester'] = run_command(f"theHarvester -d {domain} -b google -f report_{domain}.html")
            if os.path.exists(f"report_{domain}.html"):
                with open(f"report_{domain}.html", "r") as f:
                    results['theHarvester'] = f.read()
                os.remove(f"report_{domain}.html")
            else:
                results['theHarvester'] = "No email results."
        else:
            results['theHarvester'] = "No email provided for OSINT."
        if progress_callback:
            progress_callback("✅ OSINT emails done.")

    if "dnstwist" in tools:
        print("[*] Running dnstwist...")
        results['dnstwist'] = run_command(f"dnstwist {domain}")
        if progress_callback:
            progress_callback("✅ Typosquatting check done.")

    if "metagoofil" in tools:
        print("[*] Running metagoofil...")
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
        if progress_callback:
            progress_callback("✅ Document metadata done.")

    if "sherlock" in tools:
        company_name = domain.split('.')[0]
        print("[*] Running Sherlock...")
        results['sherlock'] = run_command(f"cd /home/runner/sherlock && python3 sherlock.py {company_name} --timeout 10")
        if progress_callback:
            progress_callback("✅ Social media scan done.")

    # Store
    report_text = json.dumps(results, indent=2)
    c.execute("INSERT INTO scan_results (username, domain, timestamp, report) VALUES (?,?,?,?)",
              ("reserved", domain, datetime.now().isoformat(), report_text))
    conn.commit()
    print(f"[✓] Scan finished for {domain}")
    return results

def format_report(domain: str, results: dict) -> str:
    # same as before (truncated for brevity, but copy the complete one you had)
    now = datetime.now().strftime('%Y-%m-%d %H:%M')
    report = f"🔍 **PHANTOM WATCH SECURITY REPORT**\n`{domain}`\n_{now}_\n\n"

    if 'whatweb' in results:
        whatweb_raw = results['whatweb']
        clean = re.sub(r'\x1b\[[0-9;]*m', '', whatweb_raw)
        if 'HTTPServer' in clean:
            server = re.findall(r'HTTPServer\[ (.*?) \]', clean)
            if server:
                report += f"🖥 **Web Server:** {server[0]}\n"
        if 'Cloudflare' in clean or 'cloudflare' in clean:
            report += "🛡️ **Cloudflare Detected** — site is behind a CDN/WAF (extra protection)\n"
        if '403' in clean:
            report += "🔒 Site returns *403 Forbidden* to scanners — good hardening.\n"
        ip_matches = re.findall(r'IP\[ ([^\]]+) \]', clean)
        if ip_matches:
            report += f"🌐 **IPs Found:** {', '.join(ip_matches[:3])}\n"
        report += "\n"

    if 'nmap' in results:
        nmap_out = results['nmap']
        open_ports = re.findall(r"^\d+/tcp\s+open\s+(.*)", nmap_out, re.MULTILINE)
        if open_ports:
            report += "🛡️ **Open Ports & Services**\n"
            for line in open_ports[:10]:
                report += f"• {line}\n"
            report += "\n"
        vulns = re.findall(r"\|.*VULNERABLE.*", nmap_out)
        if vulns:
            report += "⚠️ **Potential Vulnerabilities**\n"
            for v in vulns[:5]:
                report += f"• {v.replace('|','').strip()}\n"
            report += "\n"

    if 'nikto' in results:
        nikto_out = results['nikto']
        findings = re.findall(r"\+ (.*)", nikto_out)
        if findings:
            report += "🔥 **Web Security Issues (Nikto)**\n"
            for f in findings[:8]:
                report += f"• {f}\n"
            report += "\n"

    if 'theHarvester' in results and results['theHarvester'] != "No email provided for OSINT.":
        harvest = results['theHarvester']
        if "<html" in harvest.lower():
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", harvest)
            if emails:
                report += f"📧 **Leaked Emails Found ({len(emails)}):** {', '.join(emails[:5])}\n\n"
        else:
            report += f"📡 **OSINT Summary:** {harvest[:300]}\n\n"

    if 'dnstwist' in results:
        dnstwist_out = results['dnstwist']
        registered = re.findall(r"^([^ ]+)\s+registered.*", dnstwist_out, re.MULTILINE)
        if registered:
            report += "🕵️ **Similar Domains Registered (Typosquatting Risk)**\n"
            for d in registered[:6]:
                report += f"• {d}\n"
            report += "\n"

    if 'metagoofil' in results and 'No dangerous' not in results['metagoofil']:
        meta = results['metagoofil']
        report += "📄 **Document Metadata Exposure**\n"
        if 'usernames' in meta.lower() or 'path' in meta.lower():
            report += "⚠️ Sensitive info (usernames/paths) found in public documents.\n"
        else:
            report += f"{meta[:200]}\n"
        report += "\n"
    elif 'metagoofil' in results:
        report += "📄 **Document Metadata:** No leaks detected.\n\n"

    if 'sherlock' in results:
        sherlock_out = results['sherlock']
        found = re.findall(r"\[\+\] (.*)", sherlock_out)
        if found:
            report += "👥 **Social Media Presence**\n"
            for line in found[:10]:
                report += f"• {line}\n"
            report += "\n"

    report += "📌 *Phantom Watch – Automated Security Reconnaissance*\n"
    report += "_Interpretation by a professional recommended._"
    return report

# ========== MENUS & KEYBOARDS ==========
def main_menu_keyboard(user_is_admin=False):
    buttons = [
        [InlineKeyboardButton("🔍 Full Scan", callback_data="scan_full")],
        [InlineKeyboardButton("⚡ Quick Scan", callback_data="scan_quick")],
        [InlineKeyboardButton("📧 Set Email", callback_data="set_email")],
        [InlineKeyboardButton("❓ Help", callback_data="help")],
    ]
    if user_is_admin:
        buttons.append([InlineKeyboardButton("👑 Admin Menu", callback_data="admin_menu")])
    return InlineKeyboardMarkup(buttons)

def admin_menu_keyboard():
    buttons = [
        [InlineKeyboardButton("➕ Add User", callback_data="admin_adduser")],
        [InlineKeyboardButton("✅ Verify Domain", callback_data="admin_verify")],
        [InlineKeyboardButton("📊 Status", callback_data="admin_status")],
        [InlineKeyboardButton("🔙 Main Menu", callback_data="main_menu")],
    ]
    return InlineKeyboardMarkup(buttons)

def quick_scan_keyboard():
    # Predefined scan packs
    buttons = [
        [InlineKeyboardButton("🛡️ Ports & Vulns (nmap+nikto)", callback_data="quick_ports")],
        [InlineKeyboardButton("🌐 OSINT Pack (theHarvester+sherlock)", callback_data="quick_osint")],
        [InlineKeyboardButton("🔎 Recon (whatweb+dnstwist+metagoofil)", callback_data="quick_recon")],
        [InlineKeyboardButton("🔙 Main Menu", callback_data="main_menu")],
    ]
    return InlineKeyboardMarkup(buttons)

# ========== CALLBACK HANDLERS ==========
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    username = query.from_user.username

    if data == "main_menu":
        admin = (username == ADMIN_USERNAME)
        await query.edit_message_text("🔮 Phantom Watch – Main Menu", reply_markup=main_menu_keyboard(admin))
        return

    # Scan selections
    if data in ["scan_full", "scan_quick"]:
        if not is_subscription_active(username):
            await query.edit_message_text("⛔ Your subscription is inactive. Contact admin.")
            return
        if data == "scan_full":
            context.user_data['scan_type'] = 'full'
            context.user_data['tools'] = None
        else:
            # Show quick scan subtypes
            await query.edit_message_text("Choose a quick scan type:", reply_markup=quick_scan_keyboard())
            return
        # Ask for domain
        await query.edit_message_text("📌 Please send the domain you want to scan (e.g., example.com).")
        context.user_data['state'] = 'WAITING_DOMAIN'
        return

    # Quick scan sub-options
    if data.startswith("quick_"):
        if not is_subscription_active(username):
            await query.edit_message_text("⛔ Subscription inactive.")
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
        await query.edit_message_text("📌 Please send the domain you want to scan.")
        context.user_data['state'] = 'WAITING_DOMAIN'
        return

    # Set email flow
    if data == "set_email":
        if not is_subscription_active(username):
            await query.edit_message_text("⛔ Subscription inactive.")
            return
        await query.edit_message_text("📧 Please send your email address (used for OSINT scans).")
        context.user_data['state'] = 'WAITING_EMAIL'
        return

    # Help
    if data == "help":
        help_text = (
            "🔍 **Full Scan** – uses all 7 tools.\n"
            "⚡ **Quick Scan** – choose a specific tool pack.\n"
            "📧 **Set Email** – improve OSINT results.\n"
            "Send `/start` to return here anytime."
        )
        await query.edit_message_text(help_text, reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))
        return

    # Admin menu
    if data == "admin_menu":
        if username != ADMIN_USERNAME:
            await query.edit_message_text("❌ Admin only.", reply_markup=main_menu_keyboard(False))
            return
        await query.edit_message_text("👑 Admin Panel", reply_markup=admin_menu_keyboard())
        return

    if data == "admin_adduser":
        if username != ADMIN_USERNAME:
            return
        await query.edit_message_text("To add a user, use command:\n`/adduser @username plan months`\nExample: `/adduser @john free`")
        return

    if data == "admin_verify":
        if username != ADMIN_USERNAME:
            return
        await query.edit_message_text("To verify a domain manually:\n`/verify @username domain.com`")
        return

    if data == "admin_status":
        if username != ADMIN_USERNAME:
            return
        c.execute("SELECT username, plan, expiry FROM clients")
        clients = c.fetchall()
        msg = "📊 **Client List**\n\n"
        for u, p, e in clients:
            msg += f"@{u} - {p}"
            if e:
                msg += f" (exp: {e})"
            msg += "\n"
        await query.edit_message_text(msg, reply_markup=admin_menu_keyboard())
        return

# ========== TEXT MESSAGE HANDLER (for domain/email input) ==========
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.message.from_user
    username = user.username
    text = update.message.text.strip().lower()
    state = context.user_data.get('state', '')

    if state == 'WAITING_DOMAIN':
        # Validate domain
        domain_pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
        if not re.match(domain_pattern, text):
            await update.message.reply_text("❌ Invalid domain. Send like example.com")
            return
        domain = text
        if not is_subscription_active(username):
            await update.message.reply_text("⛔ Subscription expired or not authorized.")
            return
        # Verification logic (same as before, simplified)
        if username == ADMIN_USERNAME:
            pass
        else:
            c.execute("SELECT token FROM verification WHERE username=? AND domain=?", (username, domain))
            row = c.fetchone()
            if row and row[0] == "admin_verified":
                pass
            elif row and row[0] != "admin_verified":
                if not verify_domain(domain, row[0]):
                    await update.message.reply_text("⏳ Verification file missing. Upload verify.txt or ask admin to approve.")
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

        # Start scan
        await update.message.reply_text("✅ Domain verified. Launching scan... (progress updates will appear)")

        chat_id = update.message.chat_id
        async def send_progress(msg):
            await context.bot.send_message(chat_id=chat_id, text=msg)
        def sync_progress(msg):
            asyncio.run_coroutine_threadsafe(send_progress(msg), context.application.loop)

        # Get email if set
        c.execute("SELECT email_collect FROM clients WHERE username=?", (username,))
        row = c.fetchone()
        email = row[0] if row else ""

        # Determine tools
        scan_type = context.user_data.get('scan_type', 'full')
        tools = context.user_data.get('tools', None)

        loop = asyncio.get_running_loop()
        results = await loop.run_in_executor(None, run_scan, domain, email, sync_progress, tools)
        report = format_report(domain, results)
        # Send report in chunks
        max_len = 4000
        for i in range(0, len(report), max_len):
            await update.message.reply_text(report[i:i+max_len], parse_mode='Markdown')
        # Reset state
        context.user_data.pop('state', None)
        context.user_data.pop('scan_type', None)
        context.user_data.pop('tools', None)
        # Return to main menu
        await update.message.reply_text("🔮 What would you like to do next?", reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))
        return

    elif state == 'WAITING_EMAIL':
        email = text
        if '@' not in email:
            await update.message.reply_text("Invalid email. Please send a valid email address.")
            return
        c.execute("UPDATE clients SET email_collect=? WHERE username=?", (email, username))
        conn.commit()
        await update.message.reply_text(f"✅ Email set to {email}.", reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))
        context.user_data.pop('state', None)
        return

    # Fallback: if no state, treat as possible domain for backward compatibility
    if not state:
        # Just redirect to /start
        await start(update, context)
        return

# ========== ORIGINAL COMMAND HANDLERS (for /start, /adduser, etc.) ==========
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global ADMIN_CHAT_ID
    user = update.message.from_user
    if user.username == ADMIN_USERNAME:
        ADMIN_CHAT_ID = update.message.chat_id
        print(f"[*] Admin chat ID set to {ADMIN_CHAT_ID}")
    await update.message.reply_text(
        "🔮 **Phantom Watch** – Your Security Reconnaissance Bot\nChoose an option below:",
        reply_markup=main_menu_keyboard(user.username == ADMIN_USERNAME)
    )

async def adduser(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.from_user.username != ADMIN_USERNAME:
        await update.message.reply_text("❌ Admin only.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /adduser @username [plan] [months]\nExample: /adduser @john monthly 1")
        return
    target_username = context.args[0].lstrip('@')
    plan = context.args[1] if len(context.args) > 1 else "free"
    months = int(context.args[2]) if len(context.args) > 2 else 0
    add_client(target_username, plan if plan in ["free","monthly","enterprise"] else "free")
    if plan == "free":
        set_free_expiry(target_username)
    if plan != "free" and months > 0:
        set_plan(target_username, plan, months)
    await update.message.reply_text(f"✅ User @{target_username} added with {plan} plan.")

async def verify_domain_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.from_user.username != ADMIN_USERNAME:
        await update.message.reply_text("❌ Admin only.")
        return
    if len(context.args) < 2:
        await update.message.reply_text("Usage: /verify @username domain.com")
        return
    target_username = context.args[0].lstrip('@')
    domain = context.args[1].lower()
    if not is_client(target_username):
        await update.message.reply_text("User not a client. Add first with /adduser.")
        return
    c.execute("INSERT OR REPLACE INTO verification VALUES (?,?,?)",
              (target_username, domain, "admin_verified"))
    conn.commit()
    await update.message.reply_text(f"✅ Domain {domain} manually verified for @{target_username}.")

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Use the buttons below. Commands for admin:\n"
        "/adduser @user plan months\n/verify @user domain\n/status"
    )

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    err = context.error
    if isinstance(err, telegram.error.TimedOut):
        print(f"[!] Network timeout: {err}")
    else:
        print(f"[!] Error: {err}")

# ========== MAIN ==========
def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("adduser", adduser))
    app.add_handler(CommandHandler("verify", verify_domain_cmd))
    app.add_handler(CommandHandler("help", help_cmd))
    # Callback handler for inline buttons
    app.add_handler(CallbackQueryHandler(button_handler))
    # Message handler for domain/email inputs
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_error_handler(error_handler)

    print("👻 Phantom Watch is watching...")
    app.run_polling()

if __name__ == "__main__":
    main()
