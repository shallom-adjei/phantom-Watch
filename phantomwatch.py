#!/usr/bin/env python3
"""
Phantom Watch – Interactive Reconnaissance Bot
Features: button wizards, animated progress, plain‑text reports, hardened scans.
"""

import subprocess, re, os, sqlite3, random, string, shutil, json, time, asyncio, signal
from datetime import datetime, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ConversationHandler,
    filters,
    ContextTypes,
)
import telegram.error

# ========== CONFIGURATION ==========
BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_CHAT_ID = None
DB_FILE = "phantom_clients.db"
SCAN_TIMEOUT = 150  # per tool (seconds)
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

# Database setup
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
    """Send a moving progress bar every 10 seconds until stop_event is set."""
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

# ---------- Scan Engine (hardened) ----------
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
    # Save
    report_text = json.dumps(results, indent=2)
    c.execute("INSERT INTO scan_results (username, domain, timestamp, report) VALUES (?,?,?,?)",
              ("reserved", domain, datetime.now().isoformat(), report_text))
    conn.commit()
    return results

def format_report(domain: str, results: dict) -> str:
    """Plain‑text, clean report with no Markdown."""
    now = datetime.now().strftime('%Y-%m-%d %H:%M')
    report = f"🔍 PHANTOM WATCH SECURITY REPORT\n{domain}\n{now}\n\n"

    if 'whatweb' in results:
        clean = re.sub(r'\x1b\[[0-9;]*m', '', results['whatweb'])
        if 'HTTPServer' in clean:
            server = re.findall(r'HTTPServer\[ (.*?) \]', clean)
            if server: report += f"🖥 Web Server: {server[0]}\n"
        if 'Cloudflare' in clean or 'cloudflare' in clean:
            report += "🛡️ Cloudflare Detected — site behind CDN/WAF\n"
        if '403' in clean:
            report += "🔒 Site returns 403 Forbidden to scanners — good hardening.\n"
        ips = re.findall(r'IP\[ ([^\]]+) \]', clean)
        if ips: report += f"🌐 IPs Found: {', '.join(ips[:3])}\n"
        report += "\n"

    if 'nmap' in results:
        open_ports = re.findall(r"^\d+/tcp\s+open\s+(.*)", results['nmap'], re.MULTILINE)
        if open_ports:
            report += "🛡️ Open Ports & Services\n"
            for line in open_ports[:10]:
                report += f"• {line}\n"
            report += "\n"
        vulns = re.findall(r"\|.*VULNERABLE.*", results['nmap'])
        if vulns:
            report += "⚠️ Potential Vulnerabilities\n"
            for v in vulns[:5]:
                report += f"• {v.replace('|','').strip()}\n"
            report += "\n"

    if 'nikto' in results:
        findings = re.findall(r"\+ (.*)", results['nikto'])
        if findings:
            report += "🔥 Web Security Issues (Nikto)\n"
            for f in findings[:8]:
                report += f"• {f}\n"
            report += "\n"

    if 'theHarvester' in results and results['theHarvester'] != "No email provided for OSINT.":
        harvest = results['theHarvester']
        if "<html" in harvest.lower():
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", harvest)
            if emails:
                report += f"📧 Leaked Emails Found ({len(emails)}): {', '.join(emails[:5])}\n\n"
        else:
            report += f"📡 OSINT Summary: {harvest[:300]}\n\n"

    if 'dnstwist' in results:
        registered = re.findall(r"^([^ ]+)\s+registered.*", results['dnstwist'], re.MULTILINE)
        if registered:
            report += "🕵️ Similar Domains Registered (Typosquatting Risk)\n"
            for d in registered[:6]:
                report += f"• {d}\n"
            report += "\n"

    if 'metagoofil' in results and 'No dangerous' not in results['metagoofil']:
        meta = results['metagoofil']
        report += "📄 Document Metadata Exposure\n"
        if 'usernames' in meta.lower() or 'path' in meta.lower():
            report += "⚠️ Sensitive info (usernames/paths) found in public documents.\n"
        else:
            report += f"{meta[:200]}\n"
        report += "\n"
    elif 'metagoofil' in results:
        report += "📄 Document Metadata: No leaks detected.\n\n"

    if 'sherlock' in results:
        found = re.findall(r"\[\+\] (.*)", results['sherlock'])
        if found:
            report += "👥 Social Media Presence\n"
            for line in found[:10]:
                report += f"• {line}\n"
            report += "\n"

    report += "📌 Phantom Watch – Automated Security Reconnaissance\n"
    report += "Interpretation by a professional recommended."
    return report

# ==================== BUTTON MENUS ====================
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
    buttons = [
        [InlineKeyboardButton("🛡️ Ports & Vulns (nmap+nikto)", callback_data="quick_ports")],
        [InlineKeyboardButton("🌐 OSINT Pack (theHarvester+sherlock)", callback_data="quick_osint")],
        [InlineKeyboardButton("🔎 Recon (whatweb+dnstwist+metagoofil)", callback_data="quick_recon")],
        [InlineKeyboardButton("🔙 Main Menu", callback_data="main_menu")],
    ]
    return InlineKeyboardMarkup(buttons)

# ==================== CALLBACK HANDLER ====================
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    username = query.from_user.username

    if data == "main_menu":
        admin = (username == ADMIN_USERNAME)
        await query.edit_message_text("🔮 Phantom Watch – Main Menu", reply_markup=main_menu_keyboard(admin))
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

    if data == "help":
        help_text = (
            "🔍 Full Scan – all 7 tools.\n"
            "⚡ Quick Scan – select a specific pack.\n"
            "📧 Set Email – enhances OSINT.\n"
            "Use /start anytime to return."
        )
        await query.edit_message_text(help_text, reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))
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
        # Start add-user wizard
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
        if plan == "free":
            # No months needed
            await update.message.reply_text("How many months? (0 for default free trial):")
            context.user_data['state'] = ADDUSER_MONTHS
        else:
            await update.message.reply_text("How many months?")
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
        # Clear state
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

        # Subscription check
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

        # Start scan with animation
        await update.message.reply_text("✅ Domain verified. Launching scan...")
        chat_id = update.message.chat_id

        # Stop event for animation
        stop_anim = asyncio.Event()
        anim_task = asyncio.create_task(send_animation(chat_id, context, stop_anim))

        # Progress callback (edit a single progress message)
        progress_msg = await context.bot.send_message(chat_id=chat_id, text="⚡ Preparing tools...")
        def sync_progress(msg):
            async def update_progress():
                try:
                    await progress_msg.edit_text(msg)
                except:
                    pass
            asyncio.run_coroutine_threadsafe(update_progress(), context.application.loop)

        # Get email
        c.execute("SELECT email_collect FROM clients WHERE username=?", (username,))
        row = c.fetchone()
        email = row[0] if row else ""

        # Determine tools
        tools = context.user_data.get('tools', None)

        loop = asyncio.get_running_loop()
        try:
            results = await loop.run_in_executor(None, run_scan, domain, email, sync_progress, tools)
        except Exception as e:
            await update.message.reply_text(f"❌ Scan crashed: {e}")
        finally:
            stop_anim.set()
            await anim_task
            try:
                await progress_msg.delete()
            except:
                pass

        # Generate and send report (plain text, no parse_mode)
        report = format_report(domain, results)
        # Telegram limit 4096, split if needed
        max_len = 4000
        for i in range(0, len(report), max_len):
            await context.bot.send_message(chat_id=chat_id, text=report[i:i+max_len])

        # Cleanup state and show menu
        context.user_data.pop('state', None)
        context.user_data.pop('scan_type', None)
        context.user_data.pop('tools', None)
        await update.message.reply_text("🔮 What's next?", reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))
        return

    # Fallback: show menu
    await update.message.reply_text("🔮 Use the buttons below.", reply_markup=main_menu_keyboard(username == ADMIN_USERNAME))

# ==================== COMMAND HANDLERS ====================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global ADMIN_CHAT_ID
    user = update.message.from_user
    if user.username == ADMIN_USERNAME:
        ADMIN_CHAT_ID = update.message.chat_id
    await update.message.reply_text("🔮 Welcome to Phantom Watch.",
                                    reply_markup=main_menu_keyboard(user.username == ADMIN_USERNAME))

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
    # Message handler catches all text (for wizard states and domain input)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_error_handler(error_handler)

    print("👻 Phantom Watch is watching...")
    app.run_polling()

if __name__ == "__main__":
    main()
