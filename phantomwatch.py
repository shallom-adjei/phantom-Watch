#!/usr/bin/env python3
import subprocess, re, os, sqlite3, random, string, json, time, asyncio
from datetime import datetime, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, CallbackQueryHandler, filters, ContextTypes

BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
DB_FILE = "phantom_clients.db"
SCAN_TIMEOUT = 150

conn = sqlite3.connect(DB_FILE, check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS clients (username TEXT PRIMARY KEY, plan TEXT DEFAULT 'free', expiry TEXT, email_collect TEXT DEFAULT '')''')
c.execute('''CREATE TABLE IF NOT EXISTS verification (username TEXT, domain TEXT, token TEXT, PRIMARY KEY(username, domain))''')
conn.commit()

def is_client(username): c.execute("SELECT 1 FROM clients WHERE username=?", (username,)); return c.fetchone() is not None
def is_active(username):
    c.execute("SELECT plan, expiry FROM clients WHERE username=?", (username,))
    row = c.fetchone()
    if not row: return False
    plan, expiry = row
    if plan == 'free' and expiry and expiry < datetime.now().strftime("%Y-%m-%d"): return False
    if expiry and expiry < datetime.now().strftime("%Y-%m-%d"): return False
    return True
def add_client(username, plan="free", months=0):
    expiry = ""
    if plan == "free":
        expiry = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d")
    elif months > 0:
        expiry = (datetime.now() + timedelta(days=30*months)).strftime("%Y-%m-%d")
    c.execute("INSERT OR REPLACE INTO clients VALUES (?,?,?,?)", (username, plan, expiry, ""))
    conn.commit()
def generate_token(): return ''.join(random.choices(string.ascii_letters + string.digits, k=20))
def verify_domain(domain, token):
    try:
        r = subprocess.run(["curl", "-s", "-m", "15", f"http://{domain}/verify.txt"], capture_output=True, text=True)
        return r.stdout.strip() == token
    except: return False
def run_command(cmd, timeout=SCAN_TIMEOUT):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except: return "[!] Error"

def run_scan(domain, email="", progress_callback=None, tools=None):
    if tools is None: tools = ["nmap","nikto","whatweb","theHarvester","dnstwist","metagoofil","sherlock"]
    results = {}
    for tool in tools:
        if progress_callback: progress_callback(f"Running {tool}...")
        if tool == "nmap": results['nmap'] = run_command(f"nmap -sV -T4 --top-ports 200 {domain}")
        elif tool == "nikto": results['nikto'] = run_command(f"nikto -h {domain} -T 123bde -maxtime 120s")
        elif tool == "whatweb": results['whatweb'] = run_command(f"whatweb {domain}")
        elif tool == "theHarvester":
            if email:
                run_command(f"theHarvester -d {domain} -b google -f report_{domain}.html")
                if os.path.exists(f"report_{domain}.html"):
                    with open(f"report_{domain}.html") as f: results['theHarvester'] = f.read()
                    os.remove(f"report_{domain}.html")
                else: results['theHarvester'] = "No results"
            else: results['theHarvester'] = "No email"
        elif tool == "dnstwist": results['dnstwist'] = run_command(f"dnstwist {domain}")
        elif tool == "metagoofil":
            raw = run_command(f"cd /home/runner/metagoofil && python3 metagoofil.py -d {domain} -t pdf,doc,xls -l 10 -n 5 -o /tmp/meta_{domain} -f meta_{domain}.html", timeout=300)
            meta_report = f"/tmp/meta_{domain}/meta_{domain}.html"
            if os.path.exists(meta_report):
                with open(meta_report) as f: results['metagoofil'] = f.read()
                shutil.rmtree(f"/tmp/meta_{domain}")
            else: results['metagoofil'] = "No metadata found"
        elif tool == "sherlock":
            company = domain.split('.')[0]
            results['sherlock'] = run_command(f"cd /home/runner/sherlock && python3 sherlock.py {company} --timeout 10")
    return results

def format_summary(domain, results):
    lines = [f"🔍 Scan completed for {domain}\n"]
    if 'nmap' in results:
        ports = len(re.findall(r"^\d+/tcp\s+open\s+", results['nmap'], re.MULTILINE))
        vulns = len(re.findall(r"\|.*VULNERABLE.*", results['nmap']))
        lines.append(f"🛡️ Nmap: {ports} open ports, {vulns} potential vulns")
    if 'nikto' in results:
        issues = len(re.findall(r"\+ (.*)", results['nikto']))
        lines.append(f"🔥 Nikto: {issues} web issues")
    if 'whatweb' in results:
        clean = re.sub(r'\x1b\[[0-9;]*m', '', results['whatweb'])
        servers = re.findall(r'HTTPServer\[ (.*?) \]', clean)
        if servers: lines.append(f"🧩 Technology: {servers[0]}")
    if 'theHarvester' in results and results['theHarvester'] != "No email":
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
    lines.append("\n⚠️ This is a summary. Upgrade to Monthly/Enterprise for full PDF reports.")
    return "\n".join(lines)

# ---------- Menus ----------
def main_menu(admin=False):
    buttons = [
        [InlineKeyboardButton("🔍 Full Scan", callback_data="scan_full")],
        [InlineKeyboardButton("📩 Contact Admin", callback_data="contact_admin")],
        [InlineKeyboardButton("❓ Help", callback_data="help")],
    ]
    if admin:
        buttons.append([InlineKeyboardButton("👑 Admin Menu", callback_data="admin_menu")])
    return InlineKeyboardMarkup(buttons)

def admin_menu():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Add User", callback_data="admin_adduser")],
        [InlineKeyboardButton("✅ Verify Domain", callback_data="admin_verify")],
        [InlineKeyboardButton("🔙 Main Menu", callback_data="main_menu")],
    ])

# ---------- Handlers ----------
async def start(update, context):
    user = update.message.from_user
    await update.message.reply_text(
        "🔮 *PHANTOM WATCH* – Basic Edition\n"
        "Send /start to see the menu.",
        parse_mode='Markdown'
    )
    await update.message.reply_text("Main Menu:", reply_markup=main_menu(user.username == ADMIN_USERNAME))

async def button_handler(update, context):
    query = update.callback_query
    await query.answer()
    data = query.data
    username = query.from_user.username

    if data == "main_menu":
        await query.edit_message_text("Main Menu:", reply_markup=main_menu(username == ADMIN_USERNAME))
        return
    if data == "scan_full":
        if not is_active(username):
            await query.edit_message_text("⛔ Not authorized or trial expired.")
            return
        await query.edit_message_text("📌 Send the domain name to scan.")
        context.user_data['state'] = "SCAN_DOMAIN"
        return
    if data == "contact_admin":
        await query.edit_message_text("✅ Message sent to admin. They will reach out.")
        # Try to notify admin via Telegram username
        try:
            await context.bot.send_message(chat_id=f"@{ADMIN_USERNAME}", text=f"📩 Client @{username} wants to get in touch.")
        except: pass
        return
    if data == "help":
        await query.edit_message_text(
            "⚡ *Nmap* – Ports & vulns\n"
            "🕵️ *Nikto* – Web issues\n"
            "🔎 *WhatWeb* – Technology\n"
            "📧 *theHarvester* – OSINT emails\n"
            "🔄 *dnstwist* – Fake domains\n"
            "📄 *Metagoofil* – Metadata\n"
            "👤 *Sherlock* – Social media\n\n"
            "Upgrade for PDF reports, breach intel, and more.",
            parse_mode='Markdown', reply_markup=main_menu(username == ADMIN_USERNAME))
        return
    # Admin
    if data == "admin_menu":
        if username != ADMIN_USERNAME: return
        await query.edit_message_text("Admin Panel:", reply_markup=admin_menu())
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

async def message_handler(update, context):
    username = update.message.from_user.username
    text = update.message.text.strip()
    state = context.user_data.get('state')

    # Admin add user flow
    if state == "ADDUSER_USERNAME":
        if username != ADMIN_USERNAME: return
        target = text.lstrip('@')
        if not target:
            await update.message.reply_text("Invalid username.")
            return
        context.user_data['add_target'] = target
        await update.message.reply_text("Plan? (free, monthly, enterprise):")
        context.user_data['state'] = "ADDUSER_PLAN"
        return
    if state == "ADDUSER_PLAN":
        plan = text.lower()
        if plan not in ["free","monthly","enterprise"]:
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
        add_client(target, plan, months)
        await update.message.reply_text(f"✅ Added @{target} with {plan} plan.", reply_markup=admin_menu())
        for k in ('add_target','add_plan','state'): context.user_data.pop(k, None)
        return

    # Admin verify domain
    if state == "VERIFY_USERNAME":
        if username != ADMIN_USERNAME: return
        target = text.lstrip('@')
        if not is_client(target):
            await update.message.reply_text("User not a client."); return
        context.user_data['verify_target'] = target
        await update.message.reply_text("Domain to verify (e.g., example.com):")
        context.user_data['state'] = "VERIFY_DOMAIN"
        return
    if state == "VERIFY_DOMAIN":
        target = context.user_data['verify_target']
        domain = text.lower()
        c.execute("INSERT OR REPLACE INTO verification VALUES (?,?,?)", (target, domain, "admin_verified"))
        conn.commit()
        await update.message.reply_text(f"✅ Domain {domain} verified for @{target}.", reply_markup=admin_menu())
        context.user_data.pop('state', None); context.user_data.pop('verify_target', None)
        return

    # Scan domain
    if state == "SCAN_DOMAIN":
        domain = text.lower()
        if not re.match(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', domain):
            await update.message.reply_text("Invalid domain."); return
        if not is_active(username):
            await update.message.reply_text("⛔ Not authorized or trial expired."); return

        # Verification
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
                await update.message.reply_text(f"🔐 To verify, upload a file `verify.txt` with token:\n`{token}`\nto the root of your site, then send the domain again.")
                return

        await update.message.reply_text("✅ Domain verified. Launching scan...")
        chat_id = update.message.chat_id

        progress_msg = await context.bot.send_message(chat_id=chat_id, text="⚡ Preparing tools...")
        loop = asyncio.get_running_loop()
        def sync_progress(msg):
            async def _upd():
                try: await progress_msg.edit_text(msg)
                except: pass
            asyncio.run_coroutine_threadsafe(_upd(), loop)

        # Get email if set
        c.execute("SELECT email_collect FROM clients WHERE username=?", (username,))
        row = c.fetchone()
        email = row[0] if row else ""

        # Run scan in executor
        results = await loop.run_in_executor(None, run_scan, domain, email, sync_progress)
        try: await progress_msg.delete()
        except: pass

        if results:
            summary = format_summary(domain, results)
            await context.bot.send_message(chat_id=chat_id, text=summary, parse_mode='Markdown')
        else:
            await context.bot.send_message(chat_id=chat_id, text="❌ Scan failed.")

        context.user_data.pop('state', None)
        await update.message.reply_text("🔮 What's next?", reply_markup=main_menu(username == ADMIN_USERNAME))
        return

    # Fallback
    await update.message.reply_text("Use the buttons.", reply_markup=main_menu(username == ADMIN_USERNAME))

# ---------- Main ----------
def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler))
    print("👻 Phantom Watch is watching...")
    app.run_polling()

if __name__ == "__main__":
    main()
