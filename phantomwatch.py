#!/usr/bin/env python3
"""
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗    ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║    ██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║    ██║ █╗ ██║███████║   ██║   ██║     ███████║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║    ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║    ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝     ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝

Phantom Watch - Automated Security Reconnaissance Bot
"""

import subprocess, re, os, sqlite3, random, string, shutil, json, time
from datetime import datetime, timedelta
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes
import telegram.error
import asyncio
import os

# ========== CONFIGURATION ==========
BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_CHAT_ID = None                                            # Set automatically after /start
DB_FILE = "phantom_clients.db"
SCAN_TIMEOUT = 180  # seconds max per tool
# ===================================

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

# ------------------ Helper Functions ------------------
def is_client(username: str) -> bool:
    c.execute("SELECT 1 FROM clients WHERE username=?", (username,))
    return c.fetchone() is not None

def add_client(username: str, plan: str = "free", expiry: str = ""):
    c.execute("INSERT OR REPLACE INTO clients VALUES (?,?,?,?)",
              (username, plan, expiry, ""))
    conn.commit()

def set_plan(username: str, plan: str, months: int):
    new_expiry = (datetime.now() + timedelta(days=30*months)).strftime("%Y-%m-%d")
    c.execute("UPDATE clients SET plan=?, expiry=? WHERE username=?",
              (plan, new_expiry, username))
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
    """Run a shell command safely and return its output."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[!] Command timed out."
    except Exception as e:
        return f"[!] Error: {str(e)}"

async def notify_admin(text: str, context: ContextTypes.DEFAULT_TYPE):
    """Send a message to the admin (you) if chat ID is known."""
    global ADMIN_CHAT_ID
    if ADMIN_CHAT_ID:
        try:
            await context.bot.send_message(chat_id=ADMIN_CHAT_ID, text=text)
        except Exception as e:
            print(f"[!] Could not notify admin: {e}")

# ------------------ Scan Engine ------------------
def run_scan(domain: str, email: str = "") -> dict:
    """Execute all tools and return a dictionary of results."""
    results = {}
    print(f"[*] Starting scan for {domain}")

    # 1. nmap
    print("[*] Running Nmap...")
    results['nmap'] = run_command(f"nmap -sV -T4 --script vuln --top-ports 200 {domain}")

    # 2. nikto
    print("[*] Running Nikto...")
    results['nikto'] = run_command(f"nikto -h {domain} -T 123bde -maxtime 120s")

    # 3. whatweb
    print("[*] Running WhatWeb...")
    results['whatweb'] = run_command(f"whatweb {domain}")

    # 4. theHarvester
    if email:
        print("[*] Running theHarvester with email...")
        results['theHarvester'] = run_command(f"theHarvester -d {domain} -b google -f report_{domain}.html")
        if os.path.exists(f"report_{domain}.html"):
            with open(f"report_{domain}.html", "r") as f:
                results['theHarvester'] = f.read()
            os.remove(f"report_{domain}.html")
        else:
            results['theHarvester'] = "No email results."
    else:
        results['theHarvester'] = "No email provided for OSINT."

    # 5. dnstwist
    print("[*] Running dnstwist...")
    results['dnstwist'] = run_command(f"dnstwist {domain}")

    # 6. metagoofil
    print("[*] Running metagoofil...")
    results['metagoofil'] = run_command(
        f"cd ~/metagoofil && python3 metagoofil.py -d {domain} -t pdf,doc,xls -l 10 -n 5 -o /tmp/meta_{domain} -f meta_{domain}.html"
    )
    meta_report = f"/tmp/meta_{domain}/meta_{domain}.html"
    if os.path.exists(meta_report):
        with open(meta_report, "r") as f:
            results['metagoofil'] = f.read()
        shutil.rmtree(f"/tmp/meta_{domain}")
    else:
        results['metagoofil'] = "No metadata found or command failed."

    # 7. sherlock
    company_name = domain.split('.')[0]
    print("[*] Running Sherlock...")
    results['sherlock'] = run_command(f"cd ~/sherlock && python3 sherlock.py {company_name} --timeout 10")

    # 8. spiderfoot
    print("[*] Running SpiderFoot...")
    sf_cmd = f"spiderfoot -s {domain} -q -o json"
    results['spiderfoot'] = run_command(sf_cmd)

    # Store scan in database
    report_text = json.dumps(results, indent=2)
    c.execute("INSERT INTO scan_results (username, domain, timestamp, report) VALUES (?,?,?,?)",
              ("reserved", domain, datetime.now().isoformat(), report_text))
    conn.commit()
    print(f"[✓] Scan finished for {domain}")
    return results

def format_report(domain: str, results: dict) -> str:
    """Create a clean, client-friendly security report."""
    now = datetime.now().strftime('%Y-%m-%d %H:%M')
    report = f"🔍 **PHANTOM WATCH SECURITY REPORT**\n`{domain}`\n_{now}_\n\n"

    # ---------- TECHNOLOGIES (WhatWeb) ----------
    if 'whatweb' in results:
        whatweb_raw = results['whatweb']
        clean = re.sub(r'\x1b\[[0-9;]*m', '', whatweb_raw)   # remove color codes
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

    # ---------- OPEN PORTS (Nmap) ----------
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

    # ---------- NIKTO FINDINGS ----------
    if 'nikto' in results:
        nikto_out = results['nikto']
        findings = re.findall(r"\+ (.*)", nikto_out)
        if findings:
            report += "🔥 **Web Security Issues (Nikto)**\n"
            for f in findings[:8]:
                report += f"• {f}\n"
            report += "\n"

    # ---------- EMAIL LEAKS (theHarvester) ----------
    if 'theHarvester' in results and results['theHarvester'] != "No email provided for OSINT.":
        harvest = results['theHarvester']
        if "<html" in harvest.lower():
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", harvest)
            if emails:
                report += f"📧 **Leaked Emails Found ({len(emails)}):** {', '.join(emails[:5])}\n\n"
        else:
            report += f"📡 **OSINT Summary:** {harvest[:300]}\n\n"

    # ---------- TYPOSQUATTING (dnstwist) ----------
    if 'dnstwist' in results:
        dnstwist_out = results['dnstwist']
        registered = re.findall(r"^([^ ]+)\s+registered.*", dnstwist_out, re.MULTILINE)
        if registered:
            report += "🕵️ **Similar Domains Registered (Typosquatting Risk)**\n"
            for d in registered[:6]:
                report += f"• {d}\n"
            report += "\n"

    # ---------- DOCUMENT METADATA (metagoofil) ----------
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

    # ---------- SOCIAL MEDIA (sherlock) ----------
    if 'sherlock' in results:
        sherlock_out = results['sherlock']
        found = re.findall(r"\[\+\] (.*)", sherlock_out)
        if found:
            report += "👥 **Social Media Presence**\n"
            for line in found[:10]:
                report += f"• {line}\n"
            report += "\n"

    # ---------- SPIDERFOOT ----------
    if 'spiderfoot' in results:
        sf_out = results['spiderfoot']
        try:
            data = json.loads(sf_out) if sf_out.strip().startswith('[') else []
            if data:
                types = set()
                for entry in data:
                    if 'type' in entry:
                        types.add(entry['type'])
                report += f"🕸️ **SpiderFoot OSINT:** Found data categories: {', '.join(list(types)[:10])}\n\n"
            else:
                report += "🕸️ SpiderFoot: No public data collected.\n\n"
        except:
            report += "🕸️ SpiderFoot scan complete (detailed log available).\n\n"

    report += "📌 *Phantom Watch – Automated Security Reconnaissance*\n"
    report += "_Interpretation by a professional recommended._"
    return report

# ========== TELEGRAM BOT HANDLERS ==========

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global ADMIN_CHAT_ID
    if update.message.from_user.username == ADMIN_USERNAME:
        ADMIN_CHAT_ID = update.message.chat_id
        print(f"[*] Admin chat ID set to {ADMIN_CHAT_ID}")
    await update.message.reply_text(
        "🔮 **Phantom Watch** — Your Digital Shadow Reconnaissance\n"
        "Send me a domain (e.g., example.com) to begin scanning. You must be authorized by the admin."
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
    if plan != "free" and months > 0:
        set_plan(target_username, plan, months)
    await update.message.reply_text(f"✅ User @{target_username} added with {plan} plan.")

async def verify_domain_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin command: /verify @username example.com  (manually approve domain ownership)"""
    if update.message.from_user.username != ADMIN_USERNAME:
        await update.message.reply_text("❌ Admin only.")
        return
    if len(context.args) < 2:
        await update.message.reply_text("Usage: /verify @username domain.com")
        return
    target_username = context.args[0].lstrip('@')
    domain = context.args[1].lower()
    c.execute("SELECT username FROM clients WHERE username=?", (target_username,))
    if not c.fetchone():
        await update.message.reply_text(f"User @{target_username} is not a client yet. Add them first with /adduser.")
        return
    c.execute("INSERT OR REPLACE INTO verification VALUES (?,?,?)",
              (target_username, domain, "admin_verified"))
    conn.commit()
    await update.message.reply_text(f"✅ Domain {domain} manually verified for @{target_username}. They can now scan immediately.")

async def setemail(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.message.from_user.username
    if not user or not is_client(user):
        await update.message.reply_text("❌ Not authorized.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /setemail your@email.com")
        return
    email = context.args[0]
    c.execute("UPDATE clients SET email_collect=? WHERE username=?", (email, user))
    conn.commit()
    await update.message.reply_text(f"✅ Email set to {email}. OSINT scans will use this.")

async def handle_domain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.message.from_user
    username = user.username
    if not username:
        await update.message.reply_text("You must have a Telegram username to use Phantom Watch.")
        return
    if not is_client(username):
        await update.message.reply_text("⛔ You are not an authorized client. Contact the admin.")
        return
    domain = update.message.text.strip().lower()
    domain_pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
    if not re.match(domain_pattern, domain):
        await update.message.reply_text("Invalid domain format. Use something like example.com")
        return

    # ---------- Simplified Verification ----------
    if username == ADMIN_USERNAME:
        # Admin bypass, scan immediately
        pass
    else:
        c.execute("SELECT token FROM verification WHERE username=? AND domain=?", (username, domain))
        row = c.fetchone()
        if row and row[0] == "admin_verified":
            pass  # Admin manually approved
        elif row and row[0] != "admin_verified":
            token = row[0]
            if not verify_domain(domain, token):
                await update.message.reply_text("⏳ Verification file not found. Upload verify.txt or ask admin to approve.")
                return
        else:
            token = generate_token()
            c.execute("INSERT OR REPLACE INTO verification VALUES (?,?,?)", (username, domain, token))
            conn.commit()
            await update.message.reply_text(
                f"🔐 To verify you own {domain}, upload a file named `verify.txt` "
                f"to the root of your website containing exactly:\n\n`{token}`\n\n"
                f"Or contact the admin for manual verification."
            )
            return

    # Ownership confirmed, begin scan
    try:
        await update.message.reply_text("✅ Domain verified. Launching full Phantom Watch scan... (may take 5-10 minutes)")
    except Exception:
        await asyncio.sleep(2)
        await update.message.reply_text("✅ Domain verified. Launching full Phantom Watch scan... (may take 5-10 minutes)")

    print(f"[*] Scan started for {domain} by @{username}")
    await notify_admin(f"🔔 Scan started for {domain} by @{username}", context)

    # Retrieve email for OSINT
    c.execute("SELECT email_collect FROM clients WHERE username=?", (username,))
    email_row = c.fetchone()
    email = email_row[0] if email_row else ""

    # Run the scan in a separate thread (CPU-bound)
    loop = asyncio.get_running_loop()
    results = await loop.run_in_executor(None, run_scan, domain, email)

    # Format and send the report
    report = format_report(domain, results)
    max_len = 4000
    for i in range(0, len(report), max_len):
        await update.message.reply_text(report[i:i+max_len], parse_mode='Markdown')

    print(f"[✓] Report sent to @{username} for {domain}")
    await notify_admin(f"✅ Scan finished for {domain} by @{username} — report delivered.", context)

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.from_user.username != ADMIN_USERNAME:
        return
    c.execute("SELECT username, plan, expiry FROM clients")
    clients = c.fetchall()
    msg = "📊 **Client List**\n\n"
    for u, p, e in clients:
        msg += f"@{u} - {p}"
        if e:
            msg += f" (exp: {e})"
        msg += "\n"
    await update.message.reply_text(msg)

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Commands:\n"
        "/start - Welcome\n"
        "/setemail you@mail.com - Set email for OSINT\n"
        "Send a domain to scan\n\n"
        "Admin commands:\n"
        "/adduser @user [plan] [months]\n"
        "/verify @user domain.com\n"
        "/status"
    )

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Log errors and prevent crashes from network timeouts."""
    err = context.error
    if isinstance(err, telegram.error.TimedOut):
        print(f"[!] Network timeout. Bot stays alive. Details: {err}")
    else:
        print(f"[!] Unhandled error: {err}")

# ------------------ Main ------------------
def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("adduser", adduser))
    app.add_handler(CommandHandler("verify", verify_domain_cmd))
    app.add_handler(CommandHandler("setemail", setemail))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_domain))
    app.add_error_handler(error_handler)
    print("👻 Phantom Watch is watching...")
    app.run_polling()

if __name__ == "__main__":
    main()
