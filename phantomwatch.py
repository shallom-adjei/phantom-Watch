#!/usr/bin/env python3
import subprocess, re, os, sqlite3, random, string, json, time, asyncio, shutil, io
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
import requests

# ========== CONFIG ==========
BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
DB_FILE = "phantom_clients.db"
SCAN_TIMEOUT = 150
# ===========================

# Database
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
c = conn.cursor()
c.execute("""CREATE TABLE IF NOT EXISTS clients (
    username TEXT PRIMARY KEY,
    plan TEXT DEFAULT 'free',
    expiry TEXT,
    email_collect TEXT DEFAULT '',
    scan_used INTEGER DEFAULT 0
)""")
c.execute("""CREATE TABLE IF NOT EXISTS verification (
    username TEXT, domain TEXT, token TEXT,
    PRIMARY KEY(username, domain)
)""")
c.execute("""CREATE TABLE IF NOT EXISTS subscriptions (
    username TEXT, domain TEXT,
    last_scan_time TEXT, last_report_json TEXT,
    PRIMARY KEY(username, domain)
)""")
conn.commit()

# ---------- Helpers ----------
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
    return "".join(random.choices(string.ascii_letters + string.digits, k=20))

def verify_domain(domain: str, token: str) -> bool:
    try:
        r = subprocess.run(
            ["curl", "-s", "-m", "15", f"http://{domain}/verify.txt"],
            capture_output=True,
            text=True,
        )
        return r.stdout.strip() == token
    except:
        return False

def run_command(cmd, timeout=SCAN_TIMEOUT):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except:
        return "[!] Error"

async def check_breach(email: str, context, chat_id: int):
    try:
        resp = requests.get(
            f"https://api.xposedornot.com/v1/breach-analytics?email={email}",
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            breach_details = data.get("breach_details", {})
            if breach_details:
                total = len(breach_details)
                lines = [
                    f"🩸 *Breach Report for {email}*",
                    f"Found in *{total}* known breaches:\n",
                ]
                for name, info in list(breach_details.items())[:10]:
                    domain = info.get("domain", "unknown")
                    date = info.get("breach_date", "N/A")
                    lines.append(f"• *{name}* ({domain}) – {date}")
                if total > 10:
                    lines.append(f"… and {total - 10} more breaches.")
                await context.bot.send_message(
                    chat_id=chat_id,
                    text="\n".join(lines),
                    parse_mode="Markdown",
                )
                return
    except:
        pass
    await context.bot.send_message(
        chat_id=chat_id, text="✅ No breaches found for this email."
    )

# ---------- Scan engine ----------
def run_scan(domain, email="", progress_callback=None, tools=None):
    if tools is None:
        tools = ["nmap", "nikto", "whatweb", "theHarvester", "dnstwist", "metagoofil", "sherlock"]
    results = {}
    step_map = {
        "nmap": 1, "nikto": 2, "whatweb": 3, "theHarvester": 4,
        "dnstwist": 5, "metagoofil": 6, "sherlock": 7
    }
    for tool in tools:
        step = step_map.get(tool, 0)
        if progress_callback:
            progress_callback(f"⚡ [{step}/7] Running {tool}...")
        if tool == "nmap":
            results["nmap"] = run_command(["nmap", "-sV", "-T4", "-p-", "--script", "vuln", "--min-rate", "500", domain], timeout=300)
        elif tool == "nikto":
            results["nikto"] = run_command(["nikto", "-h", domain, "-T", "0123456789abcde", "-maxtime", "300s"], timeout=300)
        elif tool == "whatweb":
            results["whatweb"] = run_command(["whatweb", domain])
        elif tool == "theHarvester":
            if email:
                run_command(["theHarvester", "-d", domain, "-b", "google", "-f", f"report_{domain}.html"])
                if os.path.exists(f"report_{domain}.html"):
                    with open(f"report_{domain}.html") as f:
                        results["theHarvester"] = f.read()
                    os.remove(f"report_{domain}.html")
                else:
                    results["theHarvester"] = "No results"
            else:
                results["theHarvester"] = "No email"
        elif tool == "dnstwist":
            results["dnstwist"] = run_command(["dnstwist", domain])
        elif tool == "metagoofil":
            raw = run_command(["python3", "/home/runner/metagoofil/metagoofil.py", "-d", domain, "-t", "pdf,doc,xls", "-l", "20", "-n", "10", "-o", f"/tmp/meta_{domain}", "-f", f"meta_{domain}.html"], timeout=300)
            meta_report = f"/tmp/meta_{domain}/meta_{domain}.html"
            if os.path.exists(meta_report):
                with open(meta_report) as f:
                    results["metagoofil"] = f.read()
                shutil.rmtree(f"/tmp/meta_{domain}")
            else:
                results["metagoofil"] = "No metadata found"
        elif tool == "sherlock":
            company = domain.split(".")[0]
            results["sherlock"] = run_command(["python3", "/home/runner/sherlock/sherlock.py", company, "--timeout", "20"], timeout=200)
    return results

# ---------- Report formatters ----------
def compute_threat_score(results):
    score = 0
    max_score = 0
    if 'nmap' in results:
        open_ports = len(re.findall(r"^\d+/tcp\s+open\s+", results.get('nmap',''), re.MULTILINE))
        vulns = len(re.findall(r"\|.*VULNERABLE.*", results.get('nmap','')))
        score += (open_ports * 5) + (vulns * 15)
        max_score += (10 * 5) + (10 * 15)
    if 'nikto' in results:
        issues = len(re.findall(r"\+ (.*)", results.get('nikto','')))
        score += issues * 10
        max_score += 10 * 10
    if 'theHarvester' in results and results['theHarvester'] != "No email":
        harvest = results['theHarvester']
        if "<html" in harvest.lower():
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", harvest)
            score += len(emails) * 10
            max_score += 20 * 10
    if 'dnstwist' in results:
        registered = len(re.findall(r"^([^ ]+)\s+registered.*", results.get('dnstwist',''), re.MULTILINE))
        score += registered * 10
        max_score += 10 * 10
    if 'metagoofil' in results and "No metadata" not in results.get('metagoofil',''):
        score += 25
        max_score += 25
    if 'sherlock' in results:
        found = len(re.findall(r"\[\+\] (.*)", results.get('sherlock','')))
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
        f"{risk_emoji} Threat Score: *{score}/100*  |  Risk Level: *{level}*\n",
        "━━━━━━━━━━━━━━━━━━"
    ]
    if "nmap" in results:
        ports = len(re.findall(r"^\d+/tcp\s+open\s+", results.get("nmap", ""), re.MULTILINE))
        vulns = len(re.findall(r"\|.*VULNERABLE.*", results.get("nmap", "")))
        if ports or vulns:
            lines.append(f"🛡️ *Nmap*: {ports} open ports, {vulns} potential vulns")
        else:
            lines.append("🛡️ *Nmap*: No open ports or vulns found.")
    else:
        lines.append("🛡️ *Nmap*: Not run.")
    if "nikto" in results:
        issues = len(re.findall(r"\+ (.*)", results.get("nikto", "")))
        if issues:
            lines.append(f"🔥 *Nikto*: {issues} web issues")
        else:
            lines.append("🔥 *Nikto*: No web issues found.")
    else:
        lines.append("🔥 *Nikto*: Not run.")
    if "whatweb" in results:
        clean = re.sub(r"\x1b\[[0-9;]*m", "", results.get("whatweb", ""))
        servers = re.findall(r"HTTPServer\[ (.*?) \]", clean)
        if servers:
            lines.append(f"🧩 *Technology*: {servers[0]}")
        else:
            lines.append("🧩 *Technology*: No server header detected.")
    else:
        lines.append("🧩 *Technology*: Not run.")
    if "theHarvester" in results:
        harvest = results["theHarvester"]
        if harvest == "No email":
            lines.append("📧 *theHarvester*: No email set – skipped.")
        elif "<html" in harvest.lower():
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", harvest)
            if emails:
                lines.append(f"📧 *theHarvester*: {len(emails)} leaked emails found")
            else:
                lines.append("📧 *theHarvester*: No leaked emails found.")
        else:
            lines.append("📧 *theHarvester*: No results.")
    else:
        lines.append("📧 *theHarvester*: Not run.")
    if "dnstwist" in results:
        registered = len(re.findall(r"^([^ ]+)\s+registered.*", results.get("dnstwist", ""), re.MULTILINE))
        if registered:
            lines.append(f"🕵️ *dnstwist*: {registered} typosquatting domains registered")
        else:
            lines.append("🕵️ *dnstwist*: No similar domains registered.")
    else:
        lines.append("🕵️ *dnstwist*: Not run.")
    if "metagoofil" in results:
        if "No metadata" in results.get("metagoofil", ""):
            lines.append("📄 *Metagoofil*: No metadata leaks found.")
        else:
            lines.append("📄 *Metagoofil*: Document metadata leaks found")
    else:
        lines.append("📄 *Metagoofil*: Not run.")
    if "sherlock" in results:
        found = len(re.findall(r"\[\+\] (.*)", results.get("sherlock", "")))
        if found:
            lines.append(f"👥 *Sherlock*: {found} social media accounts found")
        else:
            lines.append("👥 *Sherlock*: No accounts found.")
    else:
        lines.append("👥 *Sherlock*: Not run.")
    lines.append("")
    if detailed:
        lines.append("")
        lines.append("📋 *DETAILED PAID REPORT*")
        for tool_name, raw in results.items():
            if raw and raw not in ("No email", "No results"):
                lines.append(f"\n🛠 *{tool_name} raw excerpt:*\n```{re.sub(r"\x1b\[[0-9;]*m", "", str(raw))[:300]}```")
        lines.append("\n⚠️ For compliance mapping & exploitation proof, contact admin.")
    else:
        lines.append("")
        lines.append("⚠️ This is a FREE summary. Upgrade to Monthly/Enterprise for full reports, compliance mapping, and exploitation proof. Contact admin to upgrade.")
    return "\n".join(lines)

# Compliance mapping
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


# ---------- Menus ----------
menu_button = ReplyKeyboardMarkup([[KeyboardButton("🛡️ Menu")]], resize_keyboard=True)

def main_menu(admin=False):
    buttons = [
        [InlineKeyboardButton("🔍 Full Scan", callback_data="scan_full"),
         InlineKeyboardButton("⚡ Quick Scan", callback_data="scan_quick")],
        [InlineKeyboardButton("📧 Set Email", callback_data="set_email"),
         InlineKeyboardButton("📩 Contact Admin", callback_data="contact_admin")],
        [InlineKeyboardButton("💲 Pricing", callback_data="pricing"),
         InlineKeyboardButton("📖 How It Works", callback_data="how_it_works")],
        [InlineKeyboardButton("🩸 Check Breaches", callback_data="check_breaches"),
         InlineKeyboardButton("❓ Help", callback_data="help")],
        [InlineKeyboardButton("🔔 Subscribe", callback_data="subscribe"),
         InlineKeyboardButton("🔑 Scan GitHub", callback_data="github_scan")],
    ]
    if admin:
        buttons.append([InlineKeyboardButton("👑 Admin Menu", callback_data="admin_menu")])
    return InlineKeyboardMarkup(buttons)

def admin_menu():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Add User", callback_data="admin_adduser"),
         InlineKeyboardButton("✅ Verify Domain", callback_data="admin_verify")],
        [InlineKeyboardButton("📊 Status", callback_data="admin_status")],
        [InlineKeyboardButton("❌ Remove User", callback_data="admin_removeuser"),
         InlineKeyboardButton("🔙 Main Menu", callback_data="main_menu")],
    ])

def quick_scan_menu():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🛡️ Ports & Vulns", callback_data="quick_ports"),
         InlineKeyboardButton("🌐 OSINT Pack", callback_data="quick_osint")],
        [InlineKeyboardButton("🔎 Recon", callback_data="quick_recon"),
         InlineKeyboardButton("🦠 XSS Check", callback_data="quick_xss")],
        [InlineKeyboardButton("🔙 Main Menu", callback_data="main_menu")],
    ])


# ---------- Handlers ----------
async def start(update, context):
    await update.message.reply_text(
        "Tap the *🛡️ Menu* button below anytime to bring up options.",
        reply_markup=menu_button,
        parse_mode="Markdown",
    )
    await update.message.reply_text(
        "🔮 *PHANTOM WATCH*\n"
        "_Elite Digital Reconnaissance & Threat Intelligence_\n"
        "━━━━━━━━━━━━━━━\n\n"
        "⚠️ Attackers scan the internet every second.\n"
        "The only question is whether they find your weaknesses first.\n\n"
        "🛡 *PHANTOM WATCH* is an advanced cybersecurity platform "
        "built to uncover hidden exposures, leaked intelligence, "
        "and critical vulnerabilities before they become breaches.\n\n"
        "━━━━━━━━━━━━━━━\n"
        "🚨 *Detect Threats Before They Escalate*\n\n"
        "Identify critical risks.\n"
        "Monitor your digital footprint.\n"
        "Protect your organization with continuous reconnaissance.\n\n"
        "👇 Access the control panel below.",
        reply_markup=main_menu(update.message.from_user.username == ADMIN_USERNAME),
        parse_mode="Markdown",
    )

async def button_handler(update, context):
    query = update.callback_query
    await query.answer()
    data = query.data
    username = query.from_user.username

    if data == "main_menu":
        try:
            await query.edit_message_text("⬇️ Main Menu:", reply_markup=main_menu(username == ADMIN_USERNAME))
        except Exception as e:
            if "Message is not modified" not in str(e):
                print(f"Edit error: {e}")
        return

    if data == "scan_full":
        if not is_active(username):
            await query.edit_message_text("⛔ Not authorized or trial expired.")
            return
        context.user_data["scan_type"] = "full"
        context.user_data["tools"] = None
        try:
            await query.edit_message_text("📌 Send the domain name to scan.")
        except Exception as e:
            if "Message is not modified" not in str(e):
                print(f"Edit error: {e}")
        context.user_data["state"] = "SCAN_DOMAIN"
        return

    if data == "scan_quick":
        if not is_active(username):
            await query.edit_message_text("⛔ Not authorized or trial expired.")
            return
        try:
            await query.edit_message_text("Choose a quick scan type:", reply_markup=quick_scan_menu())
        except Exception as e:
            if "Message is not modified" not in str(e):
                print(f"Edit error: {e}")
        return

    if data.startswith("quick_"):
        if not is_active(username):
            await query.edit_message_text("⛔ Not authorized or trial expired.")
            return
        if data == "quick_ports":
            tools = ["nmap", "nikto"]
        elif data == "quick_osint":
            tools = ["theHarvester", "sherlock"]
        elif data == "quick_recon":
            tools = ["whatweb", "dnstwist", "metagoofil"]
        elif data == "quick_xss":
            tools = ["dalfox"]
        context.user_data["tools"] = tools
        context.user_data["scan_type"] = "quick"
        try:
            await query.edit_message_text("📌 Send the domain name to scan.")
        except Exception as e:
            if "Message is not modified" not in str(e):
                print(f"Edit error: {e}")
        context.user_data["state"] = "SCAN_DOMAIN"
        return

    if data == "set_email":
        try:
            await query.edit_message_text("📧 Please send your email address:")
        except Exception as e:
            if "Message is not modified" not in str(e):
                print(f"Edit error: {e}")
        context.user_data["state"] = "SET_EMAIL"
        return

    if data == "pricing":
        pricing_text = (
            "💲 *Phantom Watch Pricing Plans*\n"
            "━━━━━━━━━━━━━━━\n\n"
            "🆓 *Free Trial — 7 Days*\n"
            "   Perfect for testing the platform\n\n"
            "   ✔ One full security scan\n"
            "   ✔ Basic findings summary\n"
            "   ✔ Exposure & vulnerability overview\n"
            "   ✔ Limited reporting features\n\n"
            "   💵 *Price:* Free\n\n"
            "🛡️ *Monthly Plan — $199/month*\n"
            "   Designed for growing businesses\n\n"
            "   ✔ Unlimited full scans\n"
            "   ✔ Professional PDF reports\n"
            "   ✔ Compliance mapping\n"
            "   ✔ Breach intelligence monitoring\n"
            "   ✔ Weekly automated scans\n"
            "   ✔ Continuous exposure tracking\n"
            "   ✔ Priority vulnerability alerts\n\n"
            "   💵 *Price:* $199/month\n\n"
            "👑 *Enterprise Plan — $2,000/month*\n"
            "   Advanced protection for organizations\n\n"
            "   ✔ Everything in Monthly Plan\n"
            "   ✔ Exploitation proof screenshots\n"
            "   ✔ Continuous CVE monitoring\n"
            "   ✔ GitHub secret scanning\n"
            "   ✔ Advanced OSINT intelligence\n"
            "   ✔ Priority support & escalation\n"
            "   ✔ Dedicated monitoring workflows\n"
            "   ✔ Enhanced reporting & analytics\n\n"
            "   💵 *Price:* $2,000/month\n\n"
            "━━━━━━━━━━━━━━━\n"
            "📩 *Need Access or an Upgrade?*\n"
            "Contact the admin to activate your plan."
        )
        await context.bot.send_message(chat_id=query.message.chat_id, text=pricing_text, parse_mode="Markdown")
        try:
            await query.edit_message_text("🔮 Return to main menu:", reply_markup=main_menu(username == ADMIN_USERNAME))
        except Exception as e:
            if "Message is not modified" not in str(e):
                print(f"Edit error: {e}")
        return

    if data == "how_it_works":
        how_text = (
            "📖 *How Phantom Watch Works*\n"
            "━━━━━━━━━━━━━━━\n\n"
            "1️ *Registration & Verification*\n"
            "   └ Your organization is added by the admin\n"
            "   └ Domain ownership is verified securely\n"
            "   └ Scanning scope is configured\n\n"
            "2️ *Choose Your Scan Type*\n"
            "   └ ⚡ *Quick Scan* → Fast exposure checks\n"
            "   └ 🛡 *Full Scan* → Deep vulnerability assessment\n"
            "   └ Targets can include domains, subdomains,\n"
            "      web apps, and public assets\n\n"
            "3️ *Automated Security Analysis*\n"
            "   └ Port & service discovery\n"
            "   └ Website technology detection\n"
            "   └ Vulnerability identification\n"
            "   └ Breach & leaked credential checks\n"
            "   └ GitHub secret exposure scanning\n\n"
            "4️ *Live Monitoring & Alerts*\n"
            "   └ Critical findings are reported instantly\n"
            "   └ High-risk exposures are prioritized\n"
            "   └ Continuous tracking for new threats\n\n"
            "5️ *Professional Reporting*\n"
            "   └ Detailed PDF security reports\n"
            "   └ Compliance mapping included\n"
            "   └ Clear remediation recommendations\n"
            "   └ Executive-friendly summaries\n\n"
            "6️ *Continuous Protection*\n"
            "   └ Weekly or scheduled scans\n"
            "   └ Ongoing breach monitoring\n"
            "   └ Long-term security visibility\n\n"
            "━━━━━━━━━━━━━━━\n"
            "💡 *Enterprise Features*\n"
            "Exploitation proof • Advanced OSINT • GitHub secret scanning • Priority monitoring"
        )
        await context.bot.send_message(chat_id=query.message.chat_id, text=how_text, parse_mode="Markdown")
        try:
            await query.edit_message_text("🔮 Return to main menu:", reply_markup=main_menu(username == ADMIN_USERNAME))
        except Exception as e:
            if "Message is not modified" not in str(e):
                print(f"Edit error: {e}")
        return

    if data == "check_breaches":
        if not is_active(username):
            await query.edit_message_text("⛔ Not authorized or trial expired.")
            return
        c.execute("SELECT email_collect FROM clients WHERE username=?", (username,))
        row = c.fetchone()
        email = row[0] if row else ""
        if not email:
            await query.edit_message_text("📧 Please set your email first using the *Set Email* button.")
        else:
            await query.edit_message_text("🩸 Checking breaches...")
            await check_breach(email, context, query.message.chat_id)
        return

    if data == "subscribe":
        if not is_active(username):
            await query.edit_message_text("⛔ Not authorized or trial expired.")
            return
        try:
            await query.edit_message_text("📌 Send the domain you want to monitor weekly:")
        except Exception as e:
            if "Message is not modified" not in str(e):
                print(f"Edit error: {e}")
        context.user_data["state"] = "SUBSCRIBE_DOMAIN"
        return

    if data == "github_scan":
        if not is_client(username):
            await query.edit_message_text("🔑 This feature requires Enterprise plan.")
            return
        try:
            await query.edit_message_text("🔑 Send the GitHub repository URL (e.g., https://github.com/user/repo):")
        except Exception as e:
            if "Message is not modified" not in str(e):
                print(f"Edit error: {e}")
        context.user_data["state"] = "GITHUB_SCAN"
        return

    if data == "help":
        help_text = (
            "🛠 *Security Toolkit*\n"
            "━━━━━━━━━━━━━━━\n\n"
            "⚡ *Nmap*\n   └ Ports & vulnerability discovery\n\n"
            "🕵️ *Nikto*\n   └ Web server vulnerability scanning\n\n"
            "🔎 *WhatWeb*\n   └ Website technology fingerprinting\n\n"
            "📧 *theHarvester*\n   └ Email & OSINT collection\n\n"
            "🔄 *dnstwist*\n   └ Detect fake / typosquatted domains\n\n"
            "📄 *Metagoofil*\n   └ Extract metadata from public files\n\n"
            "👤 *Sherlock*\n   └ Social media username tracking\n\n"
            "🦠 *Dalfox*\n   └ Automated XSS scanning\n\n"
            "🩸 *Check Breaches*\n   └ Email breach lookup\n\n"
            "🔑 *GitHub Scan*\n   └ Detect exposed secrets & keys\n\n"
            "━━━━━━━━━━━━━━━\n"
            "🚀 *Upgrade Available*\n"
            "PDF reports • Compliance mapping • Advanced scans"
        )
        await context.bot.send_message(chat_id=query.message.chat_id, text=help_text, parse_mode="Markdown")
        try:
            await query.edit_message_text("🔮 Return to main menu:", reply_markup=main_menu(username == ADMIN_USERNAME))
        except Exception as e:
            if "Message is not modified" not in str(e):
                print(f"Edit error: {e}")
        return

    if data == "contact_admin":
        msg = f"📩 Contact the admin directly: @{ADMIN_USERNAME}\n\n👉 https://t.me/{ADMIN_USERNAME}"
        try:
            await query.edit_message_text(msg)
        except Exception as e:
            if "Message is not modified" not in str(e):
                print(f"Edit error: {e}")
        return

    # Admin
    if data == "admin_menu":
        if username != ADMIN_USERNAME:
            return
        try:
            await query.edit_message_text("👑 Admin Panel:", reply_markup=admin_menu())
        except Exception as e:
            if "Message is not modified" not in str(e):
                print(f"Edit error: {e}")
        return

    if data == "admin_adduser":
        if username != ADMIN_USERNAME:
            return
        try:
            await query.edit_message_text("Enter client username (with @):")
        except Exception as e:
            if "Message is not modified" not in str(e):
                print(f"Edit error: {e}")
        context.user_data["state"] = "ADDUSER_USERNAME"
        return

    if data == "admin_verify":
        if username != ADMIN_USERNAME:
            return
        try:
            await query.edit_message_text("Enter client username (with @):")
        except Exception as e:
            if "Message is not modified" not in str(e):
                print(f"Edit error: {e}")
        context.user_data["state"] = "VERIFY_USERNAME"
        return

    if data == "admin_status":
        if username != ADMIN_USERNAME:
            return
        c.execute("SELECT username, plan, expiry FROM clients")
        clients = c.fetchall()
        msg = "📊 Client List\n\n"
        for u, p, e in clients:
            msg += f"@{u} - {p}"
            if e: msg += f" (exp: {e})"
            msg += "\n"
        try:
            await query.edit_message_text(msg, reply_markup=admin_menu())
        except Exception as e:
            if "Message is not modified" not in str(e):
                print(f"Edit error: {e}")
        return

    if data == "admin_removeuser":
        if username != ADMIN_USERNAME:
            return
        try:
            await query.edit_message_text("Enter the username of the client to remove (with @):")
        except Exception as e:
            if "Message is not modified" not in str(e):
                print(f"Edit error: {e}")
        context.user_data["state"] = "REMOVE_USER"
        return


async def message_handler(update, context):
    username = update.message.from_user.username
    text = update.message.text.strip()
    state = context.user_data.get("state")

    if text == "🛡️ Menu":
        await update.message.reply_text("Menu:", reply_markup=main_menu(username == ADMIN_USERNAME))
        return

    if state == "SET_EMAIL":
        if "@" not in text:
            await update.message.reply_text("Invalid email.")
            return
        c.execute("UPDATE clients SET email_collect=? WHERE username=?", (text, username))
        conn.commit()
        await update.message.reply_text(f"✅ Email set.", reply_markup=main_menu(username == ADMIN_USERNAME))
        context.user_data.pop("state", None)
        return

    if state == "SUBSCRIBE_DOMAIN":
        domain = text.lower()
        if not re.match(r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$", domain):
            await update.message.reply_text("Invalid domain.")
            return
        c.execute("INSERT OR REPLACE INTO subscriptions VALUES (?,?,?,?)", (username, domain, datetime.now().isoformat(), "{}"))
        conn.commit()
        await update.message.reply_text(f"✅ Subscribed to weekly scans for {domain}.", reply_markup=main_menu(username == ADMIN_USERNAME))
        context.user_data.pop("state", None)
        return

    if state == "GITHUB_SCAN":
        repo_url = text.strip()
        if not repo_url.startswith("https://github.com/"):
            await update.message.reply_text("Invalid GitHub URL.")
            return
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
                await update.message.reply_text(summary, parse_mode="Markdown")
        except Exception as e:
            await update.message.reply_text(f"❌ GitHub scan failed: {e}")
        context.user_data.pop("state", None)
        return

    if state == "REMOVE_USER":
        if username != ADMIN_USERNAME:
            await update.message.reply_text("❌ Admin only.")
            return
        target = text.lstrip("@")
        if not is_client(target):
            await update.message.reply_text("User is not a client.")
            return
        c.execute("UPDATE clients SET expiry='2000-01-01' WHERE username=?", (target,))
        conn.commit()
        await update.message.reply_text(f"❌ User @{target} has been removed. They can no longer use the bot.", reply_markup=admin_menu())
        context.user_data.pop("state", None)
        return

    if state == "ADDUSER_USERNAME":
        if username != ADMIN_USERNAME:
            await update.message.reply_text("❌ Admin only.")
            return
        target = text.lstrip("@")
        if not target:
            await update.message.reply_text("Invalid username.")
            return
        context.user_data["add_target"] = target
        await update.message.reply_text("Plan? (free, monthly, enterprise):")
        context.user_data["state"] = "ADDUSER_PLAN"
        return

    if state == "ADDUSER_PLAN":
        plan = text.lower()
        if plan not in ["free", "monthly", "enterprise"]:
            await update.message.reply_text("Invalid plan. Use free, monthly, or enterprise:")
            return
        context.user_data["add_plan"] = plan
        await update.message.reply_text("How many months? (0 for free trial):")
        context.user_data["state"] = "ADDUSER_MONTHS"
        return

    if state == "ADDUSER_MONTHS":
        try:
            months = int(text)
        except:
            await update.message.reply_text("Enter a number.")
            return
        target = context.user_data["add_target"]
        plan = context.user_data["add_plan"]
        add_client(target, plan, months)
        await update.message.reply_text(f"✅ Added @{target} with {plan} plan.", reply_markup=admin_menu())
        for k in ("add_target", "add_plan", "state"):
            context.user_data.pop(k, None)
        return

    if state == "VERIFY_USERNAME":
        if username != ADMIN_USERNAME:
            await update.message.reply_text("❌ Admin only.")
            return
        target = text.lstrip("@")
        if not is_client(target):
            await update.message.reply_text("User not a client.")
            return
        context.user_data["verify_target"] = target
        await update.message.reply_text("Domain to verify (e.g., example.com):")
        context.user_data["state"] = "VERIFY_DOMAIN"
        return

    if state == "VERIFY_DOMAIN":
        target = context.user_data["verify_target"]
        domain = text.lower()
        c.execute("INSERT OR REPLACE INTO verification VALUES (?,?,?)", (target, domain, "admin_verified"))
        conn.commit()
        await update.message.reply_text(f"✅ Domain {domain} verified for @{target}.", reply_markup=admin_menu())
        context.user_data.pop("state", None)
        context.user_data.pop("verify_target", None)
        return

    if state == "SCAN_DOMAIN":
        domain = text.lower()
        if not re.match(r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$", domain):
            await update.message.reply_text("❌ Invalid domain.")
            return
        if not is_active(username):
            await update.message.reply_text("⛔ Not authorized or trial expired.")
            return

        if username != ADMIN_USERNAME:
            c.execute("SELECT token FROM verification WHERE username=? AND domain=?", (username, domain))
            row = c.fetchone()
            if row and row[0] == "admin_verified":
                pass
            elif row and row[0] != "admin_verified":
                if not verify_domain(domain, row[0]):
                    await update.message.reply_text("⏳ Verification file missing.")
                    return
            else:
                token = generate_token()
                c.execute("INSERT OR REPLACE INTO verification VALUES (?,?,?)", (username, domain, token))
                conn.commit()
                await update.message.reply_text(
                    f"🔐 To verify, upload a file `verify.txt` with token:\n`{token}`\nto the root of your site, then send the domain again."
                )
                return

        await update.message.reply_text("✅ Domain verified. Launching scan...")
        chat_id = update.message.chat_id

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
        tools = context.user_data.get("tools", None)

        results = await loop.run_in_executor(None, run_scan, domain, email, sync_progress, tools)

        try:
            await progress_msg.delete()
        except:
            pass

        if results:
            c.execute("SELECT plan FROM clients WHERE username=?", (username,))
            row = c.fetchone()
            plan = row[0] if row else "free"
            detailed = plan in ("monthly", "enterprise")
            summary = format_summary(domain, results, detailed)
            await context.bot.send_message(chat_id=chat_id, text=summary, parse_mode="Markdown")

            # Mark free plan as used
            c.execute("SELECT plan FROM clients WHERE username=?", (username,))
            row = c.fetchone()
            plan = row[0] if row else "free"
            if plan == "free":
                c.execute("UPDATE clients SET scan_used=1 WHERE username=?", (username,))
                conn.commit()

            # PDF reports are available on paid plans.
            # Contact admin to upgrade.
        else:
            await context.bot.send_message(chat_id=chat_id, text="❌ Scan failed.")

        context.user_data.pop("state", None)
        context.user_data.pop("scan_type", None)
        context.user_data.pop("tools", None)
        await update.message.reply_text("🔮 What's next?", reply_markup=main_menu(username == ADMIN_USERNAME))
        return

    await update.message.reply_text("I didn't understand. Use the buttons below.", reply_markup=main_menu(username == ADMIN_USERNAME))


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
