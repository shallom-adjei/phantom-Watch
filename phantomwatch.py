#!/usr/bin/env python3
import subprocess, io, re, os, sqlite3, random, string, json, time, asyncio, shutil, requests
from datetime import datetime, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, CallbackQueryHandler, filters, ContextTypes

BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
DB_FILE = "phantom_clients.db"
from fpdf import FPDF
SCAN_TIMEOUT = 150

conn = sqlite3.connect(DB_FILE, check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS clients (username TEXT PRIMARY KEY, plan TEXT DEFAULT 'free', expiry TEXT, email_collect TEXT DEFAULT '')''')

c.execute('''CREATE TABLE IF NOT EXISTS subscriptions (
    username TEXT, domain TEXT,
    last_scan_time TEXT, last_report_json TEXT,
    PRIMARY KEY(username, domain)
)''')
conn.commit()

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
    await context.bot.send_message(chat_id=chat_id, text="✅ No breaches found for this email.")


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
    # Nmap
    if 'nmap' in results:
        ports = len(re.findall(r"^\d+/tcp\s+open\s+", results.get('nmap',''), re.MULTILINE))
        vulns = len(re.findall(r"\|.*VULNERABLE.*", results.get('nmap','')))
        if ports or vulns:
            lines.append(f"🛡️ Nmap: {ports} open ports, {vulns} potential vulns")
        else:
            lines.append("🛡️ Nmap: No open ports or vulns found.")
    else:
        lines.append("🛡️ Nmap: Not run.")
    # Nikto
    if 'nikto' in results:
        issues = len(re.findall(r"\+ (.*)", results.get('nikto','')))
        if issues:
            lines.append(f"🔥 Nikto: {issues} web issues")
        else:
            lines.append("🔥 Nikto: No web issues found.")
    else:
        lines.append("🔥 Nikto: Not run.")
    # WhatWeb
    if 'whatweb' in results:
        clean = re.sub(r'\x1b\[[0-9;]*m', '', results.get('whatweb',''))
        servers = re.findall(r'HTTPServer\[ (.*?) \]', clean)
        if servers:
            lines.append(f"🧩 Technology: {servers[0]}")
        else:
            lines.append("🧩 Technology: No server header detected.")

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

def generate_pdf_report(domain, results, plan):
    pdf = FPDF()
    pdf.add_page()
    pdf.add_font("DejaVu", "", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", uni=True)
    pdf.add_font("DejaVu", "B", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", uni=True)

    pdf.set_font("DejaVu", "B", 16)
    pdf.cell(0, 10, "PHANTOM WATCH Security Report", ln=True, align="C")
    pdf.set_font("DejaVu", "", 10)
    pdf.cell(0, 10, f"Domain: {domain}", ln=True)
    pdf.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", ln=True)
    pdf.ln(5)

    # ---- DETAILED FINDINGS ----
    pdf.set_font("DejaVu", "B", 12)
    pdf.cell(0, 10, "Detailed Findings", ln=True)
    pdf.set_font("DejaVu", "", 9)

    # Nmap
    if 'nmap' in results:
        raw = results['nmap']
        open_ports = re.findall(r"^\d+/tcp\s+open\s+(.*)", raw, re.MULTILINE)
        vulns = re.findall(r"\|.*VULNERABLE.*", raw)
        if open_ports:
            pdf.set_font("DejaVu", "B", 10)
            pdf.cell(0, 6, "Open Ports:", ln=True)
            pdf.set_font("DejaVu", "", 9)
            for p in open_ports[:10]:
                pdf.multi_cell(0, 5, f"• {p}")
        if vulns:
            pdf.set_font("DejaVu", "B", 10)
            pdf.cell(0, 6, "Potential Vulnerabilities:", ln=True)
            pdf.set_font("DejaVu", "", 9)
            for v in vulns[:5]:
                pdf.multi_cell(0, 5, f"• {v.strip()}")
        if not open_ports and not vulns:
            pdf.cell(0, 6, "No open ports or vulnerabilities detected.", ln=True)

    # Nikto
    if 'nikto' in results:
        findings = re.findall(r"\+ (.*)", results['nikto'])
        if findings:
            pdf.set_font("DejaVu", "B", 10)
            pdf.cell(0, 6, "Web Application Issues:", ln=True)
            pdf.set_font("DejaVu", "", 9)
            for f in findings[:10]:
                pdf.multi_cell(0, 5, f"• {f}")
        else:
            pdf.cell(0, 6, "No web application issues found.", ln=True)

    # WhatWeb
    if 'whatweb' in results:
        clean = re.sub(r'\x1b\[[0-9;]*m', '', results['whatweb'])
        pdf.cell(0, 6, f"Technology: {clean[:200]}", ln=True)

    # theHarvester
    if 'theHarvester' in results and results['theHarvester'] != "No email":
        harvest = results['theHarvester']
        if "<html" in harvest.lower():
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", harvest)
            if emails:
                pdf.set_font("DejaVu", "B", 10)
                pdf.cell(0, 6, f"Leaked Emails ({len(emails)}):", ln=True)
                pdf.set_font("DejaVu", "", 9)
                pdf.multi_cell(0, 5, ", ".join(emails[:10]))

    # dnstwist
    if 'dnstwist' in results:
        registered = re.findall(r"^([^ ]+)\s+registered.*", results['dnstwist'], re.MULTILINE)
        if registered:
            pdf.set_font("DejaVu", "B", 10)
            pdf.cell(0, 6, "Typosquatting Domains:", ln=True)
            pdf.set_font("DejaVu", "", 9)
            for d in registered[:5]:
                pdf.multi_cell(0, 5, f"• {d}")

    # Metagoofil
    if 'metagoofil' in results and "No metadata" not in results.get('metagoofil',''):
        pdf.set_font("DejaVu", "B", 10)
        pdf.cell(0, 6, "Document Metadata Leaks:", ln=True)
        pdf.set_font("DejaVu", "", 9)
        pdf.multi_cell(0, 5, results['metagoofil'][:500])

    # Sherlock
    if 'sherlock' in results:
        found = re.findall(r"\[\+\] (.*)", results['sherlock'])
        if found:
            pdf.set_font("DejaVu", "B", 10)
            pdf.cell(0, 6, "Social Media Accounts:", ln=True)
            pdf.set_font("DejaVu", "", 9)
            for f in found[:10]:
                pdf.multi_cell(0, 5, f"• {f}")

    # ---- COMPLIANCE TABLE ----
    pdf.ln(5)
    pdf.set_font("DejaVu", "B", 12)
    pdf.cell(0, 10, "Compliance Status", ln=True)
    pdf.set_font("DejaVu", "", 9)
    for category, rules in COMPLIANCE.items():
        if category == "xss" and 'dalfox' in results and "vulnerable" in results.get('dalfox','').lower():
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

    else:
        lines.append("🧩 Technology: Not run.")
    # theHarvester
    if 'theHarvester' in results:
        harvest = results['theHarvester']
        if harvest == "No email":
            lines.append("📧 theHarvester: No email set – skipped.")
        elif "<html" in harvest.lower():
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", harvest)
            if emails:
                lines.append(f"📧 Emails leaked: {len(emails)}")
            else:
                lines.append("📧 theHarvester: No leaked emails found.")
        else:
            lines.append("📧 theHarvester: No results.")
    else:
        lines.append("📧 theHarvester: Not run.")
    # dnstwist
    if 'dnstwist' in results:
        registered = len(re.findall(r"^([^ ]+)\s+registered.*", results.get('dnstwist',''), re.MULTILINE))
        if registered:
            lines.append(f"🕵️ Typosquatting: {registered} domains registered")
        else:
            lines.append("🕵️ Typosquatting: No similar domains registered.")
    else:
        lines.append("🕵️ dnstwist: Not run.")
    # Metagoofil
    if 'metagoofil' in results:
        if "No metadata" in results.get('metagoofil',''):
            lines.append("📄 Metagoofil: No metadata leaks found.")
        else:
            lines.append("📄 Document metadata leaks found")
    else:
        lines.append("📄 Metagoofil: Not run.")
    # Sherlock
    if 'sherlock' in results:
        found = len(re.findall(r"\[\+\] (.*)", results.get('sherlock','')))
        if found:
            lines.append(f"👥 Social media: {found} accounts found")
        else:
            lines.append("👥 Social media: No accounts found.")
    else:
        lines.append("👥 Sherlock: Not run.")
    lines.append("\n⚠️ Upgrade to Monthly/Enterprise for full PDF reports & compliance mapping.")
    return "\n".join(lines)
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


def quick_scan_menu():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🛡️ Ports & Vulns", callback_data="quick_ports")],
        [InlineKeyboardButton("🌐 OSINT Pack", callback_data="quick_osint")],
        [InlineKeyboardButton("🔎 Recon", callback_data="quick_recon")],
        [InlineKeyboardButton("🦠 XSS Check", callback_data="quick_xss")],
        [InlineKeyboardButton("🔙 Main Menu", callback_data="main_menu")],
    ])

def admin_menu():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Add User", callback_data="admin_adduser")],
        [InlineKeyboardButton("✅ Verify Domain", callback_data="admin_verify")],
        [InlineKeyboardButton("❌ Remove User", callback_data="admin_removeuser")],
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
    if data == "scan_quick":
        if not is_active(username):
            await query.edit_message_text("⛔ Not authorized or trial expired."); return
        await query.edit_message_text("Choose a quick scan type:", reply_markup=quick_scan_menu())
        return
    if data.startswith("quick_"):
        if not is_active(username):
            await query.edit_message_text("⛔ Not authorized or trial expired."); return
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
            "• Continuous CVE monitoring\n"
            "• GitHub secret scanning\n"
            "• Priority support\n"
            "*Price:* $2,000/month\n\n"
            "📩 Contact admin to subscribe or upgrade."
        )
        await context.bot.send_message(chat_id=query.message.chat_id, text=pricing_text, parse_mode='Markdown')
        await query.edit_message_text("🔮 Return to main menu:", reply_markup=main_menu(username == ADMIN_USERNAME))
        return
    if data == "how_it_works":
        how_text = (
            "📖 *How Phantom Watch Operates*\n"
            "1️⃣ *Registration* – Admin adds you & verifies your domain.\n"
            "2️⃣ *Choose a Scan* – Full or Quick.\n"
            "3️⃣ *Live Monitoring* – Instant alerts for critical findings.\n"
            "4️⃣ *Professional PDF Report* – Includes compliance mapping.\n"
            "5️⃣ *Continuous Protection* – Subscribe to weekly scans & breach checks.\n"
            "💡 Enterprise plan includes exploitation proof and GitHub secret scanning."
        )
        await context.bot.send_message(chat_id=query.message.chat_id, text=how_text, parse_mode='Markdown')
        await query.edit_message_text("🔮 Return to main menu:", reply_markup=main_menu(username == ADMIN_USERNAME))
        return
    if data == "check_breaches":
        if not is_active(username):
            await query.edit_message_text("⛔ Not authorized or trial expired."); return
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
        if not is_active(username):
            await query.edit_message_text("⛔ Not authorized or trial expired."); return
        await query.edit_message_text("📌 Send the domain you want to monitor weekly:")
        context.user_data['state'] = "SUBSCRIBE_DOMAIN"
        return
    if data == "github_scan":
        # Only enterprise can use, but we'll just check if client exists for now
        if not is_client(username):
            await query.edit_message_text("🔑 This feature requires Enterprise plan."); return
        await query.edit_message_text("🔑 Send the GitHub repository URL (e.g., https://github.com/user/repo):")
        context.user_data['state'] = "GITHUB_SCAN"
        return
    if data == "admin_removeuser":
        if username != ADMIN_USERNAME: return
        await query.edit_message_text("Enter the username of the client to remove (with @):")
        context.user_data['state'] = "REMOVE_USER"
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


    # ----- SET EMAIL -----
    if state == "SET_EMAIL":
        if '@' not in text:
            await update.message.reply_text("Invalid email."); return
        c.execute("UPDATE clients SET email_collect=? WHERE username=?", (text, username))
        conn.commit()
        await update.message.reply_text(f"✅ Email set.", reply_markup=main_menu(username == ADMIN_USERNAME))
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
        await update.message.reply_text(f"✅ Subscribed to weekly scans for {domain}.", reply_markup=main_menu(username == ADMIN_USERNAME))
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

    # ----- REMOVE USER -----
    if state == "REMOVE_USER":
        if username != ADMIN_USERNAME:
            await update.message.reply_text("❌ Admin only."); return
        target = text.lstrip('@')
        if not is_client(target):
            await update.message.reply_text("User is not a client."); return
        c.execute("UPDATE clients SET expiry='2000-01-01' WHERE username=?", (target,))
        conn.commit()
        await update.message.reply_text(f"❌ User @{target} has been removed. They can no longer use the bot.",
                                        reply_markup=admin_menu())
        context.user_data.pop('state', None)
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
            # Send PDF for monthly/enterprise plans
            c.execute("SELECT plan FROM clients WHERE username=?", (username,))
            row = c.fetchone()
            plan = row[0] if row else "free"
            if plan in ("monthly", "enterprise"):
                try:
                    pdf_buf = generate_pdf_report(domain, results, plan)
                    pdf_buf.name = f"PhantomWatch-{domain}-report.pdf"
                    await context.bot.send_document(chat_id=chat_id, document=pdf_buf, caption="📎 Detailed compliance report")
                except Exception as e:
                    await context.bot.send_message(chat_id=chat_id, text=f"⚠️ PDF generation failed: {e}")
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
