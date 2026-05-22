"""Client‑facing button handlers."""
import asyncio, os, re, json, random, shutil, time, subprocess
from datetime import datetime
import requests
from bot.database import is_active, is_client, generate_token, verify_domain, conn, c, ADMIN_USERNAME
from bot.scanners import run_scan
from bot.reports import format_summary
from bot.menus import main_menu, admin_menu

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
                lines = [f"🩸 *Breach Report for {email}*", f"Found in *{total}* known breaches:\n"]
                for name, info in list(breach_details.items())[:10]:
                    domain = info.get("domain", "unknown")
                    date = info.get("breach_date", "N/A")
                    lines.append(f"• *{name}* ({domain}) – {date}")
                if total > 10:
                    lines.append(f"… and {total - 10} more breaches.")
                await context.bot.send_message(chat_id=chat_id, text="\n".join(lines), parse_mode="Markdown")
                return
    except:
        pass
    await context.bot.send_message(chat_id=chat_id, text="✅ No breaches found for this email.")

# Handlers for each callback
async def start_command(update, context):
    from bot.menus import menu_button
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

async def scan_full_handler(update, context):
    query = update.callback_query
    await query.answer()
    username = query.from_user.username
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

async def scan_quick_handler(update, context):
    query = update.callback_query
    await query.answer()
    username = query.from_user.username
    if not is_active(username):
        await query.edit_message_text("⛔ Not authorized or trial expired.")
        return
    from bot.menus import quick_scan_menu
    try:
        await query.edit_message_text("Choose a quick scan type:", reply_markup=quick_scan_menu())
    except Exception as e:
        if "Message is not modified" not in str(e):
            print(f"Edit error: {e}")

async def quick_scan_subhandler(update, context):
    query = update.callback_query
    await query.answer()
    data = query.data
    username = query.from_user.username
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

async def set_email_handler(update, context):
    query = update.callback_query
    await query.answer()
    try:
        await query.edit_message_text("📧 Please send your email address:")
    except Exception as e:
        if "Message is not modified" not in str(e):
            print(f"Edit error: {e}")
    context.user_data["state"] = "SET_EMAIL"

async def pricing_handler(update, context):
    query = update.callback_query
    await query.answer()
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
        await query.edit_message_text("🔮 Return to main menu:", reply_markup=main_menu(query.from_user.username == ADMIN_USERNAME))
    except Exception as e:
        if "Message is not modified" not in str(e):
            print(f"Edit error: {e}")

async def how_it_works_handler(update, context):
    query = update.callback_query
    await query.answer()
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
        await query.edit_message_text("🔮 Return to main menu:", reply_markup=main_menu(query.from_user.username == ADMIN_USERNAME))
    except Exception as e:
        if "Message is not modified" not in str(e):
            print(f"Edit error: {e}")

async def check_breaches_handler(update, context):
    query = update.callback_query
    await query.answer()
    username = query.from_user.username
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

async def subscribe_handler(update, context):
    query = update.callback_query
    await query.answer()
    username = query.from_user.username
    if not is_active(username):
        await query.edit_message_text("⛔ Not authorized or trial expired.")
        return
    try:
        await query.edit_message_text("📌 Send the domain you want to monitor weekly:")
    except Exception as e:
        if "Message is not modified" not in str(e):
            print(f"Edit error: {e}")
    context.user_data["state"] = "SUBSCRIBE_DOMAIN"

async def github_scan_handler(update, context):
    query = update.callback_query
    await query.answer()
    username = query.from_user.username
    if not is_client(username):
        await query.edit_message_text("🔑 This feature requires Enterprise plan.")
        return
    try:
        await query.edit_message_text("🔑 Send the GitHub repository URL (e.g., https://github.com/user/repo):")
    except Exception as e:
        if "Message is not modified" not in str(e):
            print(f"Edit error: {e}")
    context.user_data["state"] = "GITHUB_SCAN"

async def help_handler(update, context):
    query = update.callback_query
    await query.answer()
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
        await query.edit_message_text("🔮 Return to main menu:", reply_markup=main_menu(query.from_user.username == ADMIN_USERNAME))
    except Exception as e:
        if "Message is not modified" not in str(e):
            print(f"Edit error: {e}")

async def contact_admin_handler(update, context):
    query = update.callback_query
    await query.answer()
    username = query.from_user.username
    msg = f"📩 Contact the admin directly: @{ADMIN_USERNAME}\n\n👉 https://t.me/{ADMIN_USERNAME}"
    try:
        await query.edit_message_text(msg)
    except Exception as e:
        if "Message is not modified" not in str(e):
            print(f"Edit error: {e}")

async def main_menu_handler(update, context):
    query = update.callback_query
    await query.answer()
    username = query.from_user.username
    try:
        await query.edit_message_text("⬇️ Main Menu:", reply_markup=main_menu(username == ADMIN_USERNAME))
    except Exception as e:
        if "Message is not modified" not in str(e):
            print(f"Edit error: {e}")

# Message handler for client states
async def handle_client_message(update, context):
    username = update.message.from_user.username
    text = update.message.text.strip()
    state = context.user_data.get("state")

    if text == "🛡️ Menu":
        await update.message.reply_text("Menu:", reply_markup=main_menu(username == ADMIN_USERNAME))
        return True

    if state == "SET_EMAIL":
        if "@" not in text:
            await update.message.reply_text("Invalid email.")
            return True
        c.execute("UPDATE clients SET email_collect=? WHERE username=?", (text, username))
        conn.commit()
        await update.message.reply_text(f"✅ Email set.", reply_markup=main_menu(username == ADMIN_USERNAME))
        context.user_data.pop("state", None)
        return True

    if state == "SUBSCRIBE_DOMAIN":
        domain = text.lower()
        if not re.match(r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$", domain):
            await update.message.reply_text("Invalid domain.")
            return True
        c.execute("INSERT OR REPLACE INTO subscriptions VALUES (?,?,?,?)", (username, domain, datetime.now().isoformat(), "{}"))
        conn.commit()
        await update.message.reply_text(f"✅ Subscribed to weekly scans for {domain}.", reply_markup=main_menu(username == ADMIN_USERNAME))
        context.user_data.pop("state", None)
        return True

    if state == "GITHUB_SCAN":
        repo_url = text.strip()
        if not repo_url.startswith("https://github.com/"):
            await update.message.reply_text("Invalid GitHub URL.")
            return True
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
        return True

    return False

# Scan domain handler
async def handle_scan_domain(update, context):
    username = update.message.from_user.username
    domain = update.message.text.strip().lower()
    if not re.match(r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$", domain):
        await update.message.reply_text("❌ Invalid domain.")
        return True
    if not is_active(username):
        await update.message.reply_text("⛔ Not authorized or trial expired.")
        return True

    # Verification
    if username != ADMIN_USERNAME:
        c.execute("SELECT token FROM verification WHERE username=? AND domain=?", (username, domain))
        row = c.fetchone()
        if row and row[0] == "admin_verified":
            pass
        elif row and row[0] != "admin_verified":
            if not verify_domain(domain, row[0]):
                await update.message.reply_text("⏳ Verification file missing.")
                return True
        else:
            token = generate_token()
            c.execute("INSERT OR REPLACE INTO verification VALUES (?,?,?)", (username, domain, token))
            conn.commit()
            await update.message.reply_text(
                f"🔐 To verify, upload a file `verify.txt` with token:\n`{token}`\nto the root of your site, then send the domain again."
            )
            return True

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

        if plan == "free":
            c.execute("UPDATE clients SET scan_used=1 WHERE username=?", (username,))
            conn.commit()
    else:
        await context.bot.send_message(chat_id=chat_id, text="❌ Scan failed.")

    context.user_data.pop("state", None)
    context.user_data.pop("scan_type", None)
    context.user_data.pop("tools", None)
    await update.message.reply_text("🔮 What's next?", reply_markup=main_menu(username == ADMIN_USERNAME))
    return True
