"""Client‑facing button handlers."""
import asyncio, os, re, json, random, shutil, time, subprocess, traceback
from datetime import datetime
import requests
from bot.database import is_active, is_client, generate_token, verify_domain, conn, c
from bot.config import ADMIN_USERNAME
from bot.scanners import run_scan
from bot.reports import build_report_markdown
from bot.menus import main_menu, admin_menu

# ---------- safe message editing ----------
async def safe_edit(query, text, **kwargs):
    try:
        await query.edit_message_text(text, **kwargs)
    except Exception:
        pass  # silently ignore all edit failures

# ---------- breach check ----------
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

# ---------- callback handlers ----------
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
    try:
        await query.answer()
    except:
        pass
    username = query.from_user.username
    if not is_active(username):
        await safe_edit(query, "⛔ Not authorized or trial expired.")
        return
    context.user_data["state"] = "SCAN_DOMAIN"
    context.user_data["scan_type"] = "full"
    context.user_data["tools"] = None
    await safe_edit(query, "📌 Send the domain name to scan.")

async def scan_quick_handler(update, context):
    query = update.callback_query
    try:
        await query.answer()
    except:
        pass
    username = query.from_user.username
    if not is_active(username):
        await safe_edit(query, "⛔ Not authorized or trial expired.")
        return
    from bot.menus import quick_scan_menu
    await safe_edit(query, "Choose a quick scan type:", reply_markup=quick_scan_menu())

async def quick_scan_subhandler(update, context):
    query = update.callback_query
    try:
        await query.answer()
    except:
        pass
    data = query.data
    username = query.from_user.username
    if not is_active(username):
        await safe_edit(query, "⛔ Not authorized or trial expired.")
        return

    tools = None
    if data == "quick_ports":
        tools = ["nmap", "nikto"]
    elif data == "quick_osint":
        tools = ["theHarvester", "sherlock"]
    elif data == "quick_subfinder":
        tools = ["subfinder"]
    elif data == "quick_ffuf":
        tools = ["ffuf"]
    elif data == "quick_nuclei":
        tools = ["nuclei"]
    elif data == "quick_recon":
        tools = ["whatweb", "dnstwist", "metagoofil"]
    elif data == "quick_xss":
        tools = ["dalfox"]
    elif data == "quick_amass":
        tools = ["amass"]
    elif data == "quick_gitleaks":
        # Gitleaks requires a GitHub URL – set state and return immediately
        context.user_data["state"] = "GITHUB_SCAN"
        await query.edit_message_text("🔑 Send the GitHub repository URL (e.g., https://github.com/user/repo):")
        return

    if tools is None:
        # fallback – should never happen
        tools = []

    context.user_data["state"] = "SCAN_DOMAIN"
    context.user_data["tools"] = tools
    context.user_data["scan_type"] = "quick"
    await safe_edit(query, "📌 Send the domain name to scan.")

        # Gitleaks requires a GitHub URL, so we'll set a special state
        context.user_data["state"] = "GITHUB_SCAN"
        await query.edit_message_text("🔑 Send the GitHub repository URL (e.g., https://github.com/user/repo):")
    context.user_data["state"] = "SCAN_DOMAIN"
    context.user_data["tools"] = tools
    context.user_data["scan_type"] = "quick"
    await safe_edit(query, "📌 Send the domain name to scan.")

async def set_email_handler(update, context):
    query = update.callback_query
    try:
        await query.answer()
    except:
        pass
    await safe_edit(query, "📧 Please send your email address:")
    context.user_data["state"] = "SET_EMAIL"

async def pricing_handler(update, context):
    query = update.callback_query
    try:
        await query.answer()
    except:
        pass
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
    await safe_edit(query, "🔮 Return to main menu:", reply_markup=main_menu(query.from_user.username == ADMIN_USERNAME))

async def how_it_works_handler(update, context):
    query = update.callback_query
    try:
        await query.answer()
    except:
        pass
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
    await safe_edit(query, "🔮 Return to main menu:", reply_markup=main_menu(query.from_user.username == ADMIN_USERNAME))

async def check_breaches_handler(update, context):
    query = update.callback_query
    try:
        await query.answer()
    except:
        pass
    username = query.from_user.username
    if not is_active(username):
        await safe_edit(query, "⛔ Not authorized or trial expired.")
        return
    c.execute("SELECT email_collect FROM clients WHERE username=?", (username,))
    row = c.fetchone()
    email = row[0] if row else ""
    if not email:
        await safe_edit(query, "📧 Please set your email first using the *Set Email* button.")
    else:
        await safe_edit(query, "🩸 Checking breaches...")
        await check_breach(email, context, query.message.chat_id)

async def subscribe_handler(update, context):
    query = update.callback_query
    try:
        await query.answer()
    except:
        pass
    username = query.from_user.username
    if not is_active(username):
        await safe_edit(query, "⛔ Not authorized or trial expired.")
        return
    await safe_edit(query, "📌 Send the domain you want to monitor weekly:")
    context.user_data["state"] = "SUBSCRIBE_DOMAIN"

async def github_scan_handler(update, context):
    query = update.callback_query
    try:
        await query.answer()
    except:
        pass
    username = query.from_user.username
    if not is_client(username):
        await safe_edit(query, "🔑 This feature requires Enterprise plan.")
        return
    await safe_edit(query, "🔑 Send the GitHub repository URL (e.g., https://github.com/user/repo):")
    context.user_data["state"] = "GITHUB_SCAN"

async def help_handler(update, context):
    query = update.callback_query
    try:
        await query.answer()
    except:
        pass
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
    await safe_edit(query, "🔮 Return to main menu:", reply_markup=main_menu(query.from_user.username == ADMIN_USERNAME))

async def contact_admin_handler(update, context):
    query = update.callback_query
    try:
        await query.answer()
    except:
        pass
    username = query.from_user.username
    msg = f"📩 Contact the admin directly: @{ADMIN_USERNAME}\n\n👉 https://t.me/{ADMIN_USERNAME}"
    await safe_edit(query, msg)

async def main_menu_handler(update, context):
    query = update.callback_query
    try:
        await query.answer()
    except:
        pass
    username = query.from_user.username
    await safe_edit(query, "⬇️ Main Menu:", reply_markup=main_menu(username == ADMIN_USERNAME))

# ---------- message handlers ----------
async def handle_client_message(update, context):
    username = update.message.from_user.username
    text = update.message.text.strip()
    state = context.user_data.get("state")

    if text == "🛡️ Menu":
        await update.message.reply_text("Menu:", reply_markup=main_menu(username == ADMIN_USERNAME))
        return True

    # Auto-detect GitHub URLs even if state is wrong
    if text.startswith("https://github.com/"):
        await update.message.reply_text("🔑 Scanning GitHub repository...")
        try:
            repo_url = text.strip()
            repo_name = repo_url.rstrip("/").split("/")[-1]
            clone_dir = f"/tmp/{repo_name}_{random.randint(1000,9999)}"
            subprocess.run(["git", "clone", "--depth=1", repo_url, clone_dir], check=True, timeout=30)
            result = subprocess.run(["gitleaks", "detect", "--source", clone_dir, "--no-git", "--report-format", "json", "--exit-code", "0"], capture_output=True, text=True, timeout=120)
            shutil.rmtree(clone_dir, ignore_errors=True)
            if result.stdout.strip():
                findings = json.loads(result.stdout)
                if findings:
                    summary = f"🔑 *Gitleaks Found {len(findings)} secrets!*\n"
                    for f in findings[:5]:
                        file_path = f.get("File", "unknown")
                        rule = f.get("Description", "Unknown")
                        summary += f"• {rule} in `{file_path}`\n"
                    await update.message.reply_text(summary, parse_mode="Markdown")
                else:
                    await update.message.reply_text("✅ No secrets detected.")
            else:
                await update.message.reply_text("✅ No secrets detected.")
        except Exception as e:
            await update.message.reply_text(f"❌ Gitleaks scan failed: {e}")
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
            # Run Gitleaks
            result = subprocess.run(
                ["gitleaks", "detect", "--source", clone_dir, "--no-git", "--report-format", "json", "--exit-code", "0"],
                capture_output=True, text=True, timeout=120
            )
            shutil.rmtree(clone_dir, ignore_errors=True)
            if result.stdout.strip():
                findings = json.loads(result.stdout)
                if findings:
                    summary = f"🔑 *Gitleaks Found {len(findings)} secrets!*\n"
                    for f in findings[:5]:
                        file_path = f.get("File", "unknown")
                        rule = f.get("Description", "Unknown")
                        summary += f"• {rule} in `{file_path}`\n"
                    await update.message.reply_text(summary, parse_mode="Markdown")
                else:
                    await update.message.reply_text("✅ No secrets detected.")
            else:
                await update.message.reply_text("✅ No secrets detected.")
        except Exception as e:
            await update.message.reply_text(f"❌ Gitleaks scan failed: {e}")
        context.user_data.pop("state", None)
        return True

    return False

# ---------- scan domain handler ----------
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

    # Determine if this is a deep scan (enterprise users)
    c.execute("SELECT plan FROM clients WHERE username=?", (username,))
    row = c.fetchone()
    plan = row[0] if row else "free"
    context.user_data["plan"] = plan   # remember for later
    deep = (plan == "enterprise")

    try:
        results = await loop.run_in_executor(None, run_scan, domain, email, sync_progress, tools, deep)
    except Exception as e:
        traceback.print_exc()
        await update.message.reply_text(f"❌ Scan crashed: {e}")
        results = None
    try:
        await progress_msg.delete()
    except:
        pass
    if results:
        # Use the plan we saved before the scan (more reliable)
        plan = context.user_data.get("plan", "free")
        detailed = plan in ("monthly", "enterprise")

        print(f"[DEBUG] Building report for {domain}, detailed={detailed}")
        try:
            from bot.reports import build_report_markdown
            show_compliance = (context.user_data.get("scan_type") == "full")
            report_md = build_report_markdown(domain, results, detailed, deep, show_compliance)
            # Split long reports into chunks
            chunk_size = 3500
            for i in range(0, len(report_md), chunk_size):
                chunk = report_md[i:i+chunk_size]
                try:
                    await context.bot.send_message(chat_id=chat_id, text=chunk, parse_mode="Markdown")
                except:
                    await context.bot.send_message(chat_id=chat_id, text=chunk)
            print(f"[DEBUG] Report sent in {(len(report_md) // chunk_size) + 1} chunks")
        except Exception as e:
            import traceback
            traceback.print_exc()
            try:
                await context.bot.send_message(chat_id=chat_id, text="⚠️ Report generation failed. Please contact admin.")
            except:
                pass

        if plan == "free":
            c.execute("UPDATE clients SET scan_used=1 WHERE username=?", (username,))
            conn.commit()

        # Exploitation proof for enterprise
        if plan == "enterprise" and results.get("dalfox") and "vulnerable" in results["dalfox"].lower():
            from bot.exploit_proof import capture_xss_proof
            await capture_xss_proof(f"http://{domain}", "<script>alert('XSS')</script>", context, chat_id)
    else:
        await context.bot.send_message(chat_id=chat_id, text="❌ Scan failed.")

    context.user_data.pop("state", None)
    context.user_data.pop("scan_type", None)
    context.user_data.pop("tools", None)
    await update.message.reply_text("🔮 What's next?", reply_markup=main_menu(username == ADMIN_USERNAME))
    return True
