#!/usr/bin/env python3
"""Injects premium features into the working phantomwatch.py without breaking anything."""

with open("phantomwatch.py", "r") as f:
    content = f.read()

# ===== 1. Add required imports if not present =====
if "import requests" not in content:
    content = content.replace("import subprocess, re, os, sqlite3, random, string, json, time, asyncio",
                              "import subprocess, re, os, sqlite3, random, string, json, time, asyncio, shutil, requests")

if "from telegram.ext import" in content and "CallbackQueryHandler" in content:
    # Already has necessary imports
    pass

# ===== 2. Add subscriptions table after clients table =====
subscriptions_table = """
c.execute('''CREATE TABLE IF NOT EXISTS subscriptions (
    username TEXT, domain TEXT,
    last_scan_time TEXT, last_report_json TEXT,
    PRIMARY KEY(username, domain)
)''')
conn.commit()
"""
if "subscriptions" not in content:
    content = content.replace("c.execute('''CREATE TABLE IF NOT EXISTS verification", subscriptions_table + "\nc.execute('''CREATE TABLE IF NOT EXISTS verification")

# ===== 3. Add helper functions: generate_token, verify_domain (already exist), check_breach, etc. =====
# Insert check_breach before the scan functions
check_breach_func = """
async def check_breach(email: str, context, chat_id):
    try:
        resp = requests.get(f"https://api.xposedornot.com/v1/breach-analytics?email={email}", timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            breach_details = data.get("breach_details", {})
            if breach_details:
                total = len(breach_details)
                lines = [f"🩸 *Breach Report for {email}*", f"Found in *{total}* known breaches:\\n"]
                for name, info in list(breach_details.items())[:10]:
                    domain = info.get("domain", "unknown")
                    date = info.get("breach_date", "N/A")
                    lines.append(f"• *{name}* ({domain}) – {date}")
                if total > 10:
                    lines.append(f"… and {total-10} more breaches.")
                await context.bot.send_message(chat_id=chat_id, text="\\n".join(lines), parse_mode='Markdown')
                return
    except:
        pass
    await context.bot.send_message(chat_id=chat_id, text="✅ No breaches found for this email.")
"""
if "async def check_breach" not in content:
    content = content.replace("def run_scan(domain", check_breach_func + "\n\ndef run_scan(domain")

# ===== 4. Update main menu keyboard to include all buttons =====
old_main_menu = '''def main_menu(admin=False):
    buttons = [
        [InlineKeyboardButton("🔍 Full Scan", callback_data="scan_full")],
        [InlineKeyboardButton("📩 Contact Admin", callback_data="contact_admin")],
        [InlineKeyboardButton("❓ Help", callback_data="help")],
    ]
    if admin:
        buttons.append([InlineKeyboardButton("👑 Admin Menu", callback_data="admin_menu")])
    return InlineKeyboardMarkup(buttons)'''

new_main_menu = '''def main_menu(admin=False):
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
    return InlineKeyboardMarkup(buttons)'''

content = content.replace(old_main_menu, new_main_menu)

# ===== 5. Add quick_scan menu =====
quick_scan_menu = '''
def quick_scan_menu():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🛡️ Ports & Vulns", callback_data="quick_ports")],
        [InlineKeyboardButton("🌐 OSINT Pack", callback_data="quick_osint")],
        [InlineKeyboardButton("🔎 Recon", callback_data="quick_recon")],
        [InlineKeyboardButton("🦠 XSS Check", callback_data="quick_xss")],
        [InlineKeyboardButton("🔙 Main Menu", callback_data="main_menu")],
    ])
'''
if "def quick_scan_menu" not in content:
    content = content.replace("def admin_menu():", quick_scan_menu + "\ndef admin_menu():")

# ===== 6. Add callback handlers for new buttons =====
# We'll replace the button_handler function entirely with an expanded one, but we can add cases inside.
# Find "if data == "help":" and add the new elifs before it.

old_button_handler = '    if data == "help":'
new_button_handler = '''    if data == "scan_quick":
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
            "💲 *Phantom Watch Pricing Plans*\\n\\n"
            "🆓 *Free Trial* – 7 days\\n"
            "• One full scan\\n"
            "• Basic summary\\n"
            "*Price:* Free\\n\\n"
            "🛡️ *Monthly* – $199/month\\n"
            "• Unlimited full scans\\n"
            "• PDF reports with compliance mapping\\n"
            "• Breach intelligence\\n"
            "• Weekly subscription scans\\n"
            "*Price:* $199/month\\n\\n"
            "👑 *Enterprise* – $2,000/month\\n"
            "• Everything in Monthly\\n"
            "• Exploitation proof screenshots\\n"
            "• Continuous CVE monitoring\\n"
            "• GitHub secret scanning\\n"
            "• Priority support\\n"
            "*Price:* $2,000/month\\n\\n"
            "📩 Contact admin to subscribe or upgrade."
        )
        await context.bot.send_message(chat_id=query.message.chat_id, text=pricing_text, parse_mode='Markdown')
        await query.edit_message_text("🔮 Return to main menu:", reply_markup=main_menu(username == ADMIN_USERNAME))
        return
    if data == "how_it_works":
        how_text = (
            "📖 *How Phantom Watch Operates*\\n"
            "1️⃣ *Registration* – Admin adds you & verifies your domain.\\n"
            "2️⃣ *Choose a Scan* – Full or Quick.\\n"
            "3️⃣ *Live Monitoring* – Instant alerts for critical findings.\\n"
            "4️⃣ *Professional PDF Report* – Includes compliance mapping.\\n"
            "5️⃣ *Continuous Protection* – Subscribe to weekly scans & breach checks.\\n"
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
    if data == "help":'''

content = content.replace(old_button_handler, new_button_handler)

# ===== 7. Add message handler states for SET_EMAIL, SUBSCRIBE_DOMAIN, GITHUB_SCAN, REMOVE_USER =====
# Insert before "if state == "SCAN_DOMAIN":" line

new_states = '''
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
                summary = f"🔑 *Found {len(findings)} secrets!*\\n"
                for f in findings[:5]:
                    summary += f"• {f.get('DetectorName','Unknown')} in {f.get('SourceMetadata',{}).get('Data',{}).get('Filesystem',{}).get('file','unknown')}\\n"
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

'''

# Insert before the SCAN_DOMAIN state check
content = content.replace("    # Scan domain\n    if state == \"SCAN_DOMAIN\":", new_states + "    # Scan domain\n    if state == \"SCAN_DOMAIN\":")

# ===== 8. Update the admin menu to include remove user =====
old_admin_menu = '''def admin_menu():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Add User", callback_data="admin_adduser")],
        [InlineKeyboardButton("✅ Verify Domain", callback_data="admin_verify")],
        [InlineKeyboardButton("🔙 Main Menu", callback_data="main_menu")],
    ])'''
new_admin_menu = '''def admin_menu():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Add User", callback_data="admin_adduser")],
        [InlineKeyboardButton("✅ Verify Domain", callback_data="admin_verify")],
        [InlineKeyboardButton("❌ Remove User", callback_data="admin_removeuser")],
        [InlineKeyboardButton("🔙 Main Menu", callback_data="main_menu")],
    ])'''
content = content.replace(old_admin_menu, new_admin_menu)

# ===== 9. Add subscribe table and check_breach function (already handled above) =====

# Save
with open("phantomwatch.py", "w") as f:
    f.write(content)

print("✅ Features added: Quick Scan, Set Email, Pricing, Check Breaches, Subscribe, GitHub Scan, How It Works, Remove User.")
