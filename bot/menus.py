"""All InlineKeyboard menus for Phantom Watch."""
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton, ReplyKeyboardMarkup

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
        [InlineKeyboardButton("💎 Upgrade", callback_data="upgrade")],
        [InlineKeyboardButton("🎁 What You Get", callback_data="whatyouget")],
    ]
    if admin:
        buttons.append([InlineKeyboardButton("👑 Admin Menu", callback_data="admin_menu")])
    return InlineKeyboardMarkup(buttons)

def admin_menu():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Add User", callback_data="admin_adduser"),
         InlineKeyboardButton("✅ Verify Domain", callback_data="admin_verify")],
        [InlineKeyboardButton("💲 Update Prices", callback_data="admin_update_prices"),
         InlineKeyboardButton("💰 Update Addresses", callback_data="admin_update_addresses")],
        [InlineKeyboardButton("📊 Status", callback_data="admin_status"),
         InlineKeyboardButton("❌ Remove User", callback_data="admin_removeuser")],
        [InlineKeyboardButton("🔙 Main Menu", callback_data="main_menu")],
    ])

def quick_scan_menu():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🛡️ Ports & Vulns", callback_data="quick_ports"),
         InlineKeyboardButton("🌐 OSINT & Social", callback_data="quick_osint")],
        [InlineKeyboardButton("🔎 Web Recon", callback_data="quick_recon"),
         InlineKeyboardButton("🦠 Vuln Validation", callback_data="quick_vulnvalidation")],
        [InlineKeyboardButton("📡 Subdomain Discovery", callback_data="quick_subfinder_massdns")],
        [InlineKeyboardButton("🕵️ Deep Investigation", callback_data="quick_deepinvestigation")],
        [InlineKeyboardButton("🔙 Main Menu", callback_data="main_menu")],
    ])
