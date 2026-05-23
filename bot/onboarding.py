"""Onboarding flow for new users."""
from bot.database import is_client, add_client, is_active, ADMIN_USERNAME
from bot.menus import main_menu

async def onboard_new_user(update, context):
    """Check if user is known; if not, send welcome and offer free trial."""
    username = update.message.from_user.username
    if not username:
        await update.message.reply_text("Please set a Telegram username to use Phantom Watch.")
        return False
    if is_client(username):
        # Existing client – show menu
        await update.message.reply_text(
            "Welcome back! Tap *🛡️ Menu* or use the buttons below.",
            reply_markup=main_menu(username == ADMIN_USERNAME),
            parse_mode="Markdown"
        )
        return True
    # New user – send onboarding message
    welcome = (
        "🔮 *Welcome to Phantom Watch!*\n"
        "Your automated cybersecurity reconnaissance platform.\n\n"
        "🆓 *Free Trial:* 7 days, one full scan.\n"
        "🛡️ *Monthly:* $199/month – unlimited scans, Detailed reports, compliance.\n"
        "👑 *Enterprise:* $2,000/month – all features, CVE monitoring, GitHub secrets.\n\n"
        "To get started, ask the admin to activate your trial. Contact: @{}\n"
        "Or tap the *📩 Contact Admin* button below."
    ).format(ADMIN_USERNAME)
    await update.message.reply_text(welcome, parse_mode="Markdown")
    # Also show main menu so they can explore
    await update.message.reply_text("⬇️ Main Menu:", reply_markup=main_menu(False))
    return True
