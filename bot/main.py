"""Phantom Watch entry point."""
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, CallbackQueryHandler, filters
from bot.handlers_client import (
    start_command, scan_full_handler, scan_quick_handler, quick_scan_subhandler,
    set_email_handler, pricing_handler, how_it_works_handler, check_breaches_handler,
    subscribe_handler, github_scan_handler, help_handler, contact_admin_handler,
    main_menu_handler, handle_client_message, handle_scan_domain,
)
from bot.handlers_admin import (
    admin_menu_handler, admin_adduser_handler, admin_verify_handler,
    admin_status_handler, admin_removeuser_handler, handle_admin_wizard,
)
import os, asyncio
from bot.config import BOT_TOKEN, ADMIN_USERNAME
from bot.menus import main_menu


# Route table
CALLBACK_ROUTES = {
    "main_menu": main_menu_handler,
    "scan_full": scan_full_handler,
    "scan_quick": scan_quick_handler,
    "set_email": set_email_handler,
    "pricing": pricing_handler,
    "how_it_works": how_it_works_handler,
    "check_breaches": check_breaches_handler,
    "subscribe": subscribe_handler,
    "github_scan": github_scan_handler,
    "help": help_handler,
    "contact_admin": contact_admin_handler,
    "admin_menu": admin_menu_handler,
    "admin_adduser": admin_adduser_handler,
    "admin_verify": admin_verify_handler,
    "admin_status": admin_status_handler,
    "admin_removeuser": admin_removeuser_handler,
}

async def button_router(update, context):
    data = update.callback_query.data
    if data.startswith("quick_"):
        await quick_scan_subhandler(update, context)
        return
    handler = CALLBACK_ROUTES.get(data)
    if handler:
        await handler(update, context)
async def message_router(update, context):
    username = update.message.from_user.username
    print(f"[DEBUG] message_router: username={update.message.from_user.username}, state={context.user_data.get("state")}")
    state = context.user_data.get("state")

    # Admin wizards
    if state in ("ADDUSER_USERNAME", "ADDUSER_PLAN", "ADDUSER_MONTHS",
                 "VERIFY_USERNAME", "VERIFY_DOMAIN", "REMOVE_USER"):
        handled = await handle_admin_wizard(update, context)
        if handled:
            return

    # Client states
    handled = await handle_client_message(update, context)
    if handled:
        return

    # Scan domain state
    if state == "SCAN_DOMAIN":
        try:
            handled = await handle_scan_domain(update, context)
        except Exception as e:
            print(f"[ERROR] handle_scan_domain crashed: {e}")
            import traceback
            traceback.print_exc()
            handled = False
        if handled:
            return

    # Fallback
    try:
        await update.message.reply_text(
            "I didn't understand. Use the buttons below.",
            reply_markup=main_menu(username == ADMIN_USERNAME)
        )
    except Exception as e:
        print(f"Fallback error: {e}")

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CallbackQueryHandler(button_router))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_router))
    print("👻 Phantom Watch is watching...")
    app.run_polling()

if __name__ == "__main__":
    main()
