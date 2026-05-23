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
from bot.config import BOT_TOKEN, ADMIN_USERNAME
from bot.menus import main_menu
import asyncio
import traceback

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
        try:
            await handler(update, context)
        except Exception as e:
            print(f"[ERROR] Callback {data} crashed: {e}")
            traceback.print_exc()

async def message_router(update, context):
    username = update.message.from_user.username
    text = update.message.text.strip()
    state = context.user_data.get("state")
    print(f"[DEBUG] msg_router: username={username}, state={state}, text={text[:50]}")

    # Admin wizards
    if state in ("ADDUSER_USERNAME", "ADDUSER_PLAN", "ADDUSER_MONTHS",
                 "VERIFY_USERNAME", "VERIFY_DOMAIN", "REMOVE_USER"):
        try:
            handled = await handle_admin_wizard(update, context)
            if handled:
                return
        except Exception as e:
            print(f"[ERROR] Admin wizard crashed: {e}")
            traceback.print_exc()
            return

    # Client states
    try:
        handled = await handle_client_message(update, context)
        if handled:
            return
    except Exception as e:
        print(f"[ERROR] Client message crashed: {e}")
        traceback.print_exc()
        return

    # Scan domain state
    if state == "SCAN_DOMAIN":
        print(f"[DEBUG] Forwarding to handle_scan_domain")
        try:
            handled = await handle_scan_domain(update, context)
            if handled:
                return
        except Exception as e:
            print(f"[ERROR] handle_scan_domain crashed: {e}")
            traceback.print_exc()
            try:
                await update.message.reply_text("❌ Scan encountered an internal error.")
            except:
                pass
            context.user_data.pop("state", None)
            return

    # Fallback
    try:
        await update.message.reply_text(
            "I didn't understand. Use the buttons below.",
            reply_markup=main_menu(username == ADMIN_USERNAME)
        )
    except Exception as e:
        print(f"Fallback error: {e}")

async def background_tasks(app):
    """Start subscription checks and CVE monitor."""
    while True:
        try:
            from bot.scheduler import check_subscriptions, cve_monitor
            await check_subscriptions(app.bot)
            await cve_monitor(app.bot, ADMIN_USERNAME)
        except Exception as e:
            print(f"Background task error: {e}")
        await asyncio.sleep(3600)  # run every hour

import subprocess, time

async def auto_save_db():
    """Commit and push phantom_clients.db to the 'db' branch every 5 minutes."""
    while True:
        await asyncio.sleep(300)  # 5 minutes
        try:
            # Only push if the file has changed
            subprocess.run(["git", "add", "phantom_clients.db"], check=False)
            result = subprocess.run(["git", "diff", "--staged", "--quiet"], check=False)
            if result.returncode != 0:  # there are changes
                subprocess.run(["git", "commit", "-m", "auto-save database"], check=False)
                subprocess.run(["git", "push", "origin", "db"], check=False)
                print("[DB] Auto‑saved database to db branch.")
        except Exception as e:
            print(f"[DB] Auto‑save failed: {e}")

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CallbackQueryHandler(button_router))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_router))

    # Start background tasks
    loop = asyncio.get_event_loop()
    loop.create_task(background_tasks(app))
    loop = asyncio.get_event_loop()
    loop.create_task(auto_save_db())

    print("👻 Phantom Watch is watching...")
    app.run_polling()

if __name__ == "__main__":
    main()
