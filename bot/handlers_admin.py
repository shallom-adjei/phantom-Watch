"""Admin button handlers and wizards."""
from bot.database import is_client, add_client, conn, c
from bot.config import ADMIN_USERNAME
from bot.menus import admin_menu, main_menu

async def admin_menu_handler(update, context):
    query = update.callback_query
    try:
        await query.answer()
    except:
        pass
    username = query.from_user.username
    if username != ADMIN_USERNAME:
        return
    try:
        await query.edit_message_text("👑 Admin Panel:", reply_markup=admin_menu())
    except Exception as e:
        if "Message is not modified" not in str(e):
            print(f"Edit error: {e}")

async def admin_adduser_handler(update, context):
    query = update.callback_query
    try:
        await query.answer()
    except:
        pass
    username = query.from_user.username
    if username != ADMIN_USERNAME:
        return
    try:
        await query.edit_message_text("Enter client username (with @):")
    except Exception as e:
        if "Message is not modified" not in str(e):
            print(f"Edit error: {e}")
    context.user_data["state"] = "ADDUSER_USERNAME"

async def admin_verify_handler(update, context):
    query = update.callback_query
    try:
        await query.answer()
    except:
        pass
    username = query.from_user.username
    if username != ADMIN_USERNAME:
        return
    try:
        await query.edit_message_text("Enter client username (with @):")
    except Exception as e:
        if "Message is not modified" not in str(e):
            print(f"Edit error: {e}")
    context.user_data["state"] = "VERIFY_USERNAME"

async def admin_status_handler(update, context):
    query = update.callback_query
    try:
        await query.answer()
    except:
        pass
    username = query.from_user.username
    if username != ADMIN_USERNAME:
        return
    c.execute("SELECT username, plan, expiry FROM clients")
    clients = c.fetchall()
    msg = "📊 Client List\n\n"
    for u, p, e in clients:
        msg += f"@{u} - {p}"
        if e:
            msg += f" (exp: {e})"
        msg += "\n"
    try:
        await query.edit_message_text(msg, reply_markup=admin_menu())
    except Exception as e:
        if "Message is not modified" not in str(e):
            print(f"Edit error: {e}")

async def admin_removeuser_handler(update, context):
    query = update.callback_query
    try:
        await query.answer()
    except:
        pass
    username = query.from_user.username
    if username != ADMIN_USERNAME:
        return
    try:
        await query.edit_message_text("Enter the username of the client to remove (with @):")
    except Exception as e:
        if "Message is not modified" not in str(e):
            print(f"Edit error: {e}")
    context.user_data["state"] = "REMOVE_USER"

async def admin_update_prices_handler(update, context):
    query = update.callback_query
    try: await query.answer()
    except: pass
    username = query.from_user.username
    if username != ADMIN_USERNAME: return
    await query.edit_message_text("Enter new prices in format: monthly=$199,enterprise=$2,000")
    context.user_data["state"] = "UPDATE_PRICES"

async def admin_update_addresses_handler(update, context):
    query = update.callback_query
    try: await query.answer()
    except: pass
    username = query.from_user.username
    if username != ADMIN_USERNAME: return
    await query.edit_message_text("Enter new crypto addresses in format: BTC=xxx,ETH=yyy,USDT=zzz")
    context.user_data["state"] = "UPDATE_ADDRESSES"


# Admin wizard message handlers
async def handle_admin_wizard(update, context):
    username = update.message.from_user.username
    text = update.message.text.strip()
    state = context.user_data.get("state")

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
        return True

    if state == "ADDUSER_PLAN":
        plan = text.lower()
        if plan not in ["free", "monthly", "enterprise"]:
            await update.message.reply_text("Invalid plan. Use free, monthly, or enterprise:")
            return True
        context.user_data["add_plan"] = plan
        await update.message.reply_text("How many months? (0 for free trial):")
        context.user_data["state"] = "ADDUSER_MONTHS"
        return True

    if state == "ADDUSER_MONTHS":
        try:
            months = int(text)
        except:
            await update.message.reply_text("Enter a number.")
            return True
        target = context.user_data["add_target"]
        plan = context.user_data["add_plan"]
        add_client(target, plan, months)
        await update.message.reply_text(f"✅ Added @{target} with {plan} plan.", reply_markup=admin_menu())
        for k in ("add_target", "add_plan", "state"):
            context.user_data.pop(k, None)
        return True

    if state == "VERIFY_USERNAME":
        if username != ADMIN_USERNAME:
            await update.message.reply_text("❌ Admin only.")
            return True
        target = text.lstrip("@")
        if not is_client(target):
            await update.message.reply_text("User not a client.")
            return True
        context.user_data["verify_target"] = target
        await update.message.reply_text("Domain to verify (e.g., example.com):")
        context.user_data["state"] = "VERIFY_DOMAIN"
        return True

    if state == "VERIFY_DOMAIN":
        target = context.user_data["verify_target"]
        domain = text.lower()
        c.execute("INSERT OR REPLACE INTO verification VALUES (?,?,?)", (target, domain, "admin_verified"))
        conn.commit()
        await update.message.reply_text(f"✅ Domain {domain} verified for @{target}.", reply_markup=admin_menu())
        context.user_data.pop("state", None)
        context.user_data.pop("verify_target", None)
        return True

    if state == "REMOVE_USER":
        if username != ADMIN_USERNAME:
            await update.message.reply_text("❌ Admin only.")
            return True
        target = text.lstrip("@")
        if not is_client(target):
            await update.message.reply_text("User is not a client.")
            return True
        c.execute("UPDATE clients SET expiry='2000-01-01' WHERE username=?", (target,))
        conn.commit()
        await update.message.reply_text(f"❌ User @{target} has been removed. They can no longer use the bot.", reply_markup=admin_menu())
        context.user_data.pop("state", None)
        return True

    if state == "UPDATE_PRICES":
        if username != ADMIN_USERNAME:
            await update.message.reply_text("❌ Admin only.")
            return True
        try:
            parts = dict(pair.split("=") for pair in text.split(","))
            from bot.payments import set_plan_prices
            set_plan_prices(parts)
            await update.message.reply_text("✅ Prices updated.", reply_markup=admin_menu())
        except Exception as e:
            await update.message.reply_text(f"❌ Invalid format. Error: {e}")
        context.user_data.pop("state", None)
        return True

    if state == "UPDATE_ADDRESSES":
        if username != ADMIN_USERNAME:
            await update.message.reply_text("❌ Admin only.")
            return True
        try:
            parts = dict(pair.split("=") for pair in text.split(","))
            from bot.payments import set_crypto_addresses
            set_crypto_addresses(parts)
            await update.message.reply_text("✅ Crypto addresses updated.", reply_markup=admin_menu())
        except Exception as e:
            await update.message.reply_text(f"❌ Invalid format. Error: {e}")
        context.user_data.pop("state", None)
        return True

    return False
