#!/usr/bin/env python3
import re

# 1. Add debug to scan_full_handler (confirm state is set)
with open("bot/handlers_client.py", "r") as f:
    content = f.read()

# Insert after "context.user_data["state"] = "SCAN_DOMAIN""
old_line = '    context.user_data["state"] = "SCAN_DOMAIN"'
new_line = '    context.user_data["state"] = "SCAN_DOMAIN"\n    print(f"[DEBUG] State set to SCAN_DOMAIN for {username}")'
content = content.replace(old_line, new_line)

# Insert debug at start of handle_scan_domain
old_func = 'async def handle_scan_domain(update, context):'
new_func = 'async def handle_scan_domain(update, context):\n    print(f"[DEBUG] handle_scan_domain called with state={context.user_data.get(\'state\')}")'
content = content.replace(old_func, new_func)

with open("bot/handlers_client.py", "w") as f:
    f.write(content)

# 2. Add debug to message_router (already done, but ensure it's there)
with open("bot/main.py", "r") as f:
    main_content = f.read()

# Ensure the debug line exists right after the state assignment
if 'print(f"[DEBUG] message_router: username={update.message.from_user.username}, state={context.user_data.get(\"state\")}")' not in main_content:
    main_content = main_content.replace(
        '    state = context.user_data.get("state")',
        '    state = context.user_data.get("state")\n    print(f"[DEBUG] message_router: username={username}, state={state}")'
    )

# Add a try/except around the handle_scan_domain call to catch silent errors
old_scan_call = '        handled = await handle_scan_domain(update, context)'
new_scan_call = '''        try:
            handled = await handle_scan_domain(update, context)
        except Exception as e:
            print(f"[ERROR] handle_scan_domain crashed: {e}")
            import traceback
            traceback.print_exc()
            handled = False'''
main_content = main_content.replace(old_scan_call, new_scan_call)

with open("bot/main.py", "w") as f:
    f.write(main_content)

print("✅ Debug prints added. Push and run a scan, then check Actions log.")
