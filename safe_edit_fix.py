#!/usr/bin/env python3
with open("phantomwatch.py", "r") as f:
    content = f.read()

# Add the safe_edit helper function right before async def button_handler
safe_edit_func = '''
async def safe_edit(query, text, **kwargs):
    try:
        await query.edit_message_text(text, **kwargs)
    except Exception as e:
        if "Message is not modified" not in str(e):
            print(f"Edit error: {e}")
'''

# Insert safe_edit before button_handler
content = content.replace("async def button_handler(update, context):", safe_edit_func + "\nasync def button_handler(update, context):")

# Replace all `await query.edit_message_text(` with `await safe_edit(query,`
content = content.replace("await query.edit_message_text(", "await safe_edit(query, ")

with open("phantomwatch.py", "w") as f:
    f.write(content)

print("✅ Safe edit wrapper added – no more 'Message is not modified' crashes.")
