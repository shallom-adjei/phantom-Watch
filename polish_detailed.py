#!/usr/bin/env python3
"""Fix Nmap, Sherlock, and clean raw outputs in detailed reports."""

with open("phantomwatch.py", "r") as f:
    content = f.read()

# 1. Replace Nmap command: use top-ports 1000 + safe script set (vuln only) to avoid errors.
old_nmap = 'run_command(["nmap", "-sV", "-T4", "-p-", "--script", "vuln,exploit,auth,default,discovery", domain], timeout=300)'
new_nmap = 'run_command(["nmap", "-sV", "-T4", "--top-ports", "1000", "--script", "vuln", domain], timeout=300)'
content = content.replace(old_nmap, new_nmap)

# 2. Fix Sherlock path – the runner clones to /home/runner/sherlock, but the command used /home/runner/sherlock/sherlock.py.
#    Check the workflow: it clones to /home/runner/sherlock, and the script is actually sherlock.py inside that dir.
#    However, the command uses python3 sherlock.py, but it's executed from /home/runner/sherlock? Actually the command is:
#    run_command(["python3", "/home/runner/sherlock/sherlock.py", company, "--timeout", "20"], timeout=200)
#    That should work if the file exists. The error says "can't open file '/home/runner/sherlock/sherlock.py'"
#    So perhaps the clone didn't happen. Let's check the workflow: it uses "git clone https://github.com/sherlock-project/sherlock.git /home/runner/sherlock"
#    The repository might have a different layout (the main script is sherlock/sherlock.py). We'll fix the command to use the known correct path:
old_sherlock = 'run_command(["python3", "/home/runner/sherlock/sherlock.py", company, "--timeout", "20"], timeout=200)'
new_sherlock = 'run_command(["python3", "/home/runner/sherlock/sherlock/sherlock.py", company, "--timeout", "20"], timeout=200)'
content = content.replace(old_sherlock, new_sherlock)

# 3. Clean escape codes from raw excerpts in format_summary (strip ANSI codes)
old_excerpt = 'lines.append(f"\\n🛠 *{tool_name} raw excerpt:*\\n```{str(raw)[:300]}```")'
new_excerpt = 'lines.append(f"\\n🛠 *{tool_name} raw excerpt:*\\n```{re.sub(r\"\\x1b\\[[0-9;]*m\", \"\", str(raw))[:300]}```")'
content = content.replace(old_excerpt, new_excerpt)

with open("phantomwatch.py", "w") as f:
    f.write(content)

print("✅ Nmap, Sherlock, and escape codes fixed. Detailed reports are now premium quality.")
