"""Database helpers."""
import sqlite3
from datetime import datetime, timedelta

DB_FILE = "phantom_clients.db"
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
c = conn.cursor()

def is_client(username: str) -> bool:
    c.execute("SELECT 1 FROM clients WHERE username=?", (username,))
    return c.fetchone() is not None

def is_active(username: str) -> bool:
    c.execute("SELECT plan, expiry, scan_used FROM clients WHERE username=?", (username,))
    row = c.fetchone()
    if not row:
        return False
    plan, expiry, scan_used = row
    if plan == "free":
        if scan_used:
            return False
        if expiry and expiry < datetime.now().strftime("%Y-%m-%d"):
            return False
        return True
    if expiry and expiry < datetime.now().strftime("%Y-%m-%d"):
        return False
    return True

def add_client(username: str, plan: str = "free", months: int = 0):
    expiry = ""
    if plan == "free":
        expiry = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d")
    elif months > 0:
        expiry = (datetime.now() + timedelta(days=30 * months)).strftime("%Y-%m-%d")
    c.execute("INSERT OR REPLACE INTO clients VALUES (?,?,?,?,?)", (username, plan, expiry, "", 0))
    conn.commit()

def generate_token() -> str:
    import random, string
    return "".join(random.choices(string.ascii_letters + string.digits, k=20))

def verify_domain(domain: str, token: str) -> bool:
    import subprocess
    try:
        r = subprocess.run(
            ["curl", "-s", "-m", "15", f"http://{domain}/verify.txt"],
            capture_output=True, text=True,
        )
        return r.stdout.strip() == token
    except:
        return False
