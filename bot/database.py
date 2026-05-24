"""Database helpers – uses Turso cloud DB for persistence."""
import os
import sqlite3
import threading
db_lock = threading.Lock()
from datetime import datetime, timedelta

DB_URL = os.getenv("TURSO_DB_URL")
AUTH_TOKEN = os.getenv("TURSO_AUTH_TOKEN")

if DB_URL and AUTH_TOKEN:
    import libsql_experimental
    conn = libsql_experimental.connect(DB_URL, auth_token=AUTH_TOKEN)
else:
    conn = sqlite3.connect("phantom_clients.db")

c = conn.cursor()

# Create tables if they don't exist
c.execute("""CREATE TABLE IF NOT EXISTS clients (
    username TEXT PRIMARY KEY,
    plan TEXT DEFAULT 'free',
    expiry TEXT,
    email_collect TEXT DEFAULT '',
    scan_used INTEGER DEFAULT 0
)""")
c.execute("""CREATE TABLE IF NOT EXISTS verification (
    username TEXT, domain TEXT, token TEXT,
    PRIMARY KEY(username, domain)
)""")
c.execute("""CREATE TABLE IF NOT EXISTS subscriptions (
    username TEXT, domain TEXT,
    last_scan_time TEXT, last_report_json TEXT,
    PRIMARY KEY(username, domain)
)""")
c.execute("""CREATE TABLE IF NOT EXISTS client_tech (
    username TEXT, domain TEXT, tech TEXT,
    last_check TEXT,
    PRIMARY KEY(username, domain, tech)
)""")
c.execute("""CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT, domain TEXT, timestamp TEXT,
    report TEXT, finished INTEGER DEFAULT 0
)""")
    with db_lock:
        conn.commit()
c.execute("""CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
)""")
# Insert defaults if not exist
c.execute("INSERT OR IGNORE INTO settings VALUES ('crypto_addresses', '{\"BTC\":\"\",\"ETH\":\"\",\"USDT\":\"\"}')")
c.execute("INSERT OR IGNORE INTO settings VALUES ('plan_prices', '{\"monthly\":\"$199\",\"enterprise\":\"$2,000\"}')")
    with db_lock:
        conn.commit()

def is_client(username: str) -> bool:
    c.execute("SELECT 1 FROM clients WHERE username=?", (username,))
    return c.fetchone() is not None

def is_active(username: str) -> bool:
    c.execute("SELECT plan, expiry, scan_used FROM clients WHERE username=?", (username,))
    row = c.fetchone()
    if not row:
        return False
    # Access columns by index (0=plan, 1=expiry, 2=scan_used)
    plan, expiry, scan_used = row[0], row[1], row[2]
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
    with db_lock:
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
