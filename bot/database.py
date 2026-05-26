"""Database helpers – Turso with automatic retry for every operation."""
import os, sqlite3, time
from datetime import datetime, timedelta

DB_URL = os.getenv("TURSO_DB_URL")
AUTH_TOKEN = os.getenv("TURSO_AUTH_TOKEN")

# Connect
if DB_URL and AUTH_TOKEN:
    try:
        import libsql_experimental
        _real_conn = libsql_experimental.connect(DB_URL, auth_token=AUTH_TOKEN)
    except Exception:
        _real_conn = sqlite3.connect("phantom_clients.db")
else:
    _real_conn = sqlite3.connect("phantom_clients.db")

_real_c = _real_conn.cursor()

# ---------- Automatic retry wrappers ----------
def _retry_execute(query, params=None, retries=3, delay=1.0):
    last_exc = None
    for attempt in range(retries):
        try:
            if params:
                return _real_c.execute(query, params)
            else:
                return _real_c.execute(query)
        except Exception as e:
            last_exc = e
            if attempt < retries - 1:
                time.sleep(delay * (2 ** attempt))
    raise last_exc

def _retry_commit(retries=3, delay=1.0):
    last_exc = None
    for attempt in range(retries):
        try:
            _real_conn.commit()
            return
        except Exception as e:
            last_exc = e
            if attempt < retries - 1:
                time.sleep(delay * (2 ** attempt))
    raise last_exc

# Replace the global c and conn so that every module automatically retries
class RetryCursor:
    def execute(self, query, params=None):
        return _retry_execute(query, params)
    def fetchone(self):
        return _real_c.fetchone()
    def fetchall(self):
        return _real_c.fetchall()
    def __getattr__(self, name):
        return getattr(_real_c, name)

class RetryConnection:
    def commit(self):
        _retry_commit()
    def __getattr__(self, name):
        return getattr(_real_conn, name)

c = RetryCursor()
conn = RetryConnection()

# ---------- Table creation ----------
_retry_execute("""CREATE TABLE IF NOT EXISTS clients (
    username TEXT PRIMARY KEY,
    plan TEXT DEFAULT 'free',
    expiry TEXT,
    email_collect TEXT DEFAULT '',
    scan_used INTEGER DEFAULT 0
)""")
_retry_execute("""CREATE TABLE IF NOT EXISTS verification (
    username TEXT, domain TEXT, token TEXT,
    PRIMARY KEY(username, domain)
)""")
_retry_execute("""CREATE TABLE IF NOT EXISTS subscriptions (
    username TEXT, domain TEXT,
    last_scan_time TEXT, last_report_json TEXT,
    PRIMARY KEY(username, domain)
)""")
_retry_execute("""CREATE TABLE IF NOT EXISTS client_tech (
    username TEXT, domain TEXT, tech TEXT,
    last_check TEXT,
    PRIMARY KEY(username, domain, tech)
)""")
_retry_execute("""CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT, domain TEXT, timestamp TEXT,
    report TEXT, finished INTEGER DEFAULT 0
)""")
_retry_execute("""CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
)""")
_retry_execute("INSERT OR IGNORE INTO settings VALUES ('crypto_addresses', '{\"BTC\":\"\",\"ETH\":\"\",\"USDT\":\"\"}')")
_retry_execute("INSERT OR IGNORE INTO settings VALUES ('plan_prices', '{\"monthly\":\"$199\",\"enterprise\":\"$2,000\"}')")
_retry_commit()

def is_client(username: str) -> bool:
    row = c.execute("SELECT 1 FROM clients WHERE username=?", (username,))
    return row.fetchone() is not None

def is_active(username: str) -> bool:
    row = c.execute("SELECT plan, expiry, scan_used FROM clients WHERE username=?", (username,)).fetchone()
    if not row:
        return False
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
