"""Payment helpers – crypto addresses & pricing."""
from bot.database import c, conn
import json

def get_crypto_addresses():
    c.execute("SELECT value FROM settings WHERE key='crypto_addresses'")
    row = c.fetchone()
    if row:
        return json.loads(row[0])
    return {"BTC":"","ETH":"","USDT":""}

def set_crypto_addresses(addresses):
    c.execute("UPDATE settings SET value=? WHERE key='crypto_addresses'", (json.dumps(addresses),))
    conn.commit()

def get_plan_prices():
    c.execute("SELECT value FROM settings WHERE key='plan_prices'")
    row = c.fetchone()
    if row:
        return json.loads(row[0])
    return {"monthly":"$199","enterprise":"$2,000"}

def set_plan_prices(prices):
    c.execute("UPDATE settings SET value=? WHERE key='plan_prices'", (json.dumps(prices),))
    conn.commit()
