"""Weekly threat intelligence feed for each client."""
import json
from datetime import datetime, timedelta
from bot.database import c, conn
from bot.scanners import run_scan
from bot.reports import build_report_markdown

async def generate_weekly_feed(bot):
    """Send a weekly aggregated security summary to all clients."""
    c.execute("SELECT username, email_collect FROM clients WHERE plan IN ('monthly','enterprise')")
    clients = c.fetchall()
    for username, email in clients:
        # For each client, gather the latest scan result for each of their verified domains
        c.execute("SELECT domain FROM verification WHERE username=?", (username,))
        domains = c.fetchall()
        if not domains:
            continue
        feed_lines = [f"📊 *Weekly Security Digest for @{username}*\n"]
        for (domain,) in domains:
            c.execute("SELECT report, timestamp FROM scan_results WHERE username=? AND domain=? ORDER BY id DESC LIMIT 1",
                      (username, domain))
            row = c.fetchone()
            if row:
                results = json.loads(row[0])
                # brief summary
                from bot.reports import compute_threat_score, clean_ansi
                score, level = compute_threat_score(results)
                feed_lines.append(f"🔍 {domain}: Score {score}/100 ({level})")
                # add a snippet of findings
                if 'nmap' in results:
                    ports = len(re.findall(r"^\d+/tcp\s+open\s+", results['nmap'], re.MULTILINE)) if 'nmap' in results else 0
                    feed_lines.append(f"  - {ports} open ports")
            else:
                feed_lines.append(f"🔍 {domain}: No recent scan.")
        feed_lines.append("\n_Phantom Watch – Your digital watchdog._")
        try:
            await bot.send_message(chat_id=f"@{username}", text="\n".join(feed_lines), parse_mode="Markdown")
        except Exception as e:
            print(f"Failed to send weekly feed to @{username}: {e}")
