"""Background tasks: weekly subscription scans and hourly CVE monitoring."""
import asyncio
import json
import re
import requests
from datetime import datetime, timedelta
from bot.database import conn, c
from bot.scanners import run_scan
from bot.reports import build_report_markdown

async def check_subscriptions(bot):
    """Run every hour: scan domains that haven't been scanned in 7 days."""
    c.execute("SELECT username, domain, last_scan_time, last_report_json FROM subscriptions")
    subs = c.fetchall()
    for username, domain, last_time, last_json in subs:
        last_dt = datetime.fromisoformat(last_time) if last_time else datetime.min
        if (datetime.now() - last_dt).days >= 7:
            # Get client email (if set)
            c.execute("SELECT email_collect FROM clients WHERE username=?", (username,))
            row = c.fetchone()
            email = row[0] if row else ""
            # Perform full scan
            results = run_scan(domain, email=email, tools=None)
            # Build diff report if previous results exist
            detailed = True  # always send detailed for subscribed users
            if last_json and last_json != "{}":
                prev_results = json.loads(last_json)
                # Build diff: only new findings (simplified: compare keys and counts)
                # We'll use build_report_markdown but with a previous flag – we can just send the new report and mention last scan time.
                # For simplicity, we'll send the full report with a note.
            report = build_report_markdown(domain, results, detailed=detailed)
            try:
                await bot.send_message(chat_id=f"@{username}", text=report, parse_mode="Markdown")
            except Exception as e:
                print(f"Failed to send subscription report to @{username}: {e}")
            # Update subscription record
            c.execute("UPDATE subscriptions SET last_scan_time=?, last_report_json=? WHERE username=? AND domain=?",
                      (datetime.now().isoformat(), json.dumps(results), username, domain))
            conn.commit()

async def cve_monitor(bot, ADMIN_USERNAME):
    """Run every hour: check NVD for new CVEs matching client technologies."""
    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=" +
            (datetime.utcnow() - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000") +
            "&resultsPerPage=50", timeout=30)
        if resp.status_code == 200:
            cves = resp.json().get("vulnerabilities", [])
            c.execute("SELECT username, domain, tech FROM client_tech")
            rows = c.fetchall()
            for username, domain, tech in rows:
                for vuln in cves:
                    desc = vuln.get("cve", {}).get("descriptions", [{}])[0].get("value", "")
                    if tech.lower() in desc.lower():
                        cve_id = vuln["cve"]["id"]
                        alert = f"🚨 *Zero‑day alert for {domain}*\nCVE-{cve_id} affects {tech}\nPatch immediately!"
                        try:
                            await bot.send_message(chat_id=f"@{username}", text=alert, parse_mode="Markdown")
                        except:
                            pass
    except Exception as e:
        print(f"CVE monitor error: {e}")
