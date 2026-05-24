"""Scan engine – full power, with all elite tools (stable)."""
import subprocess, os, shutil, concurrent.futures, json, random

COMMON_PATHS = [
    "admin", "login", "wp-admin", "backup", "test", "dev", "staging",
    "api", "v1", "v2", "console", "dashboard", "config", ".git", ".env",
    "robots.txt", "sitemap.xml", "phpmyadmin", "db", "old", "new", "beta",
    "cron", "tmp", "private", "uploads", "downloads", "images", "js", "css",
    "includes", "vendor", "node_modules", "logs", "backup.zip", "backup.tar.gz",
]

def run_command(cmd, timeout=150):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"stdout": proc.stdout + proc.stderr, "returncode": proc.returncode, "failed": proc.returncode != 0}
    except subprocess.TimeoutExpired:
        return {"stdout": "[!] Command timed out.", "returncode": -1, "failed": True}
    except Exception as e:
        return {"stdout": f"[!] Error: {e}", "returncode": -1, "failed": True}

def run_nuclei(domain, progress_callback=None):
    if progress_callback:
        progress_callback("🧬 Nuclei scanning for vulnerabilities...")
    cmd = ["nuclei", "-u", f"http://{domain}", "-severity", "critical,high,medium", "-silent", "-jsonl"]
    res = run_command(cmd, timeout=300)
    return res['stdout']

def run_subfinder(domain, progress_callback=None):
    if progress_callback:
        progress_callback("🔍 Subfinder enumerating subdomains...")
    cmd = ["subfinder", "-d", domain, "-silent"]
    res = run_command(cmd, timeout=120)
    if res['stdout'].strip():
        return res['stdout'].strip().split('\n')
    return []

def run_ffuf(domain, progress_callback=None):
    if progress_callback:
        progress_callback("🌀 FFUF fuzzing for hidden paths...")
    wordlist_path = "/tmp/ffuf_wordlist.txt"
    with open(wordlist_path, "w") as f:
        f.write("\n".join(COMMON_PATHS))
    cmd = [
        "ffuf", "-u", f"http://{domain}/FUZZ",
        "-w", wordlist_path,
        "-mc", "200,301,302,403",
        "-of", "csv",
        "-s"
    ]
    res = run_command(cmd, timeout=120)
    lines = res['stdout'].strip().split('\n')
    found = []
    for line in lines:
        if line and not line.startswith("FUZZ,"):
            parts = line.split(',')
            if len(parts) >= 1:
                found.append(parts[0])
    return "\n".join(found) if found else ""

def run_subfinder_massdns(domain, progress_callback=None):
    """Passive subdomain discovery + live verification."""
    if progress_callback:
        progress_callback("🔍 Subfinder (passive) enumerating...")
    subfinder_cmd = ["subfinder", "-d", domain, "-silent"]
    sub_res = run_command(subfinder_cmd, timeout=60)
    if sub_res['stdout'].strip():
        subs = sub_res['stdout'].strip().split('\n')
    else:
        subs = [domain]
    with open("/tmp/subs.txt", "w") as f:
        f.write("\n".join(subs))
    massdns_cmd = [
        "massdns", "-r", "/tmp/resolvers.txt",
        "-t", "A", "-o", "S", "/tmp/subs.txt"
    ]
    mass_res = run_command(massdns_cmd, timeout=30)
    live = set()
    for line in mass_res['stdout'].split('\n'):
        if " A " in line:
            sub = line.split(" A ")[0].rstrip('.')
            live.add(sub)
    if live and progress_callback:
        progress_callback(f"✅ {len(live)} live subdomains verified.")
    return list(live) if live else []

def run_prowler(provider, credentials=None, progress_callback=None):
    if progress_callback:
        progress_callback(f"☁️ Prowler auditing {provider}...")
    cmd = ["prowler", provider, "--quiet", "--output", "json"]
    if credentials:
        cmd += ["--credentials-file", credentials]
    res = run_command(cmd, timeout=600)
    try:
        findings = json.loads(res['stdout'])
        return findings
    except:
        return {"error": "Failed to parse Prowler output", "raw": res['stdout'][:500]}

def run_spiderfoot(domain, progress_callback=None):
    if progress_callback:
        progress_callback("🕸️ SpiderFoot OSINT scan...")
    cmd = ["python3", "/opt/spiderfoot/sf.py", "-s", domain, "-q", "-o", "json"]
    res = run_command(cmd, timeout=600)
    try:
        data = json.loads(res['stdout'])
        return data
    except:
        return {"error": "SpiderFoot failed", "raw": res['stdout'][:300]}

def run_reconspider(target, progress_callback=None):
    if progress_callback:
        progress_callback("🕷️ ReconSpider deep dive...")
    cmd = ["python3", "/opt/reconspider/reconspider.py", target]
    res = run_command(cmd, timeout=300)
    return res['stdout']

def run_scan(domain, email="", progress_callback=None, tools=None, deep=False):
    if tools is None:
        base_tools = [
            "nmap","nikto","whatweb","theHarvester","dnstwist","metagoofil",
            "sherlock","dalfox","nuclei","subfinder","ffuf","subfinder_massdns"
        ]
        if deep:
            tools = base_tools + ["spiderfoot"]
        else:
            tools = base_tools

    results = {}

    # ----- Heavy tools (sequential) -----
    if "nmap" in tools:
        progress_callback("⚡ Nmap (full power)" if deep else "⚡ Nmap scanning...")
        cmd = ["nmap","-p-","-sV","-O","-T4","--script","vuln,exploit,auth,default,discovery",domain] if deep else \
              ["nmap","-sV","-T4","--top-ports","200",domain]
        res = run_command(cmd, timeout=600 if deep else 180)
        results['nmap'] = res['stdout']
        if res['failed']: print(f"[!] Nmap failed (code {res['returncode']})")

    if "nikto" in tools:
        progress_callback("🕵️ Nikto (exhaustive)" if deep else "🕵️ Nikto...")
        cmd = ["nikto","-h",domain,"-T","0123456789abcde","-maxtime","600s"] if deep else \
              ["nikto","-h",domain,"-T","123bde","-maxtime","120s"]
        res = run_command(cmd, timeout=600 if deep else 300)
        results['nikto'] = res['stdout']
        if res['failed']: print(f"[!] Nikto failed (code {res['returncode']})")

    if "metagoofil" in tools:
        progress_callback("📄 Metagoofil (extensive)" if deep else "📄 Metagoofil...")
        cmd = ["python3","/home/runner/metagoofil/metagoofil.py","-d",domain,"-t","pdf,doc,xls","-l","30","-n","15",
               "-o",f"/tmp/meta_{domain}","-f",f"meta_{domain}.html"] if deep else \
              ["python3","/home/runner/metagoofil/metagoofil.py","-d",domain,"-t","pdf,doc,xls","-l","10","-n","5",
               "-o",f"/tmp/meta_{domain}","-f",f"meta_{domain}.html"]
        res = run_command(cmd, timeout=400 if deep else 300)
        meta_report = f"/tmp/meta_{domain}/meta_{domain}.html"
        if os.path.exists(meta_report):
            with open(meta_report) as f: results['metagoofil'] = f.read()
            shutil.rmtree(f"/tmp/meta_{domain}")
        else:
            results['metagoofil'] = "No public documents with metadata found (normal for this target)."

    # ----- Light tools (parallel in deep mode, else sequential) -----
    light_tools = [t for t in tools if t in (
        "whatweb","theHarvester","dnstwist","sherlock","dalfox",
        "nuclei","subfinder","ffuf","subfinder_massdns","spiderfoot","reconspider"
    )]

    if deep and light_tools:
        progress_callback(f"⚡ Running {len(light_tools)} light tools in parallel...")
        def run_light(tool):
            if tool == "whatweb": return ("whatweb", run_command(["whatweb",domain], timeout=60)['stdout'])
            elif tool == "theHarvester":
                if email:
                    cmd = ["theHarvester","-d",domain,"-b","google","-f",f"report_{domain}.html"]
                    res = run_command(cmd, timeout=120)
                    if os.path.exists(f"report_{domain}.html"):
                        with open(f"report_{domain}.html") as f: out = f.read()
                        os.remove(f"report_{domain}.html")
                    else: out = "No email results."
                else: out = "No email provided for OSINT."
                return ("theHarvester", out)
            elif tool == "dnstwist": return ("dnstwist", run_command(["dnstwist","--format","list",domain], timeout=90)['stdout'])
            elif tool == "sherlock":
                company = domain.split('.')[0]
                return ("sherlock", run_command(["sherlock",company,"--timeout","20"], timeout=200)['stdout'])
            elif tool == "dalfox":
                return ("dalfox", run_command(["dalfox","url",f"http://{domain}","--silence"], timeout=200)['stdout'])
            elif tool == "nuclei":
                return ("nuclei", run_nuclei(domain, progress_callback=None))
            elif tool == "subfinder":
                return ("subfinder", "\n".join(run_subfinder(domain)))
            elif tool == "ffuf":
                return ("ffuf", run_ffuf(domain))
            elif tool == "subfinder_massdns":
                return ("subfinder_massdns", "\n".join(run_subfinder_massdns(domain)))
            elif tool == "spiderfoot":
                return ("spiderfoot", run_spiderfoot(domain))
            elif tool == "reconspider":
                return ("reconspider", run_reconspider(domain))

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(run_light, t): t for t in light_tools}
            for future in concurrent.futures.as_completed(futures):
                try:
                    name, out = future.result()
                    results[name] = out
                except Exception as e:
                    results[futures[future]] = f"[!] Parallel error: {e}"
    else:
        for tool in light_tools:
            progress_callback(f"⚡ Running {tool}...")
            if tool == "whatweb":
                results['whatweb'] = run_command(["whatweb",domain], timeout=60)['stdout']
            elif tool == "theHarvester":
                if email:
                    cmd = ["theHarvester","-d",domain,"-b","google","-f",f"report_{domain}.html"]
                    res = run_command(cmd, timeout=120)
                    if os.path.exists(f"report_{domain}.html"):
                        with open(f"report_{domain}.html") as f: results['theHarvester'] = f.read()
                        os.remove(f"report_{domain}.html")
                    else: results['theHarvester'] = "No email results."
                else: results['theHarvester'] = "No email provided for OSINT."
            elif tool == "dnstwist": results['dnstwist'] = run_command(["dnstwist","--format","list",domain], timeout=90)['stdout']
            elif tool == "sherlock":
                results['sherlock'] = run_command(["sherlock",domain.split('.')[0],"--timeout","20"], timeout=200)['stdout']
            elif tool == "dalfox":
                results['dalfox'] = run_command(["dalfox","url",f"http://{domain}","--silence"], timeout=200)['stdout']
            elif tool == "nuclei":
                results['nuclei'] = run_nuclei(domain, progress_callback=None)
            elif tool == "subfinder":
                subs = run_subfinder(domain)
                results['subfinder'] = "\n".join(subs)
            elif tool == "ffuf":
                results['ffuf'] = run_ffuf(domain)
            elif tool == "subfinder_massdns":
                results['subfinder_massdns'] = "\n".join(run_subfinder_massdns(domain))
            elif tool == "spiderfoot":
                results['spiderfoot'] = run_spiderfoot(domain)
            elif tool == "reconspider":
                results['reconspider'] = run_reconspider(domain)

    return results
