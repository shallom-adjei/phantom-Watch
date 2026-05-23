"""Scan engine – full power, with Nuclei, Subfinder, and FFUF."""
import subprocess, os, shutil, concurrent.futures

# Small built‑in wordlist for directory fuzzing
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

def run_amass(domain, progress_callback=None):
    """Enumerate subdomains using Amass (active + passive)."""
    if progress_callback:
        progress_callback("🔍 Amass enumerating subdomains...")
    cmd = ["amass", "enum", "-d", domain, "-silent", "-timeout", "120"]
    res = run_command(cmd, timeout=180)
    if res['stdout'].strip():
        return res['stdout'].strip().split('\n')
    return []

def run_massdns(subs, progress_callback=None):
    """Verify live subdomains with MassDNS."""
    if not subs:
        return []
    if progress_callback:
        progress_callback("🔍 MassDNS verifying live subdomains...")
    # Write subs to file
    with open("/tmp/subs.txt", "w") as f:
        f.write("\n".join(subs))
    # Run MassDNS with a public resolver
    cmd = ["massdns", "-r", "/tmp/resolvers.txt", "-t", "A", "-o", "S", "/tmp/subs.txt"]
    # We need a resolvers file; download a trusted list
    # Use the resolvers file already downloaded in the workflow
    resolvers_path = "/tmp/resolvers.txt"
    cmd = ["massdns", "-r", resolvers_path, "-t", "A", "-o", "S", "/tmp/subs.txt"]
    res = run_command(cmd, timeout=60)
    # Parse output: only lines with an A record
    live = set()
    for line in res['stdout'].split('\n'):
        if line and " A " in line:
            sub = line.split(" A ")[0].rstrip('.')
            live.add(sub)
    return list(live)

def run_amass_massdns(domain, progress_callback=None):
    subs = run_amass(domain, progress_callback)
    if not subs:
        return []
    live = run_massdns(subs, progress_callback)
    return live

def run_gitleaks(repo_url, progress_callback=None):
    """Clone a GitHub repo and scan for secrets using Gitleaks."""
    if progress_callback:
        progress_callback("🔑 Gitleaks scanning for secrets...")
    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    clone_dir = f"/tmp/{repo_name}_{random.randint(1000,9999)}"
    subprocess.run(["git", "clone", "--depth=1", repo_url, clone_dir], check=True, timeout=30)
    cmd = ["gitleaks", "detect", "--source", clone_dir, "--no-git", "--report-format", "json", "--exit-code", "0"]
    res = run_command(cmd, timeout=120)
    shutil.rmtree(clone_dir, ignore_errors=True)
    # Parse JSON output
    try:
        findings = json.loads(res['stdout'])
        return findings
    except:
        return []

def run_ffuf(domain, progress_callback=None):
    """Fuzz for hidden directories using a built‑in wordlist."""
    if progress_callback:
        progress_callback("🌀 FFUF fuzzing for hidden paths...")
    # Write wordlist to a temp file
    wordlist_path = "/tmp/ffuf_wordlist.txt"
    with open(wordlist_path, "w") as f:
        f.write("\n".join(COMMON_PATHS))
    # Run ffuf
    cmd = [
        "ffuf", "-u", f"http://{domain}/FUZZ",
        "-w", wordlist_path,
        "-mc", "200,301,302,403",  # match these status codes
        "-of", "csv",              # output as CSV for easy parsing
        "-s"                       # silent mode
    ]
    res = run_command(cmd, timeout=120)
    # Parse CSV output: return list of found paths
    lines = res['stdout'].strip().split('\n')
    found = []
    for line in lines:
        if line and not line.startswith("FUZZ,"):  # skip header
            parts = line.split(',')
            if len(parts) >= 1:
                found.append(parts[0])
    return "\n".join(found) if found else ""

def run_scan(domain, email="", progress_callback=None, tools=None, deep=False):
    if tools is None:
        tools = ["nmap","nikto","whatweb","theHarvester","dnstwist","metagoofil","sherlock","dalfox","nuclei","subfinder","ffuf","amass"]

    results = {}

    # ----- Heavy tools (sequential) -----
    if "nmap" in tools:
        progress_callback("⚡ Nmap (full power)" if deep else "⚡ Nmap scanning...")
        if deep:
            cmd = ["nmap","-p-","-sV","-O","-T4","--script","vuln,exploit,auth,default,discovery",domain]
            timeout = 600
        else:
            cmd = ["nmap","-sV","-T4","--top-ports","200",domain]
            timeout = 180
        res = run_command(cmd, timeout)
        results['nmap'] = res['stdout']
        if res['failed']: print(f"[!] Nmap failed (code {res['returncode']})")

    if "nikto" in tools:
        progress_callback("🕵️ Nikto (exhaustive)" if deep else "🕵️ Nikto...")
        if deep:
            cmd = ["nikto","-h",domain,"-T","0123456789abcde","-maxtime","600s"]
            timeout = 600
        else:
            cmd = ["nikto","-h",domain,"-T","123bde","-maxtime","120s"]
            timeout = 300
        res = run_command(cmd, timeout)
        results['nikto'] = res['stdout']
        if res['failed']: print(f"[!] Nikto failed (code {res['returncode']})")

    if "metagoofil" in tools:
        progress_callback("📄 Metagoofil (extensive)" if deep else "📄 Metagoofil...")
        if deep:
            cmd = ["python3","/home/runner/metagoofil/metagoofil.py","-d",domain,"-t","pdf,doc,xls","-l","30","-n","15",
                   "-o",f"/tmp/meta_{domain}","-f",f"meta_{domain}.html"]
            timeout = 400
        else:
            cmd = ["python3","/home/runner/metagoofil/metagoofil.py","-d",domain,"-t","pdf,doc,xls","-l","10","-n","5",
                   "-o",f"/tmp/meta_{domain}","-f",f"meta_{domain}.html"]
            timeout = 300
        res = run_command(cmd, timeout)
        meta_report = f"/tmp/meta_{domain}/meta_{domain}.html"
        if os.path.exists(meta_report):
            with open(meta_report) as f: results['metagoofil'] = f.read()
            shutil.rmtree(f"/tmp/meta_{domain}")
        else:
            results['metagoofil'] = "No public documents with metadata found (normal for this target)."

    # ----- Light tools (parallel in deep mode, else sequential) -----
    light_tools = [t for t in tools if t in ("whatweb","theHarvester","dnstwist","sherlock","dalfox","nuclei","subfinder","ffuf")]

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
            elif tool == "amass":
                results['amass'] = "\n".join(run_amass_massdns(domain))

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

    return results
