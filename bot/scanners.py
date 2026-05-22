"""Scan engine."""
import subprocess, os, shutil

def run_command(cmd, timeout=150):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except:
        return "[!] Error"

def run_scan(domain, email="", progress_callback=None, tools=None):
    if tools is None:
        tools = ["nmap","nikto","whatweb","theHarvester","dnstwist","metagoofil","sherlock"]
    results = {}
    step_map = {"nmap":1,"nikto":2,"whatweb":3,"theHarvester":4,"dnstwist":5,"metagoofil":6,"sherlock":7}
    for tool in tools:
        step = step_map.get(tool,0)
        if progress_callback:
            progress_callback(f"⚡ [{step}/7] Running {tool}...")
        if tool == "nmap":
            results["nmap"] = run_command(["nmap","-sV","-T4","--top-ports","200",domain], timeout=180)
        elif tool == "nikto":
            results["nikto"] = run_command(["nikto","-h",domain,"-T","0123456789abcde","-maxtime","300s"], timeout=300)
        elif tool == "whatweb":
            results["whatweb"] = run_command(["whatweb",domain])
        elif tool == "theHarvester":
            if email:
                run_command(["theHarvester","-d",domain,"-b","google","-f",f"report_{domain}.html"])
                if os.path.exists(f"report_{domain}.html"):
                    with open(f"report_{domain}.html") as f: results["theHarvester"] = f.read()
                    os.remove(f"report_{domain}.html")
                else:
                    results["theHarvester"] = "No results"
            else:
                results["theHarvester"] = "No email"
        elif tool == "dnstwist":
            results["dnstwist"] = run_command(["dnstwist",domain], timeout=120)
        elif tool == "metagoofil":
            raw = run_command(["python3","/home/runner/metagoofil/metagoofil.py","-d",domain,"-t","pdf,doc,xls","-l","20","-n","10","-o",f"/tmp/meta_{domain}","-f",f"meta_{domain}.html"], timeout=300)
            meta_report = f"/tmp/meta_{domain}/meta_{domain}.html"
            if os.path.exists(meta_report):
                with open(meta_report) as f: results["metagoofil"] = f.read()
                shutil.rmtree(f"/tmp/meta_{domain}")
            else:
                results["metagoofil"] = "No metadata found"
        elif tool == "sherlock":
            company = domain.split(".")[0]
            results["sherlock"] = run_command(["sherlock",company,"--timeout","20"], timeout=200)
    return results
