# P1 URLs - v1.5.3 (Definitive Stable Edition)

<p align="center">
  <img src="https://img.shields.io/badge/Made%20with-Python-blue.svg" alt="Made with Python">
  <img src="https://img.shields.io/badge/Maintained%3F-yes-green.svg" alt="Maintained">
  <img src="https://img.shields.io/badge/Contributions-welcome-brightgreen.svg" alt="Contributions Welcome">
</p>

<p align="center">
  <i>An advanced, high-speed, and evasive automation framework for discovering high-impact web vulnerabilities.</i>
</p>

This tool is the culmination of an iterative development process, designed to chain together leading security tools with custom, intelligent vulnerability testing modules. It automates the entire workflow from discovery to real-time alerting, focusing on speed, accuracy, and stealth.

---

## 🚀 Key Features

- **Blazing Fast URL Discovery:** Uses **Katana** in a high-concurrency bulk mode to crawl thousands of domains in minutes, not hours.
- **Intelligent LFI Detection:** Employs a **Dynamic Differential Analysis** technique. Instead of simple string matching, it compares page content similarity to accurately detect LFI with a very low false-positive rate.
- **Evasive Blind SQLi Engine:**
  - **Dual-Vector Attack:** Tests both **URL Parameters** and **HTTP Headers** for SQLi.
  - **HTTP Parameter Pollution (HPP):** Automatically uses HPP to bypass common WAF and security filter rules when testing parameters.
  - **Randomized & Isolated Header Testing:** To evade detection, the script randomizes the order of HTTP methods and headers tested and injects payloads into only one header at a time, making requests appear more legitimate.
  - **Database-Specific Payloads:** Uses a massive, curated list of advanced, time-based payloads for MySQL, PostgreSQL, MSSQL, and Oracle.
- **Real-Time Slack Alerts:** Sends an **immediate, detailed notification to your Slack channel** the moment any vulnerability is confirmed, including LFI, SQLi, and all Nuclei findings.
- **Flexible Workflow:**
  - **Discovery Mode:** Provide a list of domains, and the script will discover and test all associated URLs.
  - **Direct Test Mode:** Use the `-u` flag to provide a pre-existing list of URLs, skipping the discovery phase entirely.
- **Customizable Payloads:** Comes with over 250 built-in, advanced LFI payloads, with an option to use your own custom payload file via the `-p` flag.
- **Professional Presentation:** Features a fully animated startup banner and clear, color-coded console output.
- **Organized Output:** Creates a unique, timestamped directory for each scan to store all logs and results, preventing data contamination between runs.

---

## 🛠️ Installation & Setup

This tool is designed to run on a Linux-based environment (like Kali, Ubuntu, or a VPS).

### Step 1: Install Python Dependencies

The script requires `rich` for formatted output and `requests` for web requests.

```bash
pip3 install rich requests


    Note: If you encounter an externally-managed-environment error, use the --user flag:
    pip3 install --user rich requests



### Step 2: Install Go-based Tools

Ensure you have the latest version of Go installed. Then, install the required tools:

      
# Web Crawler
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# URL Deduplicator
pipx install uro  # Recommended method
# Or via pip: pip3 install uro

# Pattern Matching Tool
go install -v github.com/tomnomnom/gf@latest

# Vulnerability Scanner
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest



Step 4: Clone and Configure This Script

    Clone the Repository:

          
    git clone [Your-GitHub-Repo-URL]
    cd P1-URLs



Make the Script Executable:

      
chmod +x P1-URLs.py



Configure Your Slack Webhook: This is the most important step. Open P1-URLs.py and replace the placeholder URL in the SLACK_WEBHOOK variable with your own.

      
# Find this line and replace the URL
SLACK_WEBHOOK = "https://hooks.slack.com/services/YOUR_WEBHOOK_URL_HERE"



    ⚙️ How to Use

The script offers a flexible workflow depending on your needs.
1. Standard Discovery Mode

This is the default mode. You provide a list of domains, and the script will discover and test them.

    Create a file (e.g., domains.txt) with your target root domains, one per line:

          
    https://example.com
    http://dev.example-two.com


Run the scan:

      
./P1-URLs.py -l domains.txt


Direct URL Testing Mode

Use this mode if you already have a comprehensive list of URLs and want to skip the discovery phase.

    Provide your URL list to the -l flag and add the -u flag.

          
    ./P1-URLs.py -l my_url_list.txt -u




Using Custom LFI Payloads

By default, the script uses a large, built-in list of LFI payloads. To use your own, use the -p flag.

      
# Use your custom payloads in either mode
./P1-URLs.py -l domains.txt -p /path/to/my_lfi_payloads.txt
./P1-URLs.py -l my_url_list.txt -u -p /path/to/my_lfi_payloads.txt

    


📁 Understanding the Output

All results for a scan are saved into a unique, timestamped directory (e.g., scan_results_domains_2023-10-27_15-30-00/) to keep your workspace clean.

    gf_results/: Contains text files of URLs sorted by potential vulnerability type (_lfi.txt, _sqli.txt, etc.).

    nuclei_results/: Contains the raw JSON output from all Nuclei scans.

    lfi_vulnerable.json: A log of all confirmed LFI vulnerabilities with full details.

    blind_sqli_vulnerable.json: A log of all confirmed Blind SQLi vulnerabilities with full details.

    nuclei_findings.json: A log of all vulnerabilities found by Nuclei.

Your primary results will arrive as real-time alerts in your configured Slack channel.
Credits and Inspiration

This tool stands on the shoulders of giants and was inspired by the methodologies of the broader security community.

    Authors: Vivek ( https://x.com/starkcharry )

    Core Toolchain: ProjectDiscovery (katana, nuclei), tomnomnom (gf), s0md3v (uro), and all their respective contributors.

    


        
    
