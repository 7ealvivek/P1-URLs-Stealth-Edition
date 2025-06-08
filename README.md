# P1 URLs - v1.8.0

<p align="center">
  <img src="https://img.shields.io/badge/Made%20with-Python-blue.svg" alt="Made with Python">
  <img src="https://img.shields.io/badge/Version-1.8.0-brightgreen.svg" alt="Version">
  <img src="https://img.shields.io/badge/Maintained%3F-yes-green.svg" alt="Maintained">
  <a href="#"><img src="https://img.shields.io/badge/Contributions-welcome-brightgreen.svg" alt="Contributions Welcome"></a>
</p>

<p align="center">
  <i>An advanced, high-speed, and evasive automation framework for discovering high-impact web vulnerabilities.</i>
</p>

P1 URLs is the culmination of an iterative development process, designed to chain together leading security tools with custom, intelligent vulnerability testing modules. It automates the entire workflow from discovery to real-time alerting, focusing on speed, accuracy, and stealth.

---

## 🚀 Key Features

- **Blazing Fast URL Discovery:** Uses **Katana** in a high-concurrency bulk mode to crawl thousands of domains in minutes, not hours.
- **Intelligent LFI Detection:** Employs a **Dynamic Differential Analysis** technique, comparing page content similarity to accurately detect LFI with a very low false-positive rate.
- **Evasive Blind SQLi Engine:**
  - **Multi-Vector Attack:** Tests both **URL Parameters** and **HTTP Headers** for SQLi.
  - **Multi-Technique Approach:** Automatically uses **Standard Injection**, **HTTP Parameter Pollution (HPP)**, and **Out-of-Band (OOB)** techniques.
  - **Traceable OOB Payloads:** When using OOB, each payload is embedded with a unique ID that is logged on-screen and to a file, allowing for perfect attribution of any callbacks.
  - **Evasive Payloads:** Utilizes a massive, curated list of advanced, time-based and OOB payloads, prioritizing `XOR`-based and conditional logic to bypass WAFs.
  - **Randomized & Isolated Testing:** Evades detection by randomizing the order of methods and headers tested and injecting payloads into only one header at a time.
- **Real-Time, Dual-Channel Alerts:** Sends an **immediate, detailed notification to your terminal screen AND Slack** for every confirmed vulnerability, complete with verifiable curl commands.
- **Flexible Workflow & Payloads:**
  - Run in **Discovery Mode** or **Direct URL Testing Mode**.
  - Comes with a massive, curated list of built-in LFI & SQLi payloads.
  - Option to use your own custom LFI payload file.
- **Professional Presentation & Organization:**
  - Features a fully animated, custom startup banner.
  - Creates a unique, timestamped directory for each scan to store all logs, preventing data contamination.
 


### RUN OVER VPS FOR MOST ACCURATE RESULTS

---

## 🛠️ Installation & Setup

This tool is designed to run on a Linux-based environment (like Kali, Ubuntu, or a VPS).

First, install the required Python libraries. If you encounter an `externally-managed-environment` error, the `--user` flag is the recommended quick fix.
```bash
pip3 install rich requests
```


# Web Crawler
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# URL Deduplicator
pipx install uro

# Pattern Matching Tool
go install -v github.com/tomnomnom/gf@latest

# Vulnerability Scanner
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest


### ⚙️ Configuration & Usage Initial Configuration

Before running, you must configure the tool:

    Clone the Repository:

          
    git clone [Your-GitHub-Repo-URL-Here]
    cd P1-URLs


    Make the Script Executable:

      
chmod +x P1-URLs.py

    Configure Your Slack Webhook: This is critical for real-time alerts. Open P1-URLs.py and replace the placeholder URL in the SLACK_WEBHOOK variable with your own.

Running a Scan

Standard Discovery Mode (Find and test URLs from a list of domains)

      
``./P1-URLs.py -l domains.txt``


Direct URL Testing Mode (Test a pre-existing list of URLs)

      
``./P1-URLs.py -l my_url_list.txt -u``


Using Custom LFI Payloads
To use your own LFI payloads instead of the built-in list, use the -p flag.

      
``./P1-URLs.py -l domains.txt -p /path/to/my_lfi_payloads.txt``


### Enabling Out-of-Band (OOB) SQLi Testing
This is the most powerful feature for finding "super blind" SQLi. Provide your collaborator URL (e.g., from Interactsh) using the -c flag.

First, start your Interactsh client: interactsh-client
Then, run the scan with your unique OOB URL:

      
``./P1-URLs.py -l domains.txt -c your-unique-id.oast.online``


Monitor your Interactsh client for callbacks. If you receive an interaction, search for its unique ID in the oob_requests.log file to find the vulnerable target.
📁 Output

All results are saved into a unique, timestamped directory (e.g., scan_results_domains_2023-10-27_15-30-00/).

    gf_results/: Categorized URLs for manual review.

    nuclei_results/: Raw JSONL output from Nuclei scans.

    lfi_vulnerable.json: A log of confirmed LFI vulnerabilities.

    blind_sqli_vulnerable.json: A log of confirmed time-based Blind SQLi vulnerabilities.

    nuclei_findings.json: A log of all vulnerabilities found by Nuclei.

    oob_requests.log: A critical log mapping every unique OOB ID to the URL and payload that was sent.

### Credits

    Author: Vivek (@starkcharry on X | bugcrowd.com/realvivek)

    Core Toolchain: ProjectDiscovery (katana, nuclei), tomnomnom (gf), s0md3v (uro), and all their respective contributors.

    Inspiration for Header-Based SQLi: ifconfig-me/SQLi-Scanner
        
