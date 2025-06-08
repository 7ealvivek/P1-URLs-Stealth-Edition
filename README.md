# P1 URLs - v1.6.3 (Definitive Edition)

<p align="center">
  <a href="https://www.python.org" target="_blank"><img src="https://img.shields.io/badge/Made%20with-Python-blue.svg" alt="Made with Python"></a>
  <a href="#" target="_blank"><img src="https://img.shields.io/badge/Version-1.6.3-brightgreen.svg" alt="Version"></a>
  <a href="#" target="_blank"><img src="https://img.shields.io/badge/Maintained%3F-yes-green.svg" alt="Maintained"></a>
  <a href="#" target="_blank"><img src="https://img.shields.io/badge/Contributions-welcome-brightgreen.svg" alt="Contributions Welcome"></a>
</p>

<p align="center">
  <i>An advanced, high-speed, and evasive automation framework for discovering high-impact web vulnerabilities.</i>
</p>

This tool is the culmination of an iterative development process, designed to chain together leading security tools with custom, intelligent vulnerability testing modules. It automates the entire workflow from discovery to real-time alerting, focusing on speed, accuracy, and stealth.

---

## 🚀 Key Features

-   **Blazing Fast URL Discovery:** Uses **Katana** in a high-concurrency bulk mode to crawl thousands of domains in minutes, not hours.
-   **Intelligent LFI Detection:** Employs a **Dynamic Differential Analysis** technique. Instead of simple string matching, it compares page content similarity to accurately detect LFI with a very low false-positive rate.
-   **Evasive Blind SQLi Engine:**
    -   **Multi-Vector Attack:** Tests both **URL Parameters** and **HTTP Headers** for SQLi.
    -   **Multi-Technique Approach:** Automatically uses **Standard Injection**, **HTTP Parameter Pollution (HPP)**, and **Out-of-Band (OOB)** techniques.
    -   **Traceable OOB Payloads:** When using OOB, each payload is embedded with a unique ID that is logged and sent to Slack, allowing you to instantly attribute any callbacks to the exact vulnerable URL and injection point.
    -   **Evasive Payloads:** Utilizes a massive, curated list of advanced, time-based and OOB payloads, prioritizing `XOR`-based and conditional logic to bypass WAFs.
    -   **Randomized & Isolated Testing:** Evades detection by randomizing the order of methods and headers tested and injecting payloads into only one header at a time.
-   **Real-Time Slack Alerts:** Sends an **immediate, detailed notification to your Slack channel** for every vulnerability or OOB attempt, complete with severity, payloads, and injection details.
-   **Flexible Workflow & Payloads:**
    -   Run in **Discovery Mode** (with `-l domains.txt`) or **Direct Test Mode** (with `-l urls.txt -u`).
    -   Use a large built-in LFI payload list or provide your own with the `-p` flag.
    -   Enable powerful OOB testing with the `-c` flag.
-   **Professional Presentation & Organization:**
    -   Features a fully animated, custom startup banner.
    -   Creates a unique, timestamped directory for each scan to store all logs (`lfi_vulnerable.json`, `blind_sqli_vulnerable.json`, `oob_requests.log`, etc.), preventing data contamination between runs.

---

## 🛠️ Installation & Setup

This tool is designed to run on a Linux-based environment (like Kali, Ubuntu, or a VPS).

### Step 1: Install Python Dependencies

```bash
pip3 install rich requests
```


Step 2: Install Go-based Tools

Ensure you have the latest version of Go installed. Then, install the required tools:

      
# Web Crawler
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# URL Deduplicator
pipx install uro

# Pattern Matching Tool
go install -v github.com/tomnomnom/gf@latest

# Vulnerability Scanner
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

    

IGNORE_WHEN_COPYING_START
Use code with caution. Bash
IGNORE_WHEN_COPYING_END

    Important: Make sure your Go binary path (usually $HOME/go/bin) and your pipx path ($HOME/.local/bin) are included in your system's PATH.

Step 3: Set up GF Patterns

If you haven't already, set up the patterns for gf:

      
git clone https://github.com/tomnomnom/gf
mkdir -p ~/.gf
cp -r gf/examples/* ~/.gf

    

IGNORE_WHEN_COPYING_START
Use code with caution. Bash
IGNORE_WHEN_COPYING_END
Step 4: Clone and Configure This Script

    Clone the Repository:

          
    git clone [Your-GitHub-Repo-URL-Here]
    cd P1-URLs

        

    IGNORE_WHEN_COPYING_START

Use code with caution. Bash
IGNORE_WHEN_COPYING_END

Make the Script Executable:

      
chmod +x P1-URLs.py

    

IGNORE_WHEN_COPYING_START

    Use code with caution. Bash
    IGNORE_WHEN_COPYING_END

    Configure Your Slack Webhook: This is the most important step. Open P1-URLs.py and replace the placeholder URL in the SLACK_WEBHOOK variable with your own.

⚙️ How to Use

The script offers a flexible workflow with several powerful options.
Basic Scans

1. Standard Discovery Mode (Find and test URLs from a list of domains)

      
./P1-URLs.py -l domains.txt

    

IGNORE_WHEN_COPYING_START
Use code with caution. Bash
IGNORE_WHEN_COPYING_END

2. Direct URL Testing Mode (Test a pre-existing list of URLs)

      
./P1-URLs.py -l my_url_list.txt -u

    

IGNORE_WHEN_COPYING_START
Use code with caution. Bash
IGNORE_WHEN_COPYING_END
Advanced Scans

3. Using Custom LFI Payloads
To use your own LFI payloads instead of the built-in list, use the -p flag.

      
./P1-URLs.py -l domains.txt -p /path/to/my_lfi_payloads.txt

    

IGNORE_WHEN_COPYING_START
Use code with caution. Bash
IGNORE_WHEN_COPYING_END

4. Enabling Out-of-Band (OOB) SQLi Testing
This is the most powerful feature for finding "super blind" SQLi. Provide your collaborator URL (e.g., from Interactsh) using the -c flag.

    Start your Interactsh client: interactsh-client

    Run the scan with the -c flag:

          
    ./P1-URLs.py -l domains.txt -c your-unique-id.oast.online

        

    IGNORE_WHEN_COPYING_START

    Use code with caution. Bash
    IGNORE_WHEN_COPYING_END

    Monitor: The script will send OOB payloads with unique identifiers. Watch your Interactsh client and your Slack alerts. If you get a DNS or HTTP interaction, you can trace it back to the exact URL and payload using the logs.

📁 Understanding the Output

All results for a scan are saved into a unique, timestamped directory (e.g., scan_results_domains_2023-10-27_15-30-00/).

    Real-Time Slack Alerts: Your primary source of findings.

        🚨 icon for confirmed time-based vulnerabilities.

        📡 icon for every OOB payload that is fired, allowing you to correlate callbacks.

    Local Log Files:

        gf_results/: Text files of URLs sorted by potential vulnerability type.

        nuclei_results/: Raw JSONL output from all Nuclei scans.

        lfi_vulnerable.json: A log of all confirmed LFI vulnerabilities.

        blind_sqli_vulnerable.json: A log of all confirmed time-based Blind SQLi vulnerabilities.

        oob_requests.log: A critical log containing the mapping of every unique OOB ID to the URL, injection point, and payload that was sent.

        nuclei_findings.json: A log of all vulnerabilities found by Nuclei.

Credits and Inspiration

This tool stands on the shoulders of giants and was inspired by the methodologies of the broader security community.

    Author: Vivek (@starkcharry on X)

    Core Toolchain: ProjectDiscovery (katana, nuclei), tomnomnom (gf), s0md3v (uro), and all their respective contributors.
