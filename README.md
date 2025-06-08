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
``go install -v github.com/projectdiscovery/katana/cmd/katana@latest``

# URL Deduplicator
pipx install uro

# Pattern Matching Tool
``go install -v github.com/tomnomnom/gf@latest``

# Vulnerability Scanner
``go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest``


## ⚙️ Configuration & Usage

### Initial Configuration

Before running, you must configure the tool:

1. **Clone the Repository**:
```bash
git clone [Your-GitHub-Repo-URL-Here]
cd P1-URLs
```

## ⚙️ Configuration & Usage

### Initial Setup
1. **Make the Script Executable**:
```bash
chmod +x P1-URLs.py
```

## ⚙️ Scan Modes

### 🔍 Standard Discovery Mode

Find and test URLs from a list of domains using Katana and built-in modules.

```bash
./P1-URLs.py -l domains.txt
```

## Direct URL Testing Mode

Test a pre-existing list of URLs directly for LFI/SQLi vulnerabilities.

``./P1-URLs.py -l my_url_list.txt -u``

### Custom LFI Payloads Mode

Use your own list of LFI payloads instead of the built-in wordlist.

``./P1-URLs.py -l domains.txt -p /path/to/custom_lfi_payloads.txt``

### 🧠 Advanced: Out-of-Band (OOB) SQLi Testing

This is the most powerful detection mode for super-blind SQLi using OOB payloads.

  🔁 Step 1: Start Interactsh/Burp Collab client

``interactsh-client/Burp Collab``

  🚀 Step 2: Run the scan with your unique OOB URL

``./P1-URLs.py -l domains.txt -c your-unique-id.oast.online``

💡 Note: Match interaction callback IDs with vulnerable targets by checking:

``oob_requests.log``

### 📂 Output Structure

Results are saved inside a timestamped directory like:
``scan_results_domains_2023-10-27_15-30-00/``



### 🙏 Credits

    Author: Vivek ( x.com/starkcharry ), ( bugcrowd.com/realvivek )

    Core Tools: ProjectDiscovery, tomnomnom, s0md3v
