# P1-URLs.py-Stealth-Edition

How to Use Your P1-URLs.py (Stealth Edition)

This is an advanced, automated vulnerability scanner designed to find high-impact security flaws. It intelligently chains together leading open-source tools with custom, evasive testing logic to maximize the discovery of critical vulnerabilities.
Key Features

    Maximum Discovery: Uses both Katana (active crawl) and GAU (historical archives) to build the most comprehensive list of target URLs.

    Intelligent LFI Detection: Employs a Dynamic Differential Analysis technique, comparing page content to find LFI, making it more accurate and less prone to false positives than simple string matching.

    Evasive Blind SQLi Testing:

        HTTP Parameter Pollution (HPP): Tests URL parameters using HPP to bypass common WAF rules.

        Randomized Header Testing: Tests multiple HTTP headers using randomized methods and header orders to evade pattern-based detection.

        Isolated Injection: Injects payloads into only one header at a time, making requests appear more legitimate.

    Real-Time Alerts: Sends an immediate, detailed notification to Slack the moment any vulnerability is confirmed.

    Flexible & Self-Contained: Comes with a massive, curated list of over 250 built-in LFI payloads, with an option to use your own custom list.

Setup & Installation (Prerequisites)

You only need to do this once.

    Save the Script: Save the code above as P1-URLs.py.

    Make it Executable: Open a terminal and run:

          
    chmod +x P1-URLs.py

        

    IGNORE_WHEN_COPYING_START

Use code with caution. Bash
IGNORE_WHEN_COPYING_END

Install Python Libraries: The script requires requests and rich. If you encounter an externally-managed-environment error, use the --user flag.

      
pip3 install --user rich requests

    

IGNORE_WHEN_COPYING_START
Use code with caution. Bash
IGNORE_WHEN_COPYING_END

Install Go-based Tools: This script relies on several Go tools. Ensure you have Go installed, then run:

      
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/s0md3v/uro@latest
go install github.com/tomnomnom/gf@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

    

IGNORE_WHEN_COPYING_START
Use code with caution. Bash
IGNORE_WHEN_COPYING_END

Ensure your Go binary path (~/go/bin) is in your system's PATH.

Set up GF Patterns:

      
git clone https://github.com/tomnomnom/gf
mkdir -p ~/.gf
cp -r gf/examples/* ~/.gf

    

IGNORE_WHEN_COPYING_START

    Use code with caution. Bash
    IGNORE_WHEN_COPYING_END

    Configure Your Slack Webhook: This is critical. Open P1-URLs.py and replace the placeholder SLACK_WEBHOOK URL with your actual Slack incoming webhook.

Running the Scan

    Prepare Input File: Create a text file (e.g., domains.txt) with your target root domains, one per line (e.g., https://example.com).

    Execute the Script:

        To use the powerful built-in LFI payloads:

              
        ./P1-URLs.py -l domains.txt

            

        IGNORE_WHEN_COPYING_START

Use code with caution. Bash
IGNORE_WHEN_COPYING_END

To use your own custom LFI payloads:

      
./P1-URLs.py -l domains.txt -p path/to/my_lfi_payloads.txt

    

IGNORE_WHEN_COPYING_START

        Use code with caution. Bash
        IGNORE_WHEN_COPYING_END

Detailed Workflow Explained

The script executes the following steps in order:

    Initialization: The animated banner displays, and the script checks that all necessary tools are installed.

    Step 1: URL Gathering (gather_urls): For each domain, it runs Katana and GAU to discover as many URLs as possible from both active crawling and historical archives.

    Step 2: Deduplication (run_uro): The massive, raw URL list is piped through Uro to remove duplicates and uninteresting files, focusing the scan on valuable endpoints.

    Step 3: Classification (run_gf): GF analyzes the unique URLs and sorts them into buckets based on patterns (e.g., _lfi.txt, _sqli.txt), enabling targeted scanning.

    Step 4: LFI Testing (test_lfi_dynamically):

        Input: The _lfi.txt list.

        Method: A custom Python function performs Differential Analysis. It compares a normal page response to a response with an LFI payload. If the pages are significantly different and the new page contains known sensitive strings (root:x:0:0, etc.), it confirms the LFI.

        Notification: A Slack alert is sent immediately upon confirmation.

    Step 5: Blind SQLi Testing (test_blind_sqli):

        Input: The _sqli.txt list.

        Method (Phase 1 - Parameters): For each URL parameter, it tests for SQLi using both standard injection and HTTP Parameter Pollution (HPP) for WAF evasion.

        Method (Phase 2 - Headers): It then attacks the URL's headers, randomizing the order of HTTP methods and headers tested. Each request contains a single malicious header within a set of otherwise clean, legitimate headers.

        Notification: A Slack alert detailing the exact injection point (parameter or header), method, DB, and payload is sent immediately upon confirmation.

    Step 6: Nuclei Scanning (run_nuclei):

        Input: All other lists from GF (XSS, RCE, SSRF, etc.).

        Method: Nuclei runs its vast library of templates against these categorized URLs.

        Notification: A detailed Slack alert is sent immediately for every valid finding.

    Completion: The script finishes and reminds you to check the log files.

Understanding the Results

    Real-Time Slack Alerts: Your primary source of findings. You will be notified the second a vulnerability is found.

    Local Log Files:

        gf_results/: The categorized URL lists.

        nuclei_results/: Raw JSON output from Nuclei scans.

        lfi_vulnerable.json: A log of all confirmed LFI findings.

        blind_sqli_vulnerable.json: A log of all confirmed Blind SQLi findings.

