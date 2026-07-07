# 🛡️ Dynamix Recon Bot

An automated, asynchronous network reconnaissance and OSINT (Open Source Intelligence) tool built with Python and `httpx`. Designed for security professionals and penetration testers to gather assets quickly and efficiently.

> ⚠️ **Note:** This project is currently in active development. The current version implements **Phase 1 (Passive Subdomain Enumeration)**, **Phase 2 (DNS Resolution)**, and **Phase 3 (Shodan Port & Vulnerability Scanning)**. CLI argument parsing and export utilities are planned for upcoming updates (see [Project Roadmap](#-project-roadmap)).

---

## ⚡ Features

- **Asynchronous Execution:** Built on top of Python's `asyncio` and `httpx.AsyncClient` to perform network requests concurrently, ensuring maximum performance.
- **Passive Subdomain Harvesting:** Queries multiple reputable OSINT data sources simultaneously:
  - 🔍 **crt.sh:** Certificate Transparency log parser.
  - 🎯 **HackerTarget:** Host search utility.
  - 🛡️ **AlienVault OTX:** Passive DNS indicator lookup.
- **Asynchronous DNS Resolution:** Resolves discovered subdomains to their IPv4 addresses concurrently using `asyncio.getaddrinfo`, with a configurable concurrency limit to avoid overwhelming DNS servers.
- **Shodan Integration:** Scans resolved IPs against the Shodan REST API to retrieve open ports, running services, and known CVE vulnerabilities. Includes rate-limit protection with a 1-second delay between requests.
- **Robust Error Tolerance:** Handles server timeouts, rate limits (429), and gateway errors (502) gracefully without crashing the pipeline.
- **Safe Secrets Management:** Securely loads sensitive API keys from `.env` using `python-dotenv`.
- **Automatic Sanitization:** Deduplicates subdomains and cleans wildcards (`*.`), trailing spaces, and case disparities.

---

## 🚀 Quick Start & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/bilgehan0345/dynamic-recon-bot.git
cd dynamic-recon-bot
```

### 2. Install Dependencies
Make sure you have Python 3.8+ installed. Install the required external packages:
```bash
pip install -r requirements.txt
```

### 3. Setup Configuration
Copy the configuration template and create your local environment file:
```bash
cp .env.example .env
```
Open `.env` in a text editor and add your API keys:
- `SHODAN_API_KEY` (Required for Phase 3 Shodan scans)
- `ALIENVAULT_API_KEY` (Optional, helps bypass OTX rate limits)

---

## 🛠️ Usage

Run the main reconnaissance script:
```bash
python recon.py
```
When prompted, enter your target domain:
```text
Target Domain (eg: google.com): google.com
```

### Example Terminal Output:
```text
[+] API Keys loaded successfully.

Target Domain (eg: google.com): target.com

[*] Starting Phase 1: Passive Reconnaissance for target.com
[*] Fetching subdomains from sources concurrently...
[+] Found 4 unique subdomains.

[*] Starting Phase 2: DNS Resolution...
[+] Found 3 unique active IP addresses.

[*] Starting Phase 3: Shodan Scanning...
[*] Scanning (1/3): 1.2.3.4
[*] Scanning (2/3): 5.6.7.8
[*] Scanning (3/3): 9.10.11.12
[+] Shodan bulk scan completed.

=== SHODAN SCAN RESULTS ===

[IP] 1.2.3.4
  [+] Open Ports: [80, 443]
  [+] Service Details:
      - Port 80: nginx
      - Port 443: nginx

[IP] 5.6.7.8
  [-] Error: No information available on Shodan.
```

---

## 🗺️ Project Roadmap

- [x] **Phase 1:** Passive Subdomain Enumeration (Concurrently fetched, sanitized & sorted).
- [x] **Phase 2:** Active DNS Resolution (Subdomains resolved to unique IPv4 addresses concurrently).
- [x] **Phase 3:** Shodan Port & Vulnerability Scanning (Open ports, services, and CVEs retrieved per IP with rate-limit protection).

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
