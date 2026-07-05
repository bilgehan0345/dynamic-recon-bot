# 🛡️ Dynamix Recon Bot

An automated, asynchronous network reconnaissance and OSINT (Open Source Intelligence) tool built with Python and `httpx`. Designed for security professionals and penetration testers to gather assets quickly and efficiently.

> ⚠️ **Note:** This project is currently in active development. The current version implements **Phase 1: Passive Subdomain Enumeration**. Active port scanning and service detection (Phase 2+) are planned for upcoming updates (see [Project Roadmap](#-project-roadmap)).

---

## ⚡ Features (Phase 1)

- **Asynchronous Execution:** Built on top of Python's `asyncio` and `httpx.AsyncClient` to perform network requests concurrently, ensuring maximum performance.
- **Passive Subdomain Harvesting:** Queries multiple reputable OSINT data sources simultaneously:
  - 🔍 **crt.sh:** Certificate Transparency log parser.
  - 🎯 **HackerTarget:** Host search utility.
  - 🛡️ **AlienVault OTX:** Passive DNS indicator lookup.
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
- `SHODAN_API_KEY` (Required for Phase 2 scans)
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
[*] Starting Phase 1: Passive Reconnaissance for target.com
[*] Fetching subdomains from sources concurrently...

[+] Found 4 unique subdomains:
api.target.com
mail.target.com
vpn.target.com
www.target.com
```

---

## 🗺️ Project Roadmap

- [x] **Phase 1:** Passive Subdomain Enumeration (Concurrently fetched, sanitized & sorted).
- [ ] **Phase 2:** Active DNS Resolution & Port Scanning (Resolve IPs and fetch open ports, running services, and CVE vulnerabilities via Shodan).
- [ ] **Phase 3:** Modularization & CLI Argument Parser (`argparse` integration for passive-only vs active scanning options).
- [ ] **Phase 4:** Export Utilities (Save results directly to JSON, CSV, or TXT formats).

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
