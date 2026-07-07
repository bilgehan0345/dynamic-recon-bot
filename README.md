# 🛡️ Dynamix Recon Bot

An automated, asynchronous network reconnaissance and OSINT (Open Source Intelligence) tool built with Python and `httpx`. Designed for security professionals and penetration testers to gather assets quickly and efficiently.

> ⚠️ **Note:** This project is currently in active development. The current version implements **Phase 1 (Passive Subdomain Enumeration)**, **Phase 2 (DNS Resolution)**, and **Phase 3 (Shodan Port & Vulnerability Scanning)**. CLI argument parsing and export utilities are planned for upcoming updates (see [Project Roadmap](#-project-roadmap)).

---

## ⚡ Features

- **Asynchronous Execution:** Built on top of Python's `asyncio` and `httpx.AsyncClient` to perform network requests concurrently, ensuring maximum performance.
- **Dual Target Mode:** Accepts both a **domain name** (full recon pipeline) or a **direct IP address** (skips to Shodan scan immediately).
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

---

### 2. Install Dependencies

#### 🪟 Windows (with uv)
```powershell
uv venv
.venv\Scripts\activate
uv pip install -r requirements.txt
```

#### 🪟 Windows (standard pip)
```powershell
pip install -r requirements.txt
```

#### 🐉 Kali Linux
On Kali, Python 3 is pre-installed. Use a virtual environment to avoid system package conflicts:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

> **Tip:** You'll know the virtual environment is active when you see `(.venv)` at the start of your terminal prompt. You need to activate it every time you open a new terminal session.

---

### 3. Setup API Keys (.env)

Copy the configuration template:
```bash
cp .env.example .env      # Linux / macOS / Kali
copy .env.example .env    # Windows
```

Open the `.env` file in a text editor and fill in your API keys:
```bash
nano .env    # Kali / Linux
notepad .env # Windows
```

The file looks like this:
```env
SHODAN_API_KEY=your_shodan_api_key_here
ALIENVAULT_API_KEY=your_alienvault_api_key_here
```

Replace the placeholder values with your real keys:

| Key | Where to Get It | Required? |
|---|---|---|
| `SHODAN_API_KEY` | [account.shodan.io](https://account.shodan.io) → "API Key" section | ✅ Required for Phase 3 |
| `ALIENVAULT_API_KEY` | [otx.alienvault.com](https://otx.alienvault.com) → Settings → "API Key" | ⚠️ Optional (helps avoid rate limits) |

> **Security Note:** The `.env` file is listed in `.gitignore` and will never be committed to GitHub. Never share this file or hardcode API keys directly in the source code.


---

## 🛠️ Usage

Run the main reconnaissance script:
```bash
python recon.py
```
When prompted, enter your target domain or IP address:
```text
Target (eg: google.com or 8.8.8.8): google.com
```

**Domain Mode:** Runs the full pipeline — subdomain enumeration → DNS resolution → Shodan scan.

**IP Mode:** Skips directly to the Shodan scan.
```text
Target (eg: google.com or 8.8.8.8): 8.8.8.8
```

### Example Terminal Output (Domain):
```text
[+] API Keys loaded successfully.

Target (eg: google.com or 8.8.8.8): target.com

[*] Starting reconnaissance for target: target.com
[*] Fetching subdomains from sources concurrently...
[+] Found 4 unique subdomains.

[*] Starting Phase 2: DNS Resolution...
[+] Found 3 unique active IP addresses.

[*] Starting Phase 3: Shodan Scanning...
[*] Scanning (1/3): 1.2.3.4
[+] Shodan bulk scan completed.

=== SHODAN SCAN RESULTS ===

[IP] 1.2.3.4
  [+] Open Ports: [80, 443]
  [+] Service Details:
      - Port 80: nginx
      - Port 443: nginx
```

### Example Terminal Output (Direct IP):
```text
Target (eg: google.com or 8.8.8.8): 8.8.8.8

[*] Starting reconnaissance for target: 8.8.8.8
[*] IP address detected, skipping subdomain enumeration and DNS resolution.

[*] Starting Phase 3: Shodan Scanning...
[*] Scanning (1/1): 8.8.8.8
[+] Shodan bulk scan completed.

=== SHODAN SCAN RESULTS ===

[IP] 8.8.8.8
  [+] Open Ports: [53, 443]
  [+] Service Details:
      - Port 53: Unknown
      - Port 443: Unknown
```

---

## 🗺️ Project Roadmap

- [x] **Phase 1:** Passive Subdomain Enumeration (Concurrently fetched, sanitized & sorted).
- [x] **Phase 2:** Active DNS Resolution (Subdomains resolved to unique IPv4 addresses concurrently).
- [x] **Phase 3:** Shodan Port & Vulnerability Scanning (Open ports, services, and CVEs retrieved per IP with rate-limit protection).
- [ ] **Phase 4:** Export & Reporting Utilities (Save results directly to JSON, CSV, or TXT formats).

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
