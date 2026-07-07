from dotenv import load_dotenv
import os
import asyncio
import httpx
import sys
import ipaddress

from modules.passive import fetch_crtsh, fetch_hackertarget, fetch_alienvault, fetch_wayback
from modules.resolver import resolve_subdomains_concurrently
from modules.shodan_scanner import run_shodan_scans

def is_valid_domain(domain: str) -> bool:
    """Checks if the input looks like a valid domain name."""
    import re
    pattern = r'^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
    return bool(re.match(pattern, domain))

async def main():
    load_dotenv() # fetches (.env) file to get api keys

    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "").strip()
    ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY", "").strip()

    if not SHODAN_API_KEY or SHODAN_API_KEY == "your_shodan_api_key_here":
        print("[!] Warning: SHODAN_API_KEY not configured. Phase 3 Shodan scans will be disabled.")
        SHODAN_API_KEY = None

    if not ALIENVAULT_API_KEY or ALIENVAULT_API_KEY == "your_alienvault_api_key_here":
        print("[!] Warning: ALIENVAULT_API_KEY not configured. Requests might hit rate limits (429).")
        ALIENVAULT_API_KEY = None

    if SHODAN_API_KEY or ALIENVAULT_API_KEY:
        print("[+] API Keys loaded successfully.")

    target = input("\nTarget (eg: google.com or 8.8.8.8): ").strip().lower()

    if not target:
        print("Target cannot be empty!")
        sys.exit(1)

    print(f"\n[*] Starting reconnaissance for target: {target}")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    async with httpx.AsyncClient(timeout=60.0, headers=headers) as client:
        try:
            ip_obj = ipaddress.ip_address(target)  # Raises ValueError if not an IP
            is_ip_target = True

            # Item 3: Warn if private/loopback IP — Shodan only indexes public IPs
            if ip_obj.is_private or ip_obj.is_loopback:
                print("[!] Warning: Private or loopback IP entered. Shodan only indexes public internet-facing IPs. Results may be empty.")
            elif isinstance(ip_obj, ipaddress.IPv6Address):
                print("[!] Warning: IPv6 detected. Shodan has limited IPv6 coverage.")
        except ValueError:
            is_ip_target = False

        unique_ips = set()  # Defined here so Phase 3 can always access it

        if not is_ip_target:
            # Item 4: Validate domain format before running expensive API calls
            if not is_valid_domain(target):
                print(f"[-] Invalid target: '{target}' is not a valid domain or IP address. Exiting.")
                return

            # Phase 1: Passive Recon
            tasks = [
                fetch_crtsh(client, target),
                fetch_hackertarget(client, target),
                fetch_alienvault(client, target, ALIENVAULT_API_KEY),
                fetch_wayback(client, target)
            ]
            
            print("[*] Fetching subdomains from sources concurrently...")
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            valid_results = []
            for res in results:
                if isinstance(res, Exception):
                    print(f"[-] A source task failed with error: {res}")
                else:
                    valid_results.append(res)
            
            all_subdomains = set().union(*valid_results)
            sorted_subdomains = sorted(all_subdomains)
            
            print(f"\n[+] Found {len(sorted_subdomains)} unique subdomains:")
            for sub in sorted_subdomains:
                print(f"  - {sub}")

            # Phase 2: DNS Resolution
            if not sorted_subdomains:
                print("[-] No subdomains found. Exiting.")
                return

            print("\n[*] Starting Phase 2: DNS Resolution...")
            resolved_map = await resolve_subdomains_concurrently(sorted_subdomains)
            
            for sub, ips in resolved_map.items():
                unique_ips.update(ips)
                
            print(f"[+] Found {len(unique_ips)} unique active IP addresses.")

        else:
            # IP entered directly — skip Phase 1 and 2
            print("[*] IP address detected, skipping subdomain enumeration and DNS resolution.")
            unique_ips.add(target)

        # Phase 3: Shodan Scanning
        if unique_ips and SHODAN_API_KEY:
            print("\n[*] Starting Phase 3: Shodan Scanning...")
            shodan_results = await run_shodan_scans(client, unique_ips, SHODAN_API_KEY)
            
            print("\n=== SHODAN SCAN RESULTS ===")
            for ip, data in shodan_results.items():
                print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
                print(f"[IP] {ip}")
                
                if "error" in data:
                    print(f"  [-] Error: {data['error']}")
                    continue
                    
                print(f"  [+] Open Ports: {data['ports']}")
                
                if data['vulns']:
                    print(f"  [!] VULNERABILITIES (CVE) FOUND: {data['vulns']}")
                
                if data['services']:
                    print("  [+] Service Details:")
                    for srv in data['services']:
                        print(f"      - Port {srv['port']}: {srv['product']}")
            print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

if __name__ == "__main__":
    asyncio.run(main())