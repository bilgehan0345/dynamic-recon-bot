from dotenv import load_dotenv
import os
import asyncio
import httpx
import sys

from modules.passive import fetch_crtsh, fetch_hackertarget, fetch_alienvault
from modules.resolver import resolve_subdomains_concurrently
from modules.shodan_scanner import run_shodan_scans

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

    target_domain = input("\nTarget Domain (eg: google.com): ").strip().lower()

    if not target_domain:
        print("Domain cannot be empty!")
        sys.exit(1)

    print(f"\n[*] Starting Phase 1: Passive Reconnaissance for {target_domain}")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    async with httpx.AsyncClient(timeout=60.0, headers=headers) as client:
        # Phase 1: Passive Recon
        tasks = [
            fetch_crtsh(client, target_domain),
            fetch_hackertarget(client, target_domain),
            fetch_alienvault(client, target_domain, ALIENVAULT_API_KEY)
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
        
        print(f"\n[+] Found {len(sorted_subdomains)} unique subdomains.")

        # Phase 2: DNS Resolution
        if not sorted_subdomains:
            print("[-] No subdomains found. Exiting.")
            return

        print("\n[*] Starting Phase 2: DNS Resolution...")
        resolved_map = await resolve_subdomains_concurrently(sorted_subdomains)
        
        unique_ips = set()
        for sub, ips in resolved_map.items():
            unique_ips.update(ips)
            
        print(f"[+] Found {len(unique_ips)} unique active IP addresses.")

        # Phase 3: Shodan Scanning
        if unique_ips and SHODAN_API_KEY:
            print("\n[*] Starting Phase 3: Shodan Scanning...")
            shodan_results = await run_shodan_scans(client, unique_ips, SHODAN_API_KEY)
            
            print("\n=== SHODAN SCAN RESULTS ===")
            for ip, data in shodan_results.items():
                print(f"\n[IP] {ip}")
                
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

if __name__ == "__main__":
    asyncio.run(main())