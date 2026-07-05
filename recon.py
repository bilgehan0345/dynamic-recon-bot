from dotenv import load_dotenv
import os
import asyncio
import httpx
import sys
import socket

async def fetch_crtsh(client, domain): # Fetches subdomains from crt.sh
    try:
        params = {"q": f"%.{domain}", "output": "json"} # URL Parameters: q is the query, output is the format
        response = await client.get("https://crt.sh", params=params) # GET request to crt.sh with params
        response.raise_for_status() # Response Control: 200 Success, 4xx or 5xx raise exception
        data = response.json()
        """
        data = [
            {
                "issuer_ca_id": 12345,
                "issuer_name": "C=US, O=Example CA, CN=E1",
                "common_name": "sub.target.com",
                "name_value": "sub.target.com\ntarget.com\nwww.target.com"
            }
        ]
        """
        subdomains = set()
        for entry in data:
            for name in entry["name_value"].split("\n"):  # name_value can contain multiple domains separated by \n
                name = name.strip().lower().lstrip("*.")  # remove whitespace, uppercase, wildcard prefix
                if domain in name:                        # only keep subdomains of target domain
                    subdomains.add(name)
        return subdomains
        # Output: {"target.com", "sub.target.com", "www.target.com"}
    except httpx.TimeoutException:
        print("[crt.sh] Timeout — Request timed out")
        return set()
    except httpx.HTTPStatusError as e:
        print(f"[crt.sh] HTTP Error: {e.response.status_code}")
        return set()

async def fetch_hackertarget(client, domain): #Fetches subdomains from hackertarget
    try:
        response = await client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        response.raise_for_status()
        data = response.text.split("\n")
        """
        target.com,1.2.3.4
        sub.target.com,1.2.3.5
        www.target.com,1.2.3.6
        """
        subdomains = set()
        for line in data:
            if "," not in line:      # Skip empty or invalid lines
                continue
            name = line.split(",")[0]  # Extract subdomain part
            name = name.strip().lower().lstrip("*.")
            if domain in name:
                subdomains.add(name)
        return subdomains
        # Output: {"target.com", "sub.target.com", "www.target.com"}
    except httpx.TimeoutException:
        print("[hackertarget] Timeout — Request timed out")
        return set()
    except httpx.HTTPStatusError as e:
        print(f"[hackertarget] HTTP Error: {e.response.status_code}")
        return set()

async def fetch_alienvault(client, domain, api_key=None): # Fetches subdomains from alienvault
    try:
        # Add authentication header if OTX API key is configured
        headers = {}
        if api_key and api_key != "your_alienvault_api_key_here":
            headers["X-OTX-API-KEY"] = api_key
            
        response = await client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", headers=headers)
        response.raise_for_status()
        data = response.json()
        """
        {
            "passive_dns": [
                {"hostname": "target.com", "address": "1.2.3.4"},
                {"hostname": "sub.target.com", "address": "1.2.3.5"},
                {"hostname": "www.target.com", "address": "1.2.3.6"}
                ]
        }
        """ 
        subdomains = set()
        for entry in data.get("passive_dns", []):
            hostname = entry.get("hostname")
            if not hostname:
                continue
            for name in hostname.split("\n"): 
                name = name.strip().lower().lstrip("*.") 
                if domain in name:                        
                    subdomains.add(name)
        return subdomains
        # Output: {"target.com", "sub.target.com", "www.target.com"}
    except httpx.TimeoutException:
        print("[alienvault] Timeout — Request timed out")
        return set()
    except httpx.HTTPStatusError as e:
        print(f"[alienvault] HTTP Error: {e.response.status_code}")
        return set()

async def main():
    load_dotenv()

    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "").strip()
    ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY", "").strip()

    if not SHODAN_API_KEY or SHODAN_API_KEY == "your_shodan_api_key_here":
        print("[!] Warning: SHODAN_API_KEY not configured. Phase 2 service scans will be disabled.")
        SHODAN_API_KEY = None

    if not ALIENVAULT_API_KEY or ALIENVAULT_API_KEY == "your_alienvault_api_key_here":
        print("[!] Warning: ALIENVAULT_API_KEY not configured. Requests might hit rate limits (429).")
        ALIENVAULT_API_KEY = None
    else:
        print("[+] API Keys loaded successfully.")

    target_domain = input("Target Domain (eg: google.com): ").strip().lower()

    if not target_domain:
        print("Domain cannot be empty!")
        sys.exit(1)

    print(f"\n[*] Starting Phase 1: Passive Reconnaissance for {target_domain}")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    async with httpx.AsyncClient(timeout=60.0, headers=headers) as client:
        # Those tasks are async functions
        tasks = [
            fetch_crtsh(client, target_domain),
            fetch_hackertarget(client, target_domain),
            fetch_alienvault(client, target_domain, ALIENVAULT_API_KEY)
        ]
        
        print("[*] Fetching subdomains from sources concurrently...")
        # Run tasks concurrently; return_exceptions=True prevents total crash if one source fails
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Separate successful result sets from failed task Exception objects
        valid_results = []
        for res in results:
            if isinstance(res, Exception):
                # Log the API error but skip adding it to valid results
                print(f"[-] A source task failed with error: {res}")
            else:
                valid_results.append(res)
        
        # Merge all result sets to automatically remove duplicates
        all_subdomains = set().union(*valid_results)
        
        # Sort subdomains alphabetically
        sorted_subdomains = sorted(all_subdomains)
        
        print(f"\n[+] Found {len(sorted_subdomains)} unique subdomains:")
        for sub in sorted_subdomains:
            print(sub)

asyncio.run(main())