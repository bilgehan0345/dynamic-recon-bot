"""
modules/passive.py - Passive Subdomain Gathering Module

This module collects subdomains for a target domain from passive third-party sources:
1. crt.sh (SSL/TLS certificates transparency logs)
2. HackerTarget (passive DNS lookup API)
3. AlienVault OTX (passive DNS records)
"""

import httpx

async def fetch_crtsh(client, domain): # Fetches subdomains from crt.sh
    try:
        params = {"q": f"%.{domain}", "output": "json"} # URL Parameters: q is the query, output is the format
        response = await client.get("https://crt.sh", params=params) # GET request to crt.sh with params
        response.raise_for_status() # Response Control: 200 Success, 4xx or 5xx raise exception
        data = response.json()
        # data: list of dicts, each with a "name_value" field containing newline-separated domain names
        subdomains = set()
        for entry in data:
            for name in entry["name_value"].split("\n"):  # name_value can contain multiple domains separated by \n
                name = name.strip().lower().lstrip("*.")  # remove whitespace, uppercase, wildcard prefix
                if domain in name:                        # only keep subdomains of target domain
                    subdomains.add(name)
        # Output: {"target.com", "sub.target.com", "www.target.com"}
        return subdomains
    except httpx.TimeoutException:
        print("[crt.sh] Timeout — Request timed out")
        return set()
    except httpx.HTTPStatusError as e:
        print(f"[crt.sh] HTTP Error: {e.response.status_code}")
        return set()

async def fetch_hackertarget(client, domain): # Fetches subdomains from hackertarget
    try:
        response = await client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        response.raise_for_status()
        data = response.text.split("\n")
        # data: list of "subdomain,ip" lines as plain text
        subdomains = set()
        for line in data:
            if "," not in line:      # Skip empty or invalid lines
                continue
            name = line.split(",")[0]  # Extract subdomain part
            name = name.strip().lower().lstrip("*.")
            if domain in name:
                subdomains.add(name)
        # Output: {"target.com", "sub.target.com", "www.target.com"}
        return subdomains
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
        # data: { "passive_dns": [ { "hostname": str, "address": str } ] }
        subdomains = set()
        for entry in data.get("passive_dns", []):
            hostname = entry.get("hostname")
            if not hostname:
                continue
            for name in hostname.split("\n"): 
                name = name.strip().lower().lstrip("*.") 
                if domain in name:                        
                    subdomains.add(name)
        # Output: {"target.com", "sub.target.com", "www.target.com"}
        return subdomains
    except httpx.TimeoutException:
        print("[alienvault] Timeout — Request timed out")
        return set()
    except httpx.HTTPStatusError as e:
        print(f"[alienvault] HTTP Error: {e.response.status_code}")
        return set()