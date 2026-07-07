import httpx
import asyncio

async def scan_ip_shodan(client: httpx.AsyncClient, ip: str, api_key: str) -> dict:
    """
    Scans a single IP address using the Shodan REST API.
    Returns a dictionary containing open ports, services, and vulnerabilities.
    """
    url = f"https://api.shodan.io/shodan/host/{ip}"
    params = {"key": api_key}
    
    try:
        response = await client.get(url, params=params) # http request to shodan api
        
        if response.status_code == 404: # Could not find IP on Shodan
            return {"ip": ip, "error": "No information available on Shodan."}
            
        if response.status_code == 429: # Rate limit exceeded
            return {"ip": ip, "error": "Rate limit exceeded."}
            
        response.raise_for_status() # Raise exception for any other 4xx/5xx errors
        data = response.json() # Convert response to json
        
        # data: { "ip": str, "ports": list, "vulns": list, "data": list[dict] }
        ports = data.get("ports", []) # Get open ports if there is not return empty list
        vulns = data.get("vulns", []) # Get vulnerabilities if there is not return empty list
        
        services = []
        for item in data.get("data", []):
            services.append({ 
                "port": item.get("port"),
                "product": item.get("product", "Unknown")
            })
            
        return {
            "ip": ip,
            "ports": ports,
            "services": services,
            "vulns": vulns
        }
        
    except httpx.RequestError as e:
        return {"ip": ip, "error": f"Connection error: {str(e)}"}

async def run_shodan_scans(client: httpx.AsyncClient, ips: set, api_key: str) -> dict:
    """
    Scans multiple IP addresses sequentially with a 1-second delay
    to respect Shodan API rate limits.
    """
    results = {}
    
    if not api_key:
        print("[!] Shodan API key not configured, skipping scan.")
        return results

    total_ips = len(ips)
    print(f"\n[*] Starting Shodan scan for {total_ips} unique IPs...")
    
    for i, ip in enumerate(ips, 1):
        print(f"[*] Scanning ({i}/{total_ips}): {ip}")
        
        result = await scan_ip_shodan(client, ip, api_key)
        results[ip] = result
        
        if i < total_ips:
            await asyncio.sleep(1.0)
            
    print("[+] Shodan bulk scan completed.")
    return results