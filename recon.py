from dotenv import load_dotenv
import os
import asyncio
import httpx
import sys
import ipaddress
import argparse
import json
import csv
from datetime import datetime

from modules.passive import fetch_crtsh, fetch_hackertarget, fetch_alienvault, fetch_wayback
from modules.resolver import resolve_subdomains_concurrently
from modules.shodan_scanner import run_shodan_scans

def is_valid_domain(domain: str) -> bool:
    """Checks if the input looks like a valid domain name."""
    import re
    pattern = r'^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
    return bool(re.match(pattern, domain))

def export_results(filepath, format_type, target, subdomains, resolved_map, shodan_results):
    if not format_type: # If no format type is provided, infer it from the filepath extension
        ext = filepath.split('.')[-1].lower() if '.' in filepath else ''
        if ext in ['json', 'csv', 'txt', 'html']:
            format_type = ext
        else:
            format_type = 'txt'
    
    format_type = format_type.lower()
    
    if format_type == 'json':
        _export_to_json(filepath, target, subdomains, resolved_map, shodan_results)
    elif format_type == 'csv':
        _export_to_csv(filepath, target, subdomains, resolved_map, shodan_results)
    elif format_type == 'html':
        _export_to_html(filepath, target, subdomains, resolved_map, shodan_results)
    else:
        _export_to_txt(filepath, target, subdomains, resolved_map, shodan_results)

def _export_to_json(filepath, target, subdomains, resolved_map, shodan_results):
    # Construct structured dictionary for JSON export
    data = {
        "target": target,
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "subdomains": list(subdomains),
        "dns_resolutions": {sub: list(ips) for sub, ips in resolved_map.items()},
        "shodan_results": shodan_results
    }
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"[+] Results successfully exported to JSON: {filepath}")

def _export_to_csv(filepath, target, subdomains, resolved_map, shodan_results):
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Subdomain", "IP Address", "Open Ports", "Service Details", "Vulnerabilities"])
        if not subdomains:
            # Direct IP target — skip subdomain column and iterate Shodan scans
            for ip, data in shodan_results.items():
                ports = ", ".join(map(str, data.get("ports", []))) if "ports" in data else "N/A"
                vulns = ", ".join(data.get("vulns", [])) if data.get("vulns") else "N/A"
                services = "; ".join([f"Port {s['port']}: {s['product']}" for s in data.get("services", [])]) if data.get("services") else "N/A"
                if "error" in data:
                    ports = f"Error: {data['error']}"
                    vulns = "N/A"
                    services = "N/A"
                writer.writerow(["N/A", ip, ports, services, vulns])
        else:
            # Domain target — iterate all subdomains to include unresolved ones
            for sub in sorted(subdomains):
                ips = resolved_map.get(sub, [])
                if not ips:
                    writer.writerow([sub, "Unresolved", "N/A", "N/A", "N/A"])
                    continue
                for ip in ips:
                    data = shodan_results.get(ip, {})
                    ports = ", ".join(map(str, data.get("ports", []))) if "ports" in data else "N/A"
                    vulns = ", ".join(data.get("vulns", [])) if data.get("vulns") else "N/A"
                    services = "; ".join([f"Port {s['port']}: {s['product']}" for s in data.get("services", [])]) if data.get("services") else "N/A"
                    if "error" in data:
                        ports = f"Error: {data['error']}"
                        vulns = "N/A"
                        services = "N/A"
                    writer.writerow([sub, ip, ports, services, vulns])
    print(f"[+] Results successfully exported to CSV: {filepath}")

def _export_to_txt(filepath, target, subdomains, resolved_map, shodan_results):
    lines = []
    lines.append("=" * 60)
    lines.append(f"DYNAMIX RECON BOT REPORT - {target}")
    lines.append(f"Generated at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    lines.append("=" * 60)
    lines.append("")
    if subdomains:
        lines.append(f"[+] Found {len(subdomains)} unique subdomains:")
        for sub in sorted(subdomains):
            ips = ", ".join(resolved_map.get(sub, []))
            lines.append(f"  - {sub} ({ips if ips else 'Unresolved'})")
        lines.append("")
    lines.append("=== SHODAN SCAN RESULTS ===")
    for ip, data in shodan_results.items():
        lines.append("-" * 40)
        lines.append(f"IP: {ip}")
        if "error" in data:
            lines.append(f"  Error: {data['error']}")
            continue
        lines.append(f"  Open Ports: {data.get('ports', [])}")
        if data.get('vulns'):
            lines.append(f"  Vulnerabilities: {', '.join(data['vulns'])}")
        if data.get('services'):
            lines.append("  Services:")
            for srv in data['services']:
                lines.append(f"    - Port {srv['port']}: {srv['product']}")
    lines.append("-" * 40)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))
    print(f"[+] Results successfully exported to TXT: {filepath}")

def _export_to_html(filepath, target, subdomains, resolved_map, shodan_results):
    total_subdomains = len(subdomains)
    total_resolved = sum(1 for ips in resolved_map.values() if ips)
    total_ips = len(shodan_results)
    
    # Calculate global metrics for the header cards
    total_ports_found = 0
    total_vulns_found = 0
    for ip, data in shodan_results.items():
        if "error" not in data:
            total_ports_found += len(data.get("ports", []))
            total_vulns_found += len(data.get("vulns", []))
            
    # Generate subdomain mapping rows for the left-side panel table
    subdomain_rows = ""
    for sub in sorted(subdomains):
        ips = resolved_map.get(sub, [])
        ip_badges = "".join([f'<span class="badge badge-ip">{ip}</span>' for ip in ips]) if ips else '<span class="badge badge-error">Unresolved</span>'
        subdomain_rows += f"""
        <tr>
            <td>{sub}</td>
            <td>{ip_badges}</td>
        </tr>
        """ # Append subdomain record table row
        
    # Generate the subdomain section HTML block conditionally
    subdomain_section = ""
    if subdomains:
        subdomain_section = f"""
                <!-- Subdomain Section -->
                <div class="table-section">
                    <h2 class="section-title">🔍 Subdomain Directory</h2>
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>Subdomain</th>
                                    <th>Resolved IP(s)</th>
                                </tr>
                            </thead>
                            <tbody>
                                {subdomain_rows}
                            </tbody>
                        </table>
                    </div>
                </div>"""
                
    # Determine the CSS grid-template-columns value based on target type
    grid_columns = "1fr 1fr" if subdomains else "1fr"
    
    # Generate active host card layouts for the right-side detail panel
    shodan_cards = ""
    for ip, data in shodan_results.items():
        if "error" in data:
            shodan_cards += f"""
            <div class="card card-error">
                <div class="card-header">
                    <span class="ip-title">🌐 {ip}</span>
                    <span class="status-badge error">Scan Error</span>
                </div>
                <div class="card-body">
                    <p class="error-msg">Error: {data['error']}</p>
                </div>
            </div>
            """
            continue
            
        port_badges = "".join([f'<span class="badge badge-port">{p}</span>' for p in data.get("ports", [])]) if data.get("ports") else '<span class="text-muted">No open ports</span>'
        vuln_badges = "".join([f'<span class="badge badge-vuln">{v}</span>' for v in data["vulns"]]) if data.get("vulns") else '<span class="text-success-muted">No CVEs found</span>'
        
        # Build service list items if banner products are detected
        services_list = ""
        if data.get("services"):
            services_list += '<div class="services-list"><h4>Running Services</h4><ul>'
            for srv in data["services"]:
                prod = srv['product'] if srv['product'] else 'Unknown Product'
                services_list += f"<li><strong>Port {srv['port']}:</strong> {prod}</li>"
            services_list += '</ul></div>'
            
        shodan_cards += f"""
        <div class="card">
            <div class="card-header">
                <span class="ip-title">🌐 {ip}</span>
                <span class="status-badge active">Active</span>
            </div>
            <div class="card-body">
                <div class="detail-row">
                    <strong>Open Ports:</strong>
                    <div class="badge-container">{port_badges}</div>
                </div>
                <div class="detail-row">
                    <strong>Vulnerabilities:</strong>
                    <div class="badge-container">{vuln_badges}</div>
                </div>
                {services_list}
            </div>
        </div>
        """
        
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dynamix Recon Bot - {target}</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-color: #0b0f19;
            --card-bg: #161f30;
            --card-border: rgba(255, 255, 255, 0.05);
            --text-color: #f3f4f6;
            --text-muted: #9ca3af;
            --primary-grad: linear-gradient(135deg, #7c3aed 0%, #06b6d4 100%);
            --accent-violet: #8b5cf6;
            --accent-cyan: #06b6d4;
            --success: #10b981;
            --warning: #f59e0b;
            --error: #ef4444;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-color);
            color: var(--text-color);
            font-family: 'Outfit', sans-serif;
            line-height: 1.6;
            padding: 2rem 1rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            text-align: center;
            margin-bottom: 3rem;
            padding-bottom: 2rem;
            border-bottom: 1px solid var(--card-border);
        }}
        h1 {{
            font-size: 2.8rem;
            font-weight: 800;
            background: var(--primary-grad);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}
        .subtitle {{ color: var(--text-muted); font-size: 1.1rem; font-weight: 300; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
            margin-bottom: 3rem;
        }}
        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 1.5rem;
            text-align: center;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
            position: relative;
            overflow: hidden;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.4);
        }}
        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: var(--primary-grad);
        }}
        .stat-num {{ font-size: 2.5rem; font-weight: 800; margin: 0.5rem 0; color: #fff; }}
        .stat-label {{ color: var(--text-muted); font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .section-title {{
            font-size: 1.8rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            border-left: 4px solid var(--accent-violet);
            padding-left: 10px;
        }}
        .grid-layout {{ display: grid; grid-template-columns: 1fr; gap: 3rem; }}
        @media (min-width: 768px) {{ .grid-layout {{ grid-template-columns: {grid_columns}; }} }}
        .table-container {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
            max-height: 550px;
            overflow-y: auto;
        }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; }}
        th {{ background-color: rgba(255, 255, 255, 0.02); color: #fff; font-weight: 600; padding: 1rem; border-bottom: 1px solid var(--card-border); }}
        td {{ padding: 1rem; border-bottom: 1px solid var(--card-border); font-size: 0.95rem; }}
        tr:last-child td {{ border-bottom: none; }}
        .cards-container {{ display: flex; flex-direction: column; gap: 1.5rem; }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
            transition: border-color 0.2s ease;
        }}
        .card:hover {{ border-color: rgba(255, 255, 255, 0.1); }}
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--card-border);
            padding-bottom: 0.75rem;
            margin-bottom: 1rem;
        }}
        .ip-title {{ font-size: 1.25rem; font-weight: 600; color: #fff; }}
        .status-badge {{ font-size: 0.75rem; font-weight: 600; padding: 0.25rem 0.5rem; border-radius: 9999px; text-transform: uppercase; }}
        .status-badge.active {{ background-color: rgba(16, 185, 129, 0.1); color: var(--success); }}
        .status-badge.error {{ background-color: rgba(239, 68, 68, 0.1); color: var(--error); }}
        .detail-row {{ margin-bottom: 1rem; }}
        .detail-row strong {{ display: block; margin-bottom: 0.5rem; font-size: 0.9rem; color: var(--text-muted); }}
        .badge-container {{ display: flex; flex-wrap: wrap; gap: 0.5rem; }}
        .badge {{ display: inline-block; font-size: 0.8rem; padding: 0.2rem 0.6rem; border-radius: 6px; font-weight: 600; }}
        .badge-ip {{ background-color: rgba(139, 92, 246, 0.15); color: #c084fc; }}
        .badge-port {{ background-color: rgba(6, 182, 212, 0.15); color: #22d3ee; }}
        .badge-vuln {{ background-color: rgba(239, 68, 68, 0.15); color: #fca5a5; }}
        .badge-error {{ background-color: rgba(239, 68, 68, 0.15); color: #fca5a5; }}
        .text-success-muted {{ color: #34d399; font-size: 0.9rem; }}
        .services-list {{
            background-color: rgba(255, 255, 255, 0.01);
            border: 1px solid var(--card-border);
            border-radius: 8px;
            padding: 1rem;
            margin-top: 1rem;
        }}
        .services-list h4 {{ font-size: 0.9rem; color: var(--text-muted); margin-bottom: 0.5rem; }}
        .services-list ul {{ list-style-type: none; padding-left: 0; }}
        .services-list li {{ font-size: 0.85rem; margin-bottom: 0.25rem; color: #d1d5db; }}
        .error-msg {{ color: var(--error); font-size: 0.95rem; }}
        footer {{ text-align: center; color: var(--text-muted); margin-top: 5rem; font-size: 0.85rem; border-top: 1px solid var(--card-border); padding-top: 2rem; }}
    </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>🛡️ Dynamix Recon Report</h1>
                <div class="subtitle">Target: <strong>{target}</strong> | Generated at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</div>
            </header>
            <section class="stats-grid">
                <div class="stat-card">
                    <div class="stat-num">{total_subdomains}</div>
                    <div class="stat-label">Discovered Subdomains</div>
                </div>
                <div class="stat-card">
                    <div class="stat-num">{total_resolved}</div>
                    <div class="stat-label">Resolved Subdomains</div>
                </div>
                <div class="stat-card">
                    <div class="stat-num">{total_ips}</div>
                    <div class="stat-label">Unique IPs Scanned</div>
                </div>
                <div class="stat-card">
                    <div class="stat-num">{total_ports_found}</div>
                    <div class="stat-label">Total Open Ports</div>
                </div>
            </section>
            <div class="grid-layout">
                {subdomain_section}
                <div class="shodan-section">
                    <h2 class="section-title">🛡️ Shodan Port & Vuln Scans</h2>
                    <div class="cards-container">
                        {shodan_cards}
                    </div>
                </div>
            </div>
            <footer>Generated by Dynamix Recon Bot. Designed for premium security reporting.</footer>
        </div>
    </body>
    </html>
    """
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html_content)
    print(f"[+] Results successfully exported to HTML: {filepath}")

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
    
    parser = argparse.ArgumentParser(description="Dynamix Recon Bot - Asynchronous Network Reconnaissance & OSINT Tool")
    parser.add_argument("-t", "--target", help="The target domain or IP to scan (e.g., google.com or 8.8.8.8).")
    parser.add_argument("-o", "--output", help="Filepath to save scan results")
    parser.add_argument("-f", "--format", choices=["json", "csv", "txt", "html"], help="Output format (json, csv, txt, html)")
    
    args = parser.parse_args()
    target = args.target
    is_interactive = False

    if not target:
        is_interactive = True
        target = input("\nTarget (eg: google.com or 8.8.8.8): ").strip().lower()
        if not target:
            print("Target cannot be empty!")
            sys.exit(1)
    else:
        target = target.strip().lower()

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
        sorted_subdomains = []
        resolved_map = {}
        shodan_results = {}

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
            # Quota Protection: Ask for confirmation if too many IPs
            if is_interactive and len(unique_ips) > 20:
                print(f"\n[!] WARNING: You are about to scan {len(unique_ips)} IPs with Shodan.")
                print("    This could consume a large amount of your monthly Shodan API credits.")
                proceed = input("    Do you want to proceed with Shodan scanning? (y/n): ").strip().lower()
                if proceed != 'y':
                    print("    [*] Skipping Shodan scan phase to save API credits.")
                    unique_ips = set() # Clear IPs so we skip the scan block but still export subdomain results
            
            if unique_ips:
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

        # Export findings
        if not is_interactive:
            if args.output:
                export_results(args.output, args.format, target, sorted_subdomains, resolved_map, shodan_results)
        else:
            export_choice = input("\nDo you want to export results? (json/csv/txt/html/none): ").strip().lower()
            if export_choice in ["json", "csv", "txt", "html"]:
                default_file = f"report.{export_choice}"
                filepath = input(f"Enter output filepath (default: {default_file}): ").strip()
                if not filepath:
                    filepath = default_file
                export_results(filepath, export_choice, target, sorted_subdomains, resolved_map, shodan_results)

if __name__ == "__main__":
    asyncio.run(main())