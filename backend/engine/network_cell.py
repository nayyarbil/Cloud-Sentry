import os
import nmap
import requests
import socket

def run_network_recon(target):
    print(f"[*] Network Cell: Deep Service & CVE Recon for {target}...")
    results = {
        "base_ip": None,
        "open_ports": [],
        "cves": [],
        "scan_errors": None
    }

    base_domain = target.replace('www.', '')
    
    try:
        ip = socket.gethostbyname(base_domain)
        results["base_ip"] = ip
    except:
        results["scan_errors"] = "Failed to resolve IP."
        return results

    # 1. SHODAN API (Passive CVE Detection)
    shodan_key = os.getenv("SHODAN_API_KEY")
    if shodan_key and "your_" not in shodan_key:
        try:
            print(f"[*] Querying Shodan for IP: {ip}")
            res = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={shodan_key}", timeout=10)
            if res.status_code == 200:
                data = res.json()
                if 'vulns' in data:
                    results["cves"] = data['vulns'] 
        except Exception as e:
            print(f"[-] Shodan query failed: {e}")

    # 2. ACTIVE NMAP SCAN (Bounty Hunter Profile)
    try:
        print(f"[*] Running Active Nmap Scan on {ip}...")
        nm = nmap.PortScanner()
        
        # Explicit list of high-value targets: DBs, Dev Web Servers, Docker, K8s, SMB, etc.
        bounty_ports = "21,22,25,53,80,111,135,139,443,445,1433,1521,2375,3000,3306,3389,5000,5432,5900,6379,6443,8000,8080,8081,8443,9090,9200,11211,27017"
        
        # Scan specifically for these ports with a slightly longer timeout to ensure it connects
        nm.scan(ip, arguments=f'-p {bounty_ports} -sV -Pn -T4 --max-retries 2 --host-timeout 45s')
        
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    state = nm[host][proto][port]['state']
                    if state == 'open':
                        service = nm[host][proto][port].get('name', 'unknown')
                        version = nm[host][proto][port].get('version', '')
                        product = nm[host][proto][port].get('product', '')
                        
                        results["open_ports"].append({
                            "port": port,
                            "service": service,
                            "version": f"{product} {version}".strip()
                        })
    except Exception as e:
        results["scan_errors"] = str(e)

    return results