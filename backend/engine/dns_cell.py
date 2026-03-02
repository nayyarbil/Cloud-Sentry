import os
import requests
import socket
import dns.resolver

# Factual signatures for cloud providers vulnerable to takeover
TAKEOVER_SERVICES = {
    "s3.amazonaws.com": "AWS S3",
    "herokudns.com": "Heroku",
    "herokuapp.com": "Heroku",
    "github.io": "GitHub Pages",
    "azurewebsites.net": "Azure",
    "trafficmanager.net": "Azure Traffic Manager",
    "ghost.io": "Ghost",
    "myshopify.com": "Shopify",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk"
}

def run_dns_recon(target):
    print(f"[*] DNS Cell: Deep Subdomain OSINT & Takeover Check for {target}...")
    results = {
        "base_ip": None,
        "subdomains": [],
        "sources": []
    }
    
    base_domain = target.replace('www.', '')
    found_subs = set()

    # 1. Base IP Resolution
    try:
        results["base_ip"] = socket.gethostbyname(base_domain)
    except:
        results["base_ip"] = "Resolution Failed"

    # 2. CERTIFICATE TRANSPARENCY (crt.sh)
    try:
        res = requests.get(f"https://crt.sh/?q=%25.{base_domain}&output=json", timeout=15)
        if res.status_code == 200:
            for entry in res.json():
                name = entry['name_value'].lower()
                if '*' not in name:
                    found_subs.update(name.split('\n'))
            results["sources"].append("crt.sh")
    except: pass

    # 3. VIRUSTOTAL API
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if vt_key and "your_" not in vt_key:
        try:
            headers = {"x-apikey": vt_key}
            res = requests.get(f"https://www.virustotal.com/api/v3/domains/{base_domain}/subdomains?limit=40", headers=headers, timeout=10)
            if res.status_code == 200:
                for entry in res.json().get('data', []):
                    found_subs.add(entry['id'])
                results["sources"].append("VirusTotal")
        except: pass

    # 4. Host Validation & CNAME Takeover Check
    print("[*] Validating hosts and hunting for dangling CNAMEs...")
    final_subs = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    
    for sub in list(found_subs)[:100]: 
        try:
            # Check for A Record (Live Host)
            ip = socket.gethostbyname(sub)
            final_subs.append({"host": sub, "ip": ip, "status": "LIVE"})
        except socket.gaierror:
            # If offline, check CNAME for Takeover
            try:
                answers = resolver.resolve(sub, 'CNAME')
                cname_target = str(answers[0].target).rstrip('.')
                
                # Check if it points to a vulnerable cloud provider
                is_vulnerable = False
                for signature, provider in TAKEOVER_SERVICES.items():
                    if signature in cname_target:
                        final_subs.append({"host": sub, "ip": f"CNAME: {cname_target}", "status": f"TAKEOVER RISK ({provider})"})
                        is_vulnerable = True
                        break
                
                if not is_vulnerable:
                    final_subs.append({"host": sub, "ip": f"CNAME: {cname_target}", "status": "DEAD CNAME"})
            except:
                final_subs.append({"host": sub, "ip": "OFFLINE", "status": "DEAD"})

    # Sort priorities: Takeovers first, then Live, then Dead
    priority = {"TAKEOVER RISK": 0, "LIVE": 1, "DEAD CNAME": 2, "DEAD": 3}
    results["subdomains"] = sorted(final_subs, key=lambda x: priority.get(x['status'].split(' ')[0], 4))
    
    return results