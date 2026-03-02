def generate_attack_vectors(network_data, web_data, dns_data):
    print(f"[*] Tactician Cell: Compiling military-grade threat vectors...")
    vectors = []
    
    # Safely extract intelligence
    ports = [p['port'] for p in network_data.get('open_ports', [])]
    cves = network_data.get('cves', [])
    endpoints = web_data.get('exposed_endpoints', []) 
    tech_stack = web_data.get('tech_stack', [])
    js_intel = web_data.get('js_intel', {}) # <-- Grabbing the new JS intel
    subs = dns_data.get('subdomains', [])
    
    def get_status(target_path):
        for e in endpoints:
            if e['path'] == target_path:
                return e['status']
        return None

    # --- 1. NETWORK & INFRASTRUCTURE VECTORS ---
    if 22 in ports:
        vectors.append({"severity": "MEDIUM", "title": "SSH Exposed", "action": "Initiate Hydra brute-force for weak/default credentials on Port 22."})
    if 445 in ports:
        vectors.append({"severity": "CRITICAL", "title": "SMB Exposed", "action": "Check MS17-010 (EternalBlue) and SMB signing misconfigurations."})
    if len(cves) > 0:
        vectors.append({"severity": "HIGH", "title": f"Known CVEs ({len(cves)})", "action": f"Cross-reference top vulnerabilities (e.g., {cves[0]}) with Metasploit modules."})
    if 3306 in ports or 5432 in ports:
        vectors.append({"severity": "HIGH", "title": "Database Exposed", "action": "MySQL/PostgreSQL is public. Attempt default credential bypass."})
    
    # --- 2. WEB SURFACE VECTORS ---
    env_status = get_status('/.env')
    if env_status:
        if env_status == 200:
            vectors.append({"severity": "CRITICAL", "title": "Environment Variables Leaked", "action": "Target returned HTTP 200. Extract AWS/DB keys from /.env and test access immediately."})
        elif env_status in [401, 403]:
            vectors.append({"severity": "HIGH", "title": "Protected .env File Detected", "action": f"/.env exists but is blocked (HTTP {env_status}). Attempt 403 bypass techniques (header manipulation, path normalization, SSRF)." })

    git_status = get_status('/.git/config')
    if git_status:
        if git_status == 200:
            vectors.append({"severity": "CRITICAL", "title": "Git Repository Exposed", "action": "Target returned HTTP 200. Use git-dumper to reconstruct source code and hunt for hardcoded secrets."})
        elif git_status in [401, 403]:
            vectors.append({"severity": "MEDIUM", "title": "Protected .git Directory", "action": f"/.git/config exists but is blocked (HTTP {git_status}). Attempt 403 bypass or look for /.git/HEAD."})

    swagger_status = get_status('/swagger.json') or get_status('/api/swagger-ui.html')
    if swagger_status:
        if swagger_status == 200:
            vectors.append({"severity": "HIGH", "title": "API Documentation Exposed", "action": "Target returned HTTP 200. Map all API routes and test for BOLA (Broken Object Level Authorization)."})
        elif swagger_status in [401, 403]:
            vectors.append({"severity": "MEDIUM", "title": "Protected API Docs", "action": f"API docs found but blocked (HTTP {swagger_status}). Analyze JS files for leaked API endpoints instead."})
    
    # --- 3. TECH STACK SPECIFIC ---
    if 'WordPress' in tech_stack:
        vectors.append({"severity": "MEDIUM", "title": "WordPress Detected", "action": "Run WPScan to enumerate vulnerable plugins and themes."})
    if 'PHP' in tech_stack:
        vectors.append({"severity": "LOW", "title": "PHP Backend", "action": "Test for PHP Object Injection and LFI (Local File Inclusion) on URL parameters."})
        
    # --- 4. JS BUNDLE VECTORS (NEW) ---
    secrets = js_intel.get('secrets', [])
    if secrets:
        vectors.append({"severity": "CRITICAL", "title": "Hardcoded Secrets in JS", "action": f"Found {len(secrets)} potential keys in client-side bundles. Validate keys immediately via respective cloud APIs."})
        
    hidden_routes = js_intel.get('hidden_routes', [])
    if hidden_routes:
        vectors.append({"severity": "MEDIUM", "title": "Internal API Routes Discovered", "action": f"Extracted {len(hidden_routes)} undocumented routes from JS. Fuzz these endpoints for broken access control or IDOR."})

    # --- 5. DNS / TAKEOVER VECTORS ---
    verified_takeovers = [s for s in subs if 'TAKEOVER RISK' in s.get('status', '')]
    for tk in verified_takeovers:
        provider = tk['status'].split('(')[-1].strip(')') 
        cname = tk['ip'].replace('CNAME: ', '')
        vectors.append({
            "severity": "CRITICAL", 
            "title": f"Confirmed Subdomain Takeover ({provider})", 
            "action": f"Subdomain {tk['host']} points to unclaimed {provider} at {cname}. Register the resource immediately to hijack the domain."
        })

    dead_cnames = [s for s in subs if s.get('status') == 'DEAD CNAME']
    if dead_cnames:
        vectors.append({
            "severity": "LOW",
            "title": "Dangling CNAME Records",
            "action": f"{len(dead_cnames)} subdomains have dangling CNAMEs to unknown providers. Investigate manually for edge-case takeover potential."
        })

    if not vectors:
        vectors.append({"severity": "INFO", "title": "No Surface Vulnerabilities", "action": "Automated recon clean. Proceed to manual business-logic testing (e.g., IDOR, XSS)."})

    # Sort by severity
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    vectors.sort(key=lambda x: severity_rank.get(x["severity"], 5))

    return vectors