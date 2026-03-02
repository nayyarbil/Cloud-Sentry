import requests
import urllib3
import re
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def detect_tech(html, headers, cookies):
    tech = set()
    server = headers.get('Server', '').lower()
    x_powered = headers.get('X-Powered-By', '').lower()
    
    if 'cloudflare' in server: tech.add('Cloudflare')
    if 'nginx' in server: tech.add('Nginx')
    if 'apache' in server: tech.add('Apache')
    if 'express' in x_powered: tech.add('Express.js')
    if 'php' in x_powered: tech.add('PHP')
    if 'asp.net' in x_powered: tech.add('ASP.NET')

    cookie_str = str(cookies).lower()
    if 'phpsessid' in cookie_str: tech.add('PHP')
    if 'jsessionid' in cookie_str: tech.add('Java/Spring')
    if 'csrftoken' in cookie_str: tech.add('Django')
    if 'session_id' in cookie_str and 'werkzeug' in server: tech.add('Flask')

    html_lower = html.lower()
    if 'wp-content' in html_lower or 'generator" content="wordpress' in html_lower: tech.add('WordPress')
    if 'id="__next"' in html_lower or '/_next/static' in html_lower: tech.add('Next.js')
    if 'data-reactroot' in html_lower or 'react-dom' in html_lower: tech.add('React')
    if 'data-v-' in html_lower or 'vue.js' in html_lower: tech.add('Vue.js')
    if 'ng-app' in html_lower or 'ng-version' in html_lower: tech.add('Angular')
    if 'laravel' in html_lower: tech.add('Laravel')
    if 'bootstrap' in html_lower: tech.add('Bootstrap')
    if 'jquery' in html_lower: tech.add('jQuery')

    return list(tech) if tech else ["Custom / Obfuscated"]

# --- NEW JS SCRAPER ---
def scrape_js_intel(html, base_url, headers):
    intel = {"hidden_routes": set(), "secrets": set()}
    
    # 1. Find all linked .js files
    script_paths = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', html)
    
    # Analyze up to 5 scripts to keep the scanner fast
    for path in script_paths[:5]:
        js_url = urljoin(base_url, path)
        try:
            r = requests.get(js_url, headers=headers, timeout=5, verify=False)
            if r.status_code == 200:
                content = r.text
                
                # Extract hidden API routes (e.g., "/api/v1/get_users")
                routes = re.findall(r'["\'](/[a-zA-Z0-9_/?=&.-]+)["\']', content)
                for route in routes:
                    # Filter out short garbage strings and basic formatting
                    if len(route) > 3 and len(route) < 40 and not route.endswith('.js') and not route.endswith('.css'):
                        intel["hidden_routes"].add(route)
                
                # Extract Potential Secrets (AWS Keys, Generic Bearer Tokens)
                aws_keys = re.findall(r'AKIA[0-9A-Z]{16}', content)
                for key in aws_keys:
                    intel["secrets"].add(f"AWS Key: {key[:6]}... (Redacted)")
                    
                generic_secrets = re.findall(r'(?i)(?:api_key|apikey|secret|token)["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-_]{15,})["\']', content)
                for secret in generic_secrets:
                    intel["secrets"].add(f"Generic Token: {secret[:6]}... (Redacted)")
        except:
            continue
            
    return {"hidden_routes": list(intel["hidden_routes"])[:10], "secrets": list(intel["secrets"])}

def run_web_recon(target):
    print(f"[*] Web Cell: Executing targeted endpoint sniper for {target}...")
    results = {
        "headers": {},
        "tech_stack": [],
        "missing_security_headers": [],
        "exposed_endpoints": [],
        "js_intel": {"hidden_routes": [], "secrets": []}
    }
    
    base_url = f"https://{target}"
    if target.startswith('http'):
        base_url = target
        
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        res = requests.get(base_url, headers=headers, timeout=5, verify=False, allow_redirects=True)
        
        results["headers"]["Server"] = res.headers.get("Server", "Obfuscated")
        results["tech_stack"] = detect_tech(res.text, res.headers, res.cookies)
        
        # TRIGGER THE JS SCRAPER
        results["js_intel"] = scrape_js_intel(res.text, base_url, headers)
        
        sec_headers = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options']
        for sh in sec_headers:
            if sh not in res.headers:
                results["missing_security_headers"].append(sh)
    except Exception as e:
        results["headers"]["Server"] = "Host Unreachable"
        return results

    payloads = [
        '/.env', '/.git/config', '/.aws/credentials', '/docker-compose.yml', 
        '/swagger.json', '/api/swagger-ui.html', '/server-status', 
        '/wp-config.php.bak', '/phpinfo.php', '/.DS_Store', '/backup.zip',
        '/api/v1/users', '/admin', '/actuator/env'
    ]

    def check_endpoint(path):
        try:
            url = f"{base_url}{path}"
            r = requests.get(url, headers=headers, timeout=3, verify=False, allow_redirects=False)
            if r.status_code in [200, 401, 403]:
                if "404" not in r.text and "Not Found" not in r.text:
                    return {"path": path, "status": r.status_code}
        except: pass
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        findings = list(executor.map(check_endpoint, payloads))
    
    results["exposed_endpoints"] = [f for f in findings if f is not None]

    return results