# Cloud-Sentry

**Modular Reconnaissance & Threat Analysis Framework**

Cloud-Sentry is a reconnaissance platform that uses AWS cloud services (DynamoDB & Cognito). I programmed it using Claude AI for bug bounty hunting and targeted penetration testing to serve my portfolio. It replaces fragmented CLI workflows by unifying DNS OSINT, active service fingerprinting, and client-side web analysis into a single engine. 

The core of the platform is the Tactician Engine, which ingests raw cross-module data and generates prioritized, status-aware attack vectors. All scan intelligence is automatically serialized and archived to AWS DynamoDB for persistent tracking.

## Core Capabilities

### 1. DNS & Infrastructure Intelligence
* **Deep OSINT:** Queries Certificate Transparency logs (crt.sh) and the VirusTotal API to uncover unlinked subdomains.
* **Active Takeover Verification:** Actively resolves dangling CNAME records against a signature database of cloud providers (AWS, Azure, Heroku, GitHub Pages) to confirm Subdomain Takeover vulnerabilities.

### 2. Network Surface & CVE Mapping
* **Targeted Port Profiling:** Bypasses standard top-100 scans to actively target high-value, frequently misconfigured ports (e.g., Docker APIs, Redis, ElasticSearch, internal databases).
* **Live CVE Cross-Referencing:** Integrates with the Shodan API to passively map known CVEs directly to resolved base IP addresses.

### 3. Web Surface & JS Bundle Parsing
* **Status-Aware Endpoint Crawling:** Targets high-impact files (/.env, /.git/config, /swagger.json) and evaluates HTTP status codes to differentiate between data leaks (HTTP 200) and targets requiring bypass techniques (HTTP 401/403).
* **JS Bundle Extraction:** Parses embedded JavaScript bundles to scrape for hardcoded cloud secrets (AWS keys, Bearer tokens) and hidden internal API routes.
* **Custom Tech-Stack Fingerprinting:** Analyzes DOM structures, headers, and cookies to identify underlying frameworks, bypassing easily spoofed X-Powered-By headers.

### 4. The Tactician Threat Engine
The Tactician module correlates data from the DNS, Network, and Web cells to generate actionable attack paths categorized by severity. For example, if an `/.env` file is found returning HTTP 403, it advises attempting 403-bypass techniques rather than blindly suggesting key extraction.

## Architecture & Tech Stack

* **Frontend:** React.js + Vite (Custom Glassmorphism UI, Context API)
* **Backend:** Python + FastAPI (Asynchronous API, concurrent multithreaded scanning)
* **Cloud Infrastructure:** AWS DynamoDB (Intelligence Archiving), AWS Cognito (Operator Authentication)
* **Core Libraries:** python-nmap, dnspython, requests, urllib3, boto3
* **External Integrations:** Shodan API, VirusTotal API, crt.sh

## Installation & Setup

**Prerequisites**
* Python 3.10+
* Node.js & npm
* Nmap installed on the host machine
* AWS IAM credentials with DynamoDB write access

**1. Clone & Configure**
```bash
git clone [https://github.com/nayyarbil/Cloud-Sentry.git](https://github.com/nayyarbil/Cloud-Sentry.git)
cd Cloud-Sentry
```
Create a `.env` file in the `backend/` directory and add your keys:
```text
# AWS Credentials
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_REGION=us-east-1

# DynamoDB Configuration
DYNAMODB_TABLE_NAME=CloudSentry_Intel

# Cognito Configuration
USER_POOL_ID=us-east-1_xxxxxxxxx

# Recon Logic Vectors
SHODAN_API_KEY=your_shodan_key_here
VIRUSTOTAL_API_KEY=your_vt_key_here
```

**2. Launch Backend**
```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

**3. Launch Frontend**
```bash
cd frontend
npm install
npm run dev
```

*Disclaimer: This tool is designed strictly for authorized penetration testing, bug bounty hunting on in-scope assets, and educational purposes. Ensure you have explicit permission before scanning any target.*
