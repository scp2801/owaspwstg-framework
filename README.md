<div align="center">

# 🔒 OWASP WSTG Bug Bounty Automation Framework

<img src="https://img.shields.io/badge/Version-1.0.0-00d4aa?style=for-the-badge" />
<img src="https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python" />
<img src="https://img.shields.io/badge/OWASP-WSTG_v4.2-red?style=for-the-badge" />
<img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Kali%20%7C%20Termux-green?style=for-the-badge" />
<img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" />

**Professional OWASP WSTG-based Web Security Testing & Bug Bounty Automation Framework**

*Reconnaissance → Attack Surface Mapping → Vulnerability Discovery → Professional Reports*

[Installation](#installation) • [Usage](#usage) • [Features](#features) • [Reports](#reports) • [Contributing](#contributing)

</div>

---

## 📋 Overview

**OWASP WSTG Bug Bounty Automation Framework** is a production-grade, fully autonomous web security testing framework built entirely on the [OWASP Web Security Testing Guide (WSTG) v4.2](https://owasp.org/www-project-web-security-testing-guide/) methodology.

It automates the entire bug bounty workflow:

```
Target Input → Recon → Crawl → Attack Surface → Vuln Scan → Evidence → Report
```

Similar in spirit to **reconFTW**, **Osmedeus**, **BBOT**, and **ProjectDiscovery** toolchains — but built as a single cohesive Python framework focused on OWASP WSTG checklist coverage.

---

## ✨ Features

### 🔍 Reconnaissance Engine
- **Subdomain Enumeration** — crt.sh, AlienVault OTX, RapidDNS, Wayback Machine, HackerTarget
- **DNS Enumeration** — A, AAAA, MX, TXT, CNAME, NS records
- **Live Host Detection** — HTTP/HTTPS probing, title extraction, tech fingerprinting
- **Technology Detection** — CMS, frameworks, WAF/CDN detection

### 🕷️ Web Crawling Engine
- Recursive depth-limited crawling
- JavaScript file extraction & analysis
- robots.txt & sitemap.xml parsing
- Wayback Machine archived URL collection
- Form & parameter extraction

### 🔬 Vulnerability Modules
| Module | WSTG ID | Description |
|--------|---------|-------------|
| XSS Checker | WSTG-INPV-01/02 | Reflected & Stored XSS detection |
| SQLi Checker | WSTG-INPV-05 | Error-based & Boolean-blind SQLi |
| SSRF Checker | WSTG-INPV-19 | Server-Side Request Forgery |
| Open Redirect | WSTG-CLNT-04 | Open redirect via param testing |
| CORS Checker | WSTG-CLNT-07 | CORS misconfiguration detection |
| Security Headers | WSTG-CONF-07/12 | Missing/weak security headers |
| Clickjacking | WSTG-CLNT-09 | X-Frame-Options / CSP check |
| JWT Checker | WSTG-SESS-10 | JWT algorithm/payload vulns |
| Subdomain Takeover | WSTG-CONF-10 | 15+ service fingerprints |
| Sensitive Files | WSTG-CONF-04 | .env, .git, backups, admin panels |
| JS Secrets | WSTG-INFO-05 | API keys, AWS creds, tokens in JS |
| Auth Testing | WSTG-ATHN series | Cookie attrs, HTTP login, admin panels |
| API Security | WSTG-APIT-01 | GraphQL, REST API misconfigs |
| Session Testing | WSTG-SESS series | Session fixation, CSRF, weak cookies |
| Client-Side | WSTG-CLNT series | DOM XSS, HTML injection, tabnabbing |

### 📊 Professional Reports
- **HTML** — Dark-themed professional pentest report
- **Excel** — Full OWASP WSTG checklist with colored cells & filters
- **JSON** — Machine-readable findings for CI/CD integration
- **Markdown** — GitHub-ready report
- **TXT** — Plain text summary

### 🗂️ OWASP WSTG Checklist Engine
Automatically maps every finding to WSTG IDs:
```
WSTG-INFO-01 → PASS
WSTG-CONF-07 → FAIL (Missing HSTS)
WSTG-SESS-10 → REVIEW
```

---

## 🏗️ Architecture

```
owaspwstg/
│
├── main.py                    # CLI entry point (Typer)
├── config.yaml                # Configuration file
├── requirements.txt
│
├── core/
│   ├── engine.py              # Main scan orchestrator
│   ├── checklist_engine.py    # OWASP WSTG checklist tracker
│   ├── report_engine.py       # Multi-format report generator
│   ├── screenshot_engine.py   # Playwright screenshot capture
│   ├── config_loader.py       # YAML config with scan profiles
│   ├── task_manager.py        # Async task queue + resume support
│   ├── logger.py              # Loguru-based structured logging
│   ├── os_detector.py         # Platform detection (Termux/Kali/Linux)
│   ├── dependency_checker.py  # Tool availability checker
│   └── utils.py               # Shared utilities
│
├── modules/
│   ├── recon/
│   │   ├── subdomain_enum.py  # Multi-source subdomain enumeration
│   │   ├── dns_enum.py        # DNS record enumeration
│   │   └── live_host.py       # Live host probing
│   ├── crawling/
│   │   └── web_crawler.py     # Async recursive web crawler
│   ├── params/
│   │   └── param_discovery.py # GET/POST parameter discovery
│   ├── js_analysis/
│   │   └── js_analyzer.py     # JS secret & endpoint extraction
│   ├── vulnerabilities/
│   │   ├── xss_checker.py     # XSS detection
│   │   ├── sqli_checker.py    # SQLi detection
│   │   ├── ssrf_checker.py    # SSRF detection
│   │   ├── cors_checker.py    # CORS misconfiguration
│   │   ├── open_redirect.py   # Open redirect
│   │   ├── clickjacking.py    # Clickjacking check
│   │   ├── jwt_checker.py     # JWT vulnerability analysis
│   │   ├── security_headers.py# Security header audit
│   │   ├── sensitive_files.py # Sensitive file exposure
│   │   └── subdomain_takeover.py # Subdomain takeover
│   ├── auth/
│   │   └── auth_tester.py     # Authentication testing
│   ├── session/
│   │   └── session_tester.py  # Session management testing
│   ├── api/
│   │   └── api_tester.py      # API security testing
│   └── client_side/
│       └── client_tester.py   # Client-side security testing
│
├── templates/                 # Jinja2 HTML report templates
├── payloads/                  # Custom payload files
├── wordlists/                 # Directory brute-force wordlists
├── reports/                   # Generated reports (auto-created)
├── screenshots/               # Captured screenshots
├── logs/                      # Scan logs
├── docs/                      # Documentation
└── tests/                     # Unit tests
```

---

## 💻 Installation

### Requirements
- Python 3.11+
- pip
- (Optional) Go 1.21+ for external tools

### 🐧 Linux / Ubuntu / Debian

```bash
# Clone the repository
git clone https://github.com/scp2801/owaspwstg-framework.git
cd owaspwstg-framework

# Run installer
chmod +x install.sh
./install.sh
```

### 🔴 Kali Linux

```bash
git clone https://github.com/scp2801/owaspwstg-framework.git
cd owaspwstg-framework

chmod +x kali_setup.sh
./kali_setup.sh
```

Kali setup installs: `subfinder`, `httpx`, `nuclei`, `katana`, `ffuf`, `naabu`

### 📱 Termux (Android)

```bash
git clone https://github.com/scp2801/owaspwstg-framework.git
cd owaspwstg-framework

chmod +x termux_setup.sh
./termux_setup.sh
```

> **Note:** Screenshots are automatically disabled on Termux. All other features work normally.

### Manual Installation

```bash
# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install Playwright browsers (optional, for screenshots)
playwright install chromium

# Make CLI executable
chmod +x main.py
```

---

## 🚀 Usage

### Basic Scan

```bash
python3 main.py scan example.com
```

### Full Scan with All Reports

```bash
python3 main.py scan example.com --format all --output reports/
```

### Scan with Scope File

```bash
python3 main.py scan example.com --scope-file scope.txt
```

### Deep Scan Profile

```bash
python3 main.py scan example.com --profile deep --threads 5
```

### Fast Scan (No Screenshots)

```bash
python3 main.py scan example.com --profile fast --no-screenshots
```

### Stealth Scan

```bash
python3 main.py scan example.com --profile stealth
```

### Recon Only

```bash
python3 main.py recon example.com
```

### Generate Report from Existing Results

```bash
python3 main.py report reports/example.com_20240101/scan_results.json --format excel
```

### Check Dependencies

```bash
python3 main.py check
```

---

## 📊 Report Examples

### Excel WSTG Checklist Report

The Excel report follows the official OWASP WSTG checklist format:

| WSTG ID | Category | Test Name | Status | Severity | URL | Evidence | Recommendation |
|---------|----------|-----------|--------|----------|-----|----------|----------------|
| WSTG-INFO-01 | Information Gathering | Search Engine Discovery | ✅ PASS | Info | ... | ... | ... |
| WSTG-CONF-07 | Configuration | HTTP Strict Transport Security | ❌ FAIL | Medium | https://... | Missing HSTS header | Add HSTS header |
| WSTG-SESS-10 | Session Management | JWT Testing | ⚠️ REVIEW | High | ... | JWT with none alg | Reject none algorithm |

**Features:**
- Color-coded severity cells (Critical=Red, High=Orange, Medium=Yellow, Low=Blue)
- AutoFilter on all columns
- Frozen header rows
- 3 sheets: WSTG Checklist, Vulnerability Findings, Recon Summary

### HTML Report

Professional dark-themed pentest report with:
- Executive summary dashboard
- Severity breakdown cards
- Detailed vulnerability findings with evidence
- Complete WSTG checklist table

### JSON Report

Machine-readable output for CI/CD integration:
```json
{
  "meta": { "target": "example.com", "scan_date": "2024-01-01" },
  "summary": { "critical": 2, "high": 5, "medium": 8 },
  "vulnerabilities": [...],
  "checklist": [...]
}
```

---

## 🛡️ Scan Profiles

| Profile | Threads | Timeout | Rate Limit | Use Case |
|---------|---------|---------|------------|----------|
| `default` | 10 | 30s | 50 req/s | Standard bug bounty |
| `fast` | 25 | 10s | 100 req/s | Quick overview |
| `deep` | 5 | 60s | 10 req/s | Thorough testing |
| `stealth` | 2 | 45s | 5 req/s | Low & slow |

---

## 🔧 Configuration

Edit `config.yaml` to customize:

```yaml
scan:
  threads: 10
  timeout: 30
  rate_limit: 50
  vuln_scan: true

recon:
  sources: [crtsh, alienvault, rapiddns, webarchive]
  max_subdomains: 5000

vulnerabilities:
  xss: true
  sqli: true
  cors: true
  # ... enable/disable modules
```

---

## 📁 Scope File Format

```text
# scope.txt
example.com
*.example.com
sub.example.com
https://api.example.com
```

---

## 🔌 External Tools Integration

The framework auto-detects and uses these tools if installed:

| Tool | Purpose | Auto-Install |
|------|---------|-------------|
| `subfinder` | Subdomain enumeration | Kali setup |
| `httpx` | HTTP probing | Kali setup |
| `nuclei` | Vulnerability scanning | Kali setup |
| `katana` | Web crawling | Kali setup |
| `ffuf` | Directory fuzzing | Kali setup |
| `naabu` | Port scanning | Kali setup |

---

## ⚖️ Legal Disclaimer

> **IMPORTANT:** This framework is designed for **authorized security testing only**.
>
> - Only use on systems you have explicit written permission to test
> - Always comply with the target's bug bounty program rules
> - The authors are not responsible for misuse or damage caused
> - This tool does NOT contain destructive payloads
> - All vulnerability tests are safe and non-destructive
>
> Unauthorized use may violate the Computer Fraud and Abuse Act (CFAA),
> GDPR, or similar laws in your jurisdiction.

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-module`
3. Write tests in `tests/`
4. Follow PEP8 coding standards
5. Submit a Pull Request

### Adding a New Vulnerability Module

```python
# modules/vulnerabilities/my_checker.py
class MyChecker:
    def __init__(self, urls, config, logger):
        ...
    
    async def check(self) -> List[Dict]:
        # Return list of findings with these fields:
        return [{
            "type": "my_vuln",
            "name": "My Vulnerability",
            "url": url,
            "wstg_id": "WSTG-XXXX-XX",
            "severity": "High",
            "cwe": "CWE-XXX",
            "cvss": "7.5",
            "description": "...",
            "evidence": "...",
            "recommendation": "...",
            "vulnerable": True,
            "status": "FAIL",
        }]
```

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**scp2801**
- GitHub: [@scp2801](https://github.com/scp2801)
- Framework: [owaspwstg-framework](https://github.com/scp2801/owaspwstg-framework)

---

<div align="center">

**⭐ Star this repo if it helped your bug bounty hunting!**

Made with ❤️ for the security community

</div>
