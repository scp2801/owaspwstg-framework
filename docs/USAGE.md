# OWASP WSTG Framework - Detailed Usage Guide

## Table of Contents
1. [Basic Usage](#basic-usage)
2. [Scan Profiles](#scan-profiles)
3. [Scope Files](#scope-files)
4. [Output Formats](#output-formats)
5. [Configuration](#configuration)
6. [Module Reference](#module-reference)
7. [Troubleshooting](#troubleshooting)

---

## Basic Usage

```bash
# Activate virtual environment first
source venv/bin/activate

# Simplest scan
python3 main.py scan example.com

# Scan with specific output directory
python3 main.py scan example.com -o /tmp/results

# Scan with all report formats
python3 main.py scan example.com --format all

# Only reconnaissance phase
python3 main.py recon example.com

# Check tool availability
python3 main.py check
```

---

## Scan Profiles

### Default Profile
```bash
python3 main.py scan example.com --profile default
# Threads: 10 | Timeout: 30s | Rate: 50 req/s
```

### Fast Profile (Quick Overview)
```bash
python3 main.py scan example.com --profile fast
# Threads: 25 | Timeout: 10s | Rate: 100 req/s
# Crawl depth: 1 | Max pages: 100
```

### Deep Profile (Thorough)
```bash
python3 main.py scan example.com --profile deep
# Threads: 5 | Timeout: 60s | Rate: 10 req/s
# Crawl depth: 5 | Max pages: 2000
```

### Stealth Profile (Low & Slow)
```bash
python3 main.py scan example.com --profile stealth
# Threads: 2 | Timeout: 45s | Rate: 5 req/s
# Delay: 2 seconds between requests
```

---

## Scope Files

Create a `scope.txt` file:
```text
# Lines starting with # are comments
example.com
*.example.com
api.example.com
https://shop.example.com
```

Run with scope file:
```bash
python3 main.py scan example.com --scope-file scope.txt
```

---

## Output Formats

```bash
# All formats
python3 main.py scan example.com --format all

# Only Excel checklist
python3 main.py scan example.com --format excel

# Only HTML report
python3 main.py scan example.com --format html

# JSON + Markdown
python3 main.py scan example.com --format json,md
```

**Output Location:** `reports/<domain>_<timestamp>/`

---

## Configuration

Edit `config.yaml` to customize:

```yaml
scan:
  threads: 10         # Concurrent threads
  timeout: 30         # Request timeout
  rate_limit: 50      # Max requests/second

recon:
  max_subdomains: 5000
  sources: [crtsh, alienvault, rapiddns]

vulnerabilities:
  xss: true
  sqli: true
  cors: true
  # Set false to skip a module
```

---

## Module Reference

### Recon Modules
| Module | File | Description |
|--------|------|-------------|
| Subdomain Enum | `modules/recon/subdomain_enum.py` | crt.sh, AlienVault, RapidDNS |
| DNS Enum | `modules/recon/dns_enum.py` | A, AAAA, MX, TXT, CNAME |
| Live Host | `modules/recon/live_host.py` | HTTP probe, tech detection |

### Vulnerability Modules
| Module | WSTG ID | Severity |
|--------|---------|---------|
| XSS | WSTG-INPV-01 | High |
| SQLi | WSTG-INPV-05 | Critical |
| SSRF | WSTG-INPV-19 | Critical |
| CORS | WSTG-CLNT-07 | High |
| JWT | WSTG-SESS-10 | High |
| Security Headers | WSTG-CONF-07 | Medium |
| Clickjacking | WSTG-CLNT-09 | Medium |
| Sensitive Files | WSTG-CONF-04 | Critical |
| Subdomain Takeover | WSTG-CONF-10 | High |

---

## Troubleshooting

### Screenshots not working
```bash
# Install Playwright
playwright install chromium
# Or disable screenshots
python3 main.py scan example.com --no-screenshots
```

### Slow scans
```bash
# Use fast profile
python3 main.py scan example.com --profile fast --threads 25
```

### Missing tool warnings
```bash
# Install ProjectDiscovery tools
./kali_setup.sh  # Kali Linux
# Or check what's available
python3 main.py check
```

### Termux issues
```bash
# Always use --no-screenshots on Termux
python3 main.py scan example.com --no-screenshots
```

---

## Legal Notice

> Only use on systems you have **explicit written permission** to test.
> Follow bug bounty program scope and rules at all times.
