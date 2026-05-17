# OWASP WSTG Coverage Map

Complete mapping of automated test coverage against OWASP WSTG v4.2

## Coverage Summary

| Category | Total Tests | Automated | Manual Required |
|----------|-------------|-----------|-----------------|
| INFO | 10 | 8 | 2 |
| CONF | 12 | 10 | 2 |
| IDNT | 5 | 2 | 3 |
| ATHN | 10 | 5 | 5 |
| AUTHZ | 4 | 2 | 2 |
| SESS | 10 | 7 | 3 |
| INPV | 19 | 8 | 11 |
| ERRH | 2 | 2 | 0 |
| CRYP | 4 | 3 | 1 |
| BUSL | 9 | 0 | 9 |
| CLNT | 14 | 8 | 6 |
| APIT | 1 | 1 | 0 |

## Automated Coverage Detail

### WSTG-INFO (Information Gathering)
- ✅ WSTG-INFO-01: Search engine discovery (passive recon)
- ✅ WSTG-INFO-02: Web server fingerprinting (headers, banners)
- ✅ WSTG-INFO-03: Robots.txt & sitemap analysis
- ✅ WSTG-INFO-04: Application enumeration (live hosts)
- ✅ WSTG-INFO-05: JS secrets & sensitive data in source
- ✅ WSTG-INFO-06: Entry point identification (crawling)
- ✅ WSTG-INFO-07: Execution path mapping (crawling)
- ✅ WSTG-INFO-08: Framework fingerprinting (tech detection)
- ⚠️ WSTG-INFO-09: Application fingerprinting (partial)
- ✅ WSTG-INFO-10: Architecture mapping (live hosts)

### WSTG-CONF (Configuration Management)
- ⚠️ WSTG-CONF-01: Network infrastructure (partial)
- ✅ WSTG-CONF-02: Platform configuration (headers)
- ✅ WSTG-CONF-03: File extension handling
- ✅ WSTG-CONF-04: Backup/unreferenced files
- ✅ WSTG-CONF-05: Admin interfaces enumeration
- ✅ WSTG-CONF-06: HTTP methods
- ✅ WSTG-CONF-07: HSTS testing
- ✅ WSTG-CONF-08: Cross-domain policy
- ⚠️ WSTG-CONF-09: File permissions (partial)
- ✅ WSTG-CONF-10: Subdomain takeover
- ✅ WSTG-CONF-11: Cloud storage exposure
- ✅ WSTG-CONF-12: Content Security Policy

### WSTG-ATHN (Authentication)
- ✅ WSTG-ATHN-01: Credentials over HTTP
- ✅ WSTG-ATHN-02: Default credentials (passive)
- ✅ WSTG-ATHN-03: Lockout mechanism (detect)
- ⚠️ WSTG-ATHN-04: Auth bypass (partial)
- ✅ WSTG-ATHN-05: Remember password
- ✅ WSTG-ATHN-06: Browser cache weaknesses

### WSTG-SESS (Session Management)
- ✅ WSTG-SESS-01: Session schema analysis
- ✅ WSTG-SESS-02: Cookie attributes
- ✅ WSTG-SESS-03: Session fixation (detect)
- ✅ WSTG-SESS-04: Session variable exposure
- ✅ WSTG-SESS-05: CSRF detection
- ✅ WSTG-SESS-06: Logout functionality
- ✅ WSTG-SESS-10: JWT testing

### WSTG-INPV (Input Validation)
- ✅ WSTG-INPV-01: Reflected XSS
- ✅ WSTG-INPV-02: Stored XSS (detect)
- ✅ WSTG-INPV-03: HTTP verb tampering
- ✅ WSTG-INPV-04: HTTP parameter pollution
- ✅ WSTG-INPV-05: SQL Injection
- ✅ WSTG-INPV-17: Host header injection
- ✅ WSTG-INPV-18: SSTI (detect)
- ✅ WSTG-INPV-19: SSRF

### WSTG-CLNT (Client-Side)
- ✅ WSTG-CLNT-01: DOM XSS patterns
- ✅ WSTG-CLNT-03: HTML injection
- ✅ WSTG-CLNT-04: Open redirect
- ✅ WSTG-CLNT-07: CORS misconfiguration
- ✅ WSTG-CLNT-09: Clickjacking
- ✅ WSTG-CLNT-12: Browser storage
- ✅ WSTG-CLNT-13: Mixed content
- ✅ WSTG-CLNT-14: Reverse tabnabbing

### WSTG-APIT (API Testing)
- ✅ WSTG-APIT-01: GraphQL security

---

> Legend: ✅ Fully automated | ⚠️ Partial | ❌ Manual only
