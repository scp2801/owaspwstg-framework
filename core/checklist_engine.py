"""
OWASP WSTG Checklist Engine
============================
Maps scan results to OWASP WSTG test IDs.
Maintains checklist state: PASS / FAIL / REVIEW / NOT_TESTED.
Full WSTG v4.2 checklist included.
"""

from typing import Dict, List, Any, Optional
from enum import Enum
from datetime import datetime


class ChecklistStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    REVIEW = "REVIEW"
    NOT_TESTED = "NOT_TESTED"
    NOT_APPLICABLE = "N/A"


# Full OWASP WSTG v4.2 Checklist
WSTG_CHECKLIST = [
    # ── INFO ──────────────────────────────────────────────────────────
    {"id": "WSTG-INFO-01", "category": "Information Gathering", "name": "Conduct Search Engine Discovery", "severity": "Info"},
    {"id": "WSTG-INFO-02", "category": "Information Gathering", "name": "Fingerprint Web Server", "severity": "Info"},
    {"id": "WSTG-INFO-03", "category": "Information Gathering", "name": "Review Webserver Metafiles for Information Leakage", "severity": "Low"},
    {"id": "WSTG-INFO-04", "category": "Information Gathering", "name": "Enumerate Applications on Webserver", "severity": "Info"},
    {"id": "WSTG-INFO-05", "category": "Information Gathering", "name": "Review Webpage Content for Information Leakage", "severity": "Info"},
    {"id": "WSTG-INFO-06", "category": "Information Gathering", "name": "Identify Application Entry Points", "severity": "Info"},
    {"id": "WSTG-INFO-07", "category": "Information Gathering", "name": "Map Execution Paths Through Application", "severity": "Info"},
    {"id": "WSTG-INFO-08", "category": "Information Gathering", "name": "Fingerprint Web Application Framework", "severity": "Info"},
    {"id": "WSTG-INFO-09", "category": "Information Gathering", "name": "Fingerprint Web Application", "severity": "Info"},
    {"id": "WSTG-INFO-10", "category": "Information Gathering", "name": "Map Application Architecture", "severity": "Info"},

    # ── CONF ──────────────────────────────────────────────────────────
    {"id": "WSTG-CONF-01", "category": "Configuration Management", "name": "Test Network Infrastructure Configuration", "severity": "Medium"},
    {"id": "WSTG-CONF-02", "category": "Configuration Management", "name": "Test Application Platform Configuration", "severity": "Medium"},
    {"id": "WSTG-CONF-03", "category": "Configuration Management", "name": "Test File Extension Handling for Sensitive Information", "severity": "Medium"},
    {"id": "WSTG-CONF-04", "category": "Configuration Management", "name": "Review Old Backup and Unreferenced Files", "severity": "Medium"},
    {"id": "WSTG-CONF-05", "category": "Configuration Management", "name": "Enumerate Infrastructure and Application Admin Interfaces", "severity": "High"},
    {"id": "WSTG-CONF-06", "category": "Configuration Management", "name": "Test HTTP Methods", "severity": "Medium"},
    {"id": "WSTG-CONF-07", "category": "Configuration Management", "name": "Test HTTP Strict Transport Security", "severity": "Medium"},
    {"id": "WSTG-CONF-08", "category": "Configuration Management", "name": "Test RIA Cross Domain Policy", "severity": "Medium"},
    {"id": "WSTG-CONF-09", "category": "Configuration Management", "name": "Test File Permission", "severity": "Medium"},
    {"id": "WSTG-CONF-10", "category": "Configuration Management", "name": "Test for Subdomain Takeover", "severity": "High"},
    {"id": "WSTG-CONF-11", "category": "Configuration Management", "name": "Test Cloud Storage", "severity": "High"},
    {"id": "WSTG-CONF-12", "category": "Configuration Management", "name": "Test for Content Security Policy", "severity": "Medium"},

    # ── IDNT ──────────────────────────────────────────────────────────
    {"id": "WSTG-IDNT-01", "category": "Identity Management", "name": "Test Role Definitions", "severity": "Medium"},
    {"id": "WSTG-IDNT-02", "category": "Identity Management", "name": "Test User Registration Process", "severity": "Medium"},
    {"id": "WSTG-IDNT-03", "category": "Identity Management", "name": "Test Account Provisioning Process", "severity": "Medium"},
    {"id": "WSTG-IDNT-04", "category": "Identity Management", "name": "Testing for Account Enumeration and Guessable User Account", "severity": "Medium"},
    {"id": "WSTG-IDNT-05", "category": "Identity Management", "name": "Testing for Weak or Unenforced Username Policy", "severity": "Low"},

    # ── ATHN ──────────────────────────────────────────────────────────
    {"id": "WSTG-ATHN-01", "category": "Authentication", "name": "Testing for Credentials Transported over an Encrypted Channel", "severity": "High"},
    {"id": "WSTG-ATHN-02", "category": "Authentication", "name": "Testing for Default Credentials", "severity": "High"},
    {"id": "WSTG-ATHN-03", "category": "Authentication", "name": "Testing for Weak Lock Out Mechanism", "severity": "Medium"},
    {"id": "WSTG-ATHN-04", "category": "Authentication", "name": "Testing for Bypassing Authentication Schema", "severity": "Critical"},
    {"id": "WSTG-ATHN-05", "category": "Authentication", "name": "Testing for Vulnerable Remember Password", "severity": "Medium"},
    {"id": "WSTG-ATHN-06", "category": "Authentication", "name": "Testing for Browser Cache Weaknesses", "severity": "Low"},
    {"id": "WSTG-ATHN-07", "category": "Authentication", "name": "Testing for Weak Password Policy", "severity": "Medium"},
    {"id": "WSTG-ATHN-08", "category": "Authentication", "name": "Testing for Weak Security Question Answer", "severity": "Medium"},
    {"id": "WSTG-ATHN-09", "category": "Authentication", "name": "Testing for Weak Password Change or Reset Functionalities", "severity": "High"},
    {"id": "WSTG-ATHN-10", "category": "Authentication", "name": "Testing for Weaker Authentication in Alternative Channel", "severity": "Medium"},

    # ── AUTHZ ──────────────────────────────────────────────────────────
    {"id": "WSTG-AUTHZ-01", "category": "Authorization", "name": "Testing Directory Traversal File Include", "severity": "High"},
    {"id": "WSTG-AUTHZ-02", "category": "Authorization", "name": "Testing for Bypassing Authorization Schema", "severity": "Critical"},
    {"id": "WSTG-AUTHZ-03", "category": "Authorization", "name": "Testing for Privilege Escalation", "severity": "High"},
    {"id": "WSTG-AUTHZ-04", "category": "Authorization", "name": "Testing for Insecure Direct Object References (IDOR)", "severity": "High"},

    # ── SESS ──────────────────────────────────────────────────────────
    {"id": "WSTG-SESS-01", "category": "Session Management", "name": "Testing for Session Management Schema", "severity": "High"},
    {"id": "WSTG-SESS-02", "category": "Session Management", "name": "Testing for Cookies Attributes", "severity": "Medium"},
    {"id": "WSTG-SESS-03", "category": "Session Management", "name": "Testing for Session Fixation", "severity": "High"},
    {"id": "WSTG-SESS-04", "category": "Session Management", "name": "Testing for Exposed Session Variables", "severity": "High"},
    {"id": "WSTG-SESS-05", "category": "Session Management", "name": "Testing for Cross Site Request Forgery (CSRF)", "severity": "High"},
    {"id": "WSTG-SESS-06", "category": "Session Management", "name": "Testing for Logout Functionality", "severity": "Medium"},
    {"id": "WSTG-SESS-07", "category": "Session Management", "name": "Testing Session Timeout", "severity": "Medium"},
    {"id": "WSTG-SESS-08", "category": "Session Management", "name": "Testing for Session Puzzling", "severity": "Medium"},
    {"id": "WSTG-SESS-09", "category": "Session Management", "name": "Testing for Session Hijacking", "severity": "High"},
    {"id": "WSTG-SESS-10", "category": "Session Management", "name": "Testing JSON Web Tokens", "severity": "High"},

    # ── INPV ──────────────────────────────────────────────────────────
    {"id": "WSTG-INPV-01", "category": "Input Validation", "name": "Testing for Reflected Cross Site Scripting (XSS)", "severity": "High"},
    {"id": "WSTG-INPV-02", "category": "Input Validation", "name": "Testing for Stored Cross Site Scripting (XSS)", "severity": "Critical"},
    {"id": "WSTG-INPV-03", "category": "Input Validation", "name": "Testing for HTTP Verb Tampering", "severity": "Medium"},
    {"id": "WSTG-INPV-04", "category": "Input Validation", "name": "Testing for HTTP Parameter Pollution", "severity": "Medium"},
    {"id": "WSTG-INPV-05", "category": "Input Validation", "name": "Testing for SQL Injection", "severity": "Critical"},
    {"id": "WSTG-INPV-06", "category": "Input Validation", "name": "Testing for LDAP Injection", "severity": "High"},
    {"id": "WSTG-INPV-07", "category": "Input Validation", "name": "Testing for XML Injection", "severity": "High"},
    {"id": "WSTG-INPV-08", "category": "Input Validation", "name": "Testing for SSI Injection", "severity": "High"},
    {"id": "WSTG-INPV-09", "category": "Input Validation", "name": "Testing for XPath Injection", "severity": "High"},
    {"id": "WSTG-INPV-10", "category": "Input Validation", "name": "Testing for IMAP SMTP Injection", "severity": "High"},
    {"id": "WSTG-INPV-11", "category": "Input Validation", "name": "Testing for Code Injection", "severity": "Critical"},
    {"id": "WSTG-INPV-12", "category": "Input Validation", "name": "Testing for Command Injection", "severity": "Critical"},
    {"id": "WSTG-INPV-13", "category": "Input Validation", "name": "Testing for Format String Injection", "severity": "High"},
    {"id": "WSTG-INPV-14", "category": "Input Validation", "name": "Testing for Incubated Vulnerability", "severity": "High"},
    {"id": "WSTG-INPV-15", "category": "Input Validation", "name": "Testing for HTTP Splitting Smuggling", "severity": "High"},
    {"id": "WSTG-INPV-16", "category": "Input Validation", "name": "Testing for HTTP Incoming Requests", "severity": "Medium"},
    {"id": "WSTG-INPV-17", "category": "Input Validation", "name": "Testing for Host Header Injection", "severity": "Medium"},
    {"id": "WSTG-INPV-18", "category": "Input Validation", "name": "Testing for Server Side Template Injection (SSTI)", "severity": "Critical"},
    {"id": "WSTG-INPV-19", "category": "Input Validation", "name": "Testing for Server-Side Request Forgery (SSRF)", "severity": "High"},

    # ── ERRH ──────────────────────────────────────────────────────────
    {"id": "WSTG-ERRH-01", "category": "Error Handling", "name": "Testing for Improper Error Handling", "severity": "Low"},
    {"id": "WSTG-ERRH-02", "category": "Error Handling", "name": "Testing for Stack Traces", "severity": "Low"},

    # ── CRYP ──────────────────────────────────────────────────────────
    {"id": "WSTG-CRYP-01", "category": "Cryptography", "name": "Testing for Weak Transport Layer Security", "severity": "High"},
    {"id": "WSTG-CRYP-02", "category": "Cryptography", "name": "Testing for Padding Oracle", "severity": "High"},
    {"id": "WSTG-CRYP-03", "category": "Cryptography", "name": "Testing for Sensitive Information Sent via Unencrypted Channels", "severity": "High"},
    {"id": "WSTG-CRYP-04", "category": "Cryptography", "name": "Testing for Weak Encryption", "severity": "High"},

    # ── BUSL ──────────────────────────────────────────────────────────
    {"id": "WSTG-BUSL-01", "category": "Business Logic", "name": "Test Business Logic Data Validation", "severity": "Medium"},
    {"id": "WSTG-BUSL-02", "category": "Business Logic", "name": "Test Ability to Forge Requests", "severity": "Medium"},
    {"id": "WSTG-BUSL-03", "category": "Business Logic", "name": "Test Integrity Checks", "severity": "Medium"},
    {"id": "WSTG-BUSL-04", "category": "Business Logic", "name": "Test for Process Timing", "severity": "Medium"},
    {"id": "WSTG-BUSL-05", "category": "Business Logic", "name": "Test Number of Times a Function Can Be Used Limits", "severity": "Medium"},
    {"id": "WSTG-BUSL-06", "category": "Business Logic", "name": "Testing for the Circumvention of Workflows", "severity": "Medium"},
    {"id": "WSTG-BUSL-07", "category": "Business Logic", "name": "Test Defenses Against Application Mis-use", "severity": "Medium"},
    {"id": "WSTG-BUSL-08", "category": "Business Logic", "name": "Test Upload of Unexpected File Types", "severity": "High"},
    {"id": "WSTG-BUSL-09", "category": "Business Logic", "name": "Test Upload of Malicious Files", "severity": "High"},

    # ── CLNT ──────────────────────────────────────────────────────────
    {"id": "WSTG-CLNT-01", "category": "Client-Side", "name": "Testing for DOM Based Cross Site Scripting (DOM XSS)", "severity": "High"},
    {"id": "WSTG-CLNT-02", "category": "Client-Side", "name": "Testing for JavaScript Execution", "severity": "High"},
    {"id": "WSTG-CLNT-03", "category": "Client-Side", "name": "Testing for HTML Injection", "severity": "Medium"},
    {"id": "WSTG-CLNT-04", "category": "Client-Side", "name": "Testing for Client Side URL Redirect", "severity": "Medium"},
    {"id": "WSTG-CLNT-05", "category": "Client-Side", "name": "Testing for CSS Injection", "severity": "Medium"},
    {"id": "WSTG-CLNT-06", "category": "Client-Side", "name": "Testing for Client Side Resource Manipulation", "severity": "Medium"},
    {"id": "WSTG-CLNT-07", "category": "Client-Side", "name": "Test Cross Origin Resource Sharing (CORS)", "severity": "High"},
    {"id": "WSTG-CLNT-08", "category": "Client-Side", "name": "Testing for Cross Site Flashing", "severity": "Medium"},
    {"id": "WSTG-CLNT-09", "category": "Client-Side", "name": "Testing for Clickjacking", "severity": "Medium"},
    {"id": "WSTG-CLNT-10", "category": "Client-Side", "name": "Testing WebSockets", "severity": "Medium"},
    {"id": "WSTG-CLNT-11", "category": "Client-Side", "name": "Testing Web Messaging", "severity": "Medium"},
    {"id": "WSTG-CLNT-12", "category": "Client-Side", "name": "Testing Browser Storage", "severity": "Low"},
    {"id": "WSTG-CLNT-13", "category": "Client-Side", "name": "Testing for Cross Site Script Inclusion (XSSI)", "severity": "Medium"},
    {"id": "WSTG-CLNT-14", "category": "Client-Side", "name": "Testing for Reverse Tabnabbing", "severity": "Low"},

    # ── APIT ──────────────────────────────────────────────────────────
    {"id": "WSTG-APIT-01", "category": "API Testing", "name": "Testing GraphQL", "severity": "High"},
]


class ChecklistEngine:
    """
    Manages OWASP WSTG checklist state and result mapping.
    Tracks test results and generates checklist summaries.
    """

    def __init__(self):
        # Initialize all tests as NOT_TESTED
        self.checklist: Dict[str, Dict] = {}
        for item in WSTG_CHECKLIST:
            self.checklist[item["id"]] = {
                **item,
                "status": ChecklistStatus.NOT_TESTED,
                "evidence": [],
                "urls": [],
                "notes": "",
                "recommendations": "",
                "tested_at": None,
                "cwe": "",
                "cvss": "",
            }

    def update(
        self,
        wstg_id: str,
        status: ChecklistStatus,
        evidence: str = "",
        url: str = "",
        notes: str = "",
        recommendation: str = "",
        cwe: str = "",
        cvss: str = "",
    ):
        """
        Update a WSTG checklist item with test results.

        Args:
            wstg_id: WSTG test ID (e.g., 'WSTG-INPV-01')
            status: ChecklistStatus enum value
            evidence: Evidence string or description
            url: Affected URL
            notes: Additional notes
            recommendation: Remediation recommendation
            cwe: CWE identifier
            cvss: CVSS score
        """
        if wstg_id not in self.checklist:
            return

        item = self.checklist[wstg_id]
        item["status"] = status
        item["tested_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if evidence:
            item["evidence"].append(evidence)
        if url and url not in item["urls"]:
            item["urls"].append(url)
        if notes:
            item["notes"] = notes
        if recommendation:
            item["recommendations"] = recommendation
        if cwe:
            item["cwe"] = cwe
        if cvss:
            item["cvss"] = cvss

    def mark_pass(self, wstg_id: str, url: str = "", notes: str = ""):
        """Mark a test as passed."""
        self.update(wstg_id, ChecklistStatus.PASS, url=url, notes=notes)

    def mark_fail(self, wstg_id: str, evidence: str = "", url: str = "",
                  notes: str = "", recommendation: str = "", cwe: str = "", cvss: str = ""):
        """Mark a test as failed (vulnerability found)."""
        self.update(wstg_id, ChecklistStatus.FAIL, evidence=evidence,
                    url=url, notes=notes, recommendation=recommendation,
                    cwe=cwe, cvss=cvss)

    def mark_review(self, wstg_id: str, evidence: str = "", url: str = "", notes: str = ""):
        """Mark a test as needing manual review."""
        self.update(wstg_id, ChecklistStatus.REVIEW, evidence=evidence, url=url, notes=notes)

    def get_summary(self) -> Dict[str, Any]:
        """Generate checklist summary statistics."""
        status_counts = {s.value: 0 for s in ChecklistStatus}
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

        for item in self.checklist.values():
            status_counts[item["status"].value if hasattr(item["status"], "value") else item["status"]] += 1

        failures = [i for i in self.checklist.values()
                    if (i["status"].value if hasattr(i["status"], "value") else i["status"]) == "FAIL"]

        for f in failures:
            sev = f.get("severity", "Info")
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            "total": len(self.checklist),
            "status_counts": status_counts,
            "severity_counts": severity_counts,
            "failures": failures,
            "pass_rate": round(status_counts["PASS"] / max(len(self.checklist), 1) * 100, 1),
        }

    def get_all(self) -> List[Dict]:
        """Return all checklist items as list."""
        return list(self.checklist.values())

    def get_failures(self) -> List[Dict]:
        """Return only failed checklist items."""
        return [i for i in self.checklist.values()
                if (i["status"].value if hasattr(i["status"], "value") else i["status"]) == "FAIL"]

    def get_by_category(self) -> Dict[str, List[Dict]]:
        """Group checklist items by category."""
        categories: Dict[str, List] = {}
        for item in self.checklist.values():
            cat = item["category"]
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(item)
        return categories
