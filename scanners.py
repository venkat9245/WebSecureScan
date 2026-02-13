#!/usr/bin/env python3

import requests
import urllib3
from urllib.parse import urljoin
import json
import os
from datetime import datetime

# Disable SSL warnings (since verify can be False)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WebScanner:
    def __init__(self, target, config, output_dir=None):
        self.target = target.rstrip('/')
        self.config = config
        self.session = requests.Session()
        self.session.verify = config.get("verify_ssl", False)

        self.results = {
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "issues": [],
            "info": {}
        }

        self.output_dir = output_dir or "scan_results"

    # -----------------------------
    # Log Issue
    # -----------------------------
    def log_issue(self, category, severity, title, description, evidence=None):
        severity = severity.lower().strip()

        issue = {
            "category": category,
            "severity": severity,
            "title": title,
            "description": description,
            "evidence": evidence or {}
        }

        self.results["issues"].append(issue)

        print(f"[{severity.upper()}] {title}")

    # -----------------------------
    # Save Results
    # -----------------------------
    def save_results(self):
        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        json_file = f"{self.output_dir}/webscan_{timestamp}.json"
        with open(json_file, "w") as f:
            json.dump(self.results, f, indent=2)

        print(f"[+] Results saved: {json_file}")

        severity_order = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1
        }

        txt_file = f"{self.output_dir}/webscan_{timestamp}.txt"
        with open(txt_file, "w") as f:
            f.write(f"WebSecureScan Results - {self.target}\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Scan Time: {self.results['timestamp']}\n")
            f.write(f"Total Issues: {len(self.results['issues'])}\n\n")

            for issue in sorted(
                self.results["issues"],
                key=lambda x: severity_order.get(x["severity"], 0),
                reverse=True
            ):
                f.write(f"[{issue['severity'].upper()}] {issue['title']}\n")
                f.write(f"  Category: {issue['category']}\n")
                f.write(f"  Description: {issue['description']}\n")
                if issue["evidence"]:
                    f.write(f"  Evidence: {issue['evidence']}\n")
                f.write("\n")

        print(f"[+] Text report: {txt_file}")

    # -----------------------------
    # Make HTTP Request
    # -----------------------------
    def make_request(self, url, method="GET", **kwargs):
        try:
            kwargs.setdefault("timeout", (self.config["timeout"], 30))
            return self.session.request(method, url, **kwargs)
        except requests.exceptions.RequestException:
            return None

    # -----------------------------
    # Check Security Headers
    # -----------------------------
    def check_security_headers(self):
        print("[*] Checking security headers...")
        resp = self.make_request(self.target)
        if not resp:
            return

        headers = resp.headers

        required_headers = [
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "Referrer-Policy"
        ]

        missing = [h for h in required_headers if h not in headers]

        if missing:
            self.log_issue(
                "security_headers",
                "medium",
                "Missing Security Headers",
                f"Missing headers: {', '.join(missing)}",
                {"missing_headers": missing}
            )

        if "X-Powered-By" in headers:
            self.log_issue(
                "info_disclosure",
                "low",
                "Technology Disclosure",
                "X-Powered-By header exposed",
                {"value": headers["X-Powered-By"]}
            )

    # -----------------------------
    # Check Common Vulnerabilities
    # -----------------------------
    def check_common_vulns(self):
        print("[*] Testing common vulnerabilities...")

        tests = {
            "XSS": "/?q=<script>alert(1337)</script>",
            "SQLi": "/?id=1' OR '1'='1",
            "LFI": "/?file=../../../../etc/passwd"
        }

        sql_errors = [
            "sql syntax",
            "mysql",
            "syntax error",
            "warning: mysql",
            "unclosed quotation mark",
            "pdoexception"
        ]

        for name, path in tests.items():
            test_url = urljoin(self.target, path)
            resp = self.make_request(test_url)

            if not resp:
                continue

            body = resp.text.lower()

            # Reflected XSS
            if name == "XSS":
                if "<script>alert(1337)</script>" in resp.text:
                    self.log_issue(
                        "injection",
                        "high",
                        "Reflected XSS Detected",
                        "Payload reflected in response",
                        {"url": test_url}
                    )

            # SQL Error Detection
            elif name == "SQLi":
                if any(err in body for err in sql_errors):
                    self.log_issue(
                        "injection",
                        "high",
                        "SQL Injection Error Detected",
                        "Database error message found in response",
                        {"url": test_url}
                    )

            # LFI Detection
            elif name == "LFI":
                if "root:x:" in body:
                    self.log_issue(
                        "injection",
                        "high",
                        "Local File Inclusion Detected",
                        "/etc/passwd exposed",
                        {"url": test_url}
                    )

    # -----------------------------
    # Check SSL
    # -----------------------------
    def check_ssl(self):
        print("[*] Checking SSL...")

        if not self.target.startswith("https"):
            self.log_issue(
                "ssl",
                "medium",
                "HTTP Only",
                "Target is not using HTTPS"
            )

    # -----------------------------
    # Fingerprint Technology
    # -----------------------------
    def fingerprint_tech(self):
        print("[*] Fingerprinting technologies...")
        resp = self.make_request(self.target)
        if not resp:
            return

        server = resp.headers.get("Server", "Unknown")
        self.results["info"]["server"] = server
        print(f"[+] Server: {server}")

    # -----------------------------
    # Run Full Scan
    # -----------------------------
    def run_full_scan(self):
        print("[+] Running full security assessment...\n")

        self.check_security_headers()
        print()

        self.fingerprint_tech()
        print()

        self.check_ssl()
        print()

        self.check_common_vulns()
        print()

        self.save_results()

        print(f"\n[+] Scan complete! Found {len(self.results['issues'])} issues")
