# WebSecureScan

WebSecureScan is a lightweight educational web security scanner written in Python.

⚠️ **IMPORTANT DISCLAIMER**

This tool is created strictly for:

- Educational purposes
- Learning web security concepts
- Testing applications you own
- Authorized penetration testing environments

🚫 Do NOT scan websites without explicit permission.
Unauthorized scanning may violate laws in your country.

---

## Purpose

WebSecureScan helps learners understand:

- Security headers
- Basic vulnerability detection (XSS, SQLi, LFI)
- HTTP request/response handling
- Severity classification
- Report generation

This tool is NOT an enterprise-grade vulnerability scanner.

---

## Limitations

- No deep crawling
- No authentication support
- Basic detection logic
- May produce false positives
- Not intended for production penetration testing

For professional scanning, use tools like:
- OWASP ZAP
- Burp Suite
- Nuclei
- Nikto

---

## Usage

```bash
python3 websecurescan.py http://example.com -o results
