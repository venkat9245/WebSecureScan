
#!/usr/bin/env python3
"""
WebSecureScan v2.0 - Comprehensive Web Security Scanner
Ethical hacking tool for authorized penetration testing
"""

import argparse
import sys
from scanners import WebScanner
from config import CONFIG
print("\n⚠️  This tool is for educational and authorized testing only.")
print("⚠️  Do not scan systems without permission.\n")


def main():
    parser = argparse.ArgumentParser(
        description="WebSecureScan - Ethical Web Security Scanner"
    )

    parser.add_argument(
        "target",
        help="Target URL (http://example.com)"
    )

    parser.add_argument(
        "-o", "--output",
        help="Output directory name"
    )

    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=CONFIG['timeout'],
        help="Connection timeout in seconds"
    )

    args = parser.parse_args()

    # Copy default config
    config = CONFIG.copy()
    config['timeout'] = args.timeout

    print("[*] WebSecureScan v2.0 - Ethical Hacking Tool")
    print(f"[*] Target: {args.target}")
    print(f"[*] Timeout: {config['timeout']}s")

    if args.output:
        print(f"[*] Output: {args.output}")

    try:
        scanner = WebScanner(
            target=args.target,
            config=config,
            output_dir=args.output
        )

        scanner.run_full_scan()

        print("\n[+] Scan completed successfully!")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)

    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
