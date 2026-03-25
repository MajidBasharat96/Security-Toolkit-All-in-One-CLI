#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║          SECURITY TOOLKIT - All-in-One CLI           ║
║    Port Scanner | Hash Gen | Password | WHOIS        ║
╚══════════════════════════════════════════════════════╝
"""

import argparse
import sys
from modules.port_scanner import PortScanner
from modules.hash_generator import HashGenerator
from modules.password_checker import PasswordChecker
from modules.whois_lookup import WhoisLookup

BANNER = """
\033[92m
 ██████╗███████╗ ██████╗    ████████╗ ██████╗  ██████╗ ██╗      ██╗  ██╗██╗████████╗
██╔════╝██╔════╝██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║      ██║ ██╔╝██║╚══██╔══╝
╚█████╗ █████╗  ██║            ██║   ██║   ██║██║   ██║██║      █████╔╝ ██║   ██║
 ╚═══██╗██╔══╝  ██║            ██║   ██║   ██║██║   ██║██║      ██╔═██╗ ██║   ██║
██████╔╝███████╗╚██████╗       ██║   ╚██████╔╝╚██████╔╝███████╗ ██║  ██╗██║   ██║
╚═════╝ ╚══════╝ ╚═════╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝ ╚═╝  ╚═╝╚═╝   ╚═╝
\033[0m
\033[90m         All-in-One Cybersecurity Toolkit | For Educational Purposes Only\033[0m
"""


def build_parser():
    parser = argparse.ArgumentParser(
        prog="toolkit",
        description="Security Toolkit — Port Scanner, Hash Generator, Password Checker, WHOIS Lookup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python toolkit.py scan -t 192.168.1.1 -p 1-1024
  python toolkit.py scan -t example.com --common
  python toolkit.py hash -i "hello world" -a sha256
  python toolkit.py hash -f /path/to/file.txt -a md5
  python toolkit.py password -p "MyP@ssw0rd!"
  python toolkit.py whois -d example.com
        """
    )
    parser.add_argument("--no-banner", action="store_true", help="Suppress the banner")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ── Port Scanner ──────────────────────────────────────────────────────────
    scan_parser = subparsers.add_parser("scan", help="Scan open ports on a host")
    scan_parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    scan_parser.add_argument("-p", "--ports", default="1-1024",
                             help="Port range (e.g. 1-1024) or comma-separated (e.g. 22,80,443)")
    scan_parser.add_argument("--common", action="store_true",
                             help="Scan common ports only (overrides -p)")
    scan_parser.add_argument("--timeout", type=float, default=1.0,
                             help="Socket timeout in seconds (default: 1.0)")
    scan_parser.add_argument("--threads", type=int, default=100,
                             help="Number of threads (default: 100)")
    scan_parser.add_argument("-o", "--output", help="Save results to file")

    # ── Hash Generator ────────────────────────────────────────────────────────
    hash_parser = subparsers.add_parser("hash", help="Generate cryptographic hashes")
    hash_input = hash_parser.add_mutually_exclusive_group(required=True)
    hash_input.add_argument("-i", "--input", help="String to hash")
    hash_input.add_argument("-f", "--file", help="File to hash")
    hash_parser.add_argument(
        "-a", "--algorithm",
        choices=["md5", "sha1", "sha256", "sha512", "sha3_256", "blake2b", "all"],
        default="sha256",
        help="Hash algorithm (default: sha256)"
    )
    hash_parser.add_argument("-o", "--output", help="Save results to file")

    # ── Password Strength ─────────────────────────────────────────────────────
    pwd_parser = subparsers.add_parser("password", help="Check password strength")
    pwd_parser.add_argument("-p", "--password", help="Password to analyse (or omit for prompt)")
    pwd_parser.add_argument("--suggest", action="store_true",
                            help="Suggest a strong password")
    pwd_parser.add_argument("-o", "--output", help="Save results to file")

    # ── WHOIS Lookup ──────────────────────────────────────────────────────────
    whois_parser = subparsers.add_parser("whois", help="Perform WHOIS domain lookup")
    whois_parser.add_argument("-d", "--domain", required=True, help="Domain to look up")
    whois_parser.add_argument("-o", "--output", help="Save results to file")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        scanner = PortScanner(args.target, args.ports, args.common,
                              args.timeout, args.threads)
        scanner.run(output_file=args.output)

    elif args.command == "hash":
        gen = HashGenerator(args.algorithm)
        if args.input:
            gen.hash_string(args.input, output_file=args.output)
        else:
            gen.hash_file(args.file, output_file=args.output)

    elif args.command == "password":
        checker = PasswordChecker()
        if args.suggest:
            checker.suggest_password()
        else:
            pwd = args.password or checker.prompt_hidden()
            checker.analyse(pwd, output_file=args.output)

    elif args.command == "whois":
        lookup = WhoisLookup(args.domain)
        lookup.run(output_file=args.output)


if __name__ == "__main__":
    main()
