"""
WHOIS Lookup Module
--------------------
Performs domain WHOIS lookups via raw TCP socket (port 43)
with IANA bootstrap to find the correct WHOIS server.
"""

import socket
import re
from datetime import datetime
from typing import Optional

C_GREEN  = "\033[92m"
C_RED    = "\033[91m"
C_YELLOW = "\033[93m"
C_CYAN   = "\033[96m"
C_GRAY   = "\033[90m"
C_BOLD   = "\033[1m"
C_RESET  = "\033[0m"

# TLD → WHOIS server map (common TLDs)
TLD_SERVERS = {
    "com":  "whois.verisign-grs.com",
    "net":  "whois.verisign-grs.com",
    "org":  "whois.pir.org",
    "io":   "whois.nic.io",
    "co":   "whois.nic.co",
    "uk":   "whois.nic.uk",
    "de":   "whois.denic.de",
    "fr":   "whois.nic.fr",
    "nl":   "whois.domain-registry.nl",
    "eu":   "whois.eu",
    "au":   "whois.auda.org.au",
    "ca":   "whois.cira.ca",
    "jp":   "whois.jprs.jp",
    "cn":   "whois.cnnic.cn",
    "in":   "whois.registry.in",
    "br":   "whois.registro.br",
    "ru":   "whois.tcinet.ru",
    "info": "whois.afilias.net",
    "biz":  "whois.biz",
    "mobi": "whois.dotmobiregistry.net",
    "name": "whois.nic.name",
    "pro":  "whois.registrypro.pro",
    "tv":   "tvwhois.verisign-grs.com",
    "cc":   "ccwhois.verisign-grs.com",
    "ws":   "whois.website.ws",
    "us":   "whois.nic.us",
    "me":   "whois.nic.me",
    "ly":   "whois.nic.ly",
    "app":  "whois.nic.app",
    "dev":  "whois.nic.dev",
    "ai":   "whois.nic.ai",
    "pk":   "whois.pknic.net.pk",
}

EXTRACT_FIELDS = [
    ("Registrant", r'(?i)registrant(?:\s+name)?:\s*(.+)'),
    ("Registrar",  r'(?i)registrar:\s*(.+)'),
    ("Created",    r'(?i)creat(?:ion date|ed):\s*(.+)'),
    ("Expires",    r'(?i)expir(?:y|ation) date:\s*(.+)'),
    ("Updated",    r'(?i)updated? date:\s*(.+)'),
    ("Name Servers", r'(?i)name server:\s*(.+)'),
    ("Status",     r'(?i)domain status:\s*(.+)'),
    ("DNSSEC",     r'(?i)dnssec:\s*(.+)'),
]


class WhoisLookup:
    def __init__(self, domain: str):
        self.domain = domain.lower().strip()

    # ── WHOIS query ───────────────────────────────────────────────────────────

    def _get_whois_server(self) -> str:
        tld = self.domain.rsplit(".", 1)[-1]
        return TLD_SERVERS.get(tld, "whois.iana.org")

    def _query(self, server: str, query: str, timeout: float = 10.0) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((server, 43))
                s.send((query + "\r\n").encode())
                response = b""
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data
                return response.decode(errors="ignore")
        except Exception as e:
            return f"ERROR: {e}"

    def _follow_referral(self, raw: str) -> Optional[str]:
        """Check if IANA returned a referral to another WHOIS server."""
        m = re.search(r'(?i)whois:\s+(\S+)', raw)
        return m.group(1) if m else None

    # ── Parsing ───────────────────────────────────────────────────────────────

    @staticmethod
    def _extract(raw: str) -> dict:
        result = {}
        for label, pattern in EXTRACT_FIELDS:
            matches = re.findall(pattern, raw)
            if matches:
                vals = [m.strip() for m in matches if m.strip()]
                result[label] = vals if len(vals) > 1 else vals[0]
        return result

    # ── DNS resolution ────────────────────────────────────────────────────────

    def _resolve_dns(self) -> Optional[str]:
        try:
            return socket.gethostbyname(self.domain)
        except Exception:
            return None

    # ── Run ───────────────────────────────────────────────────────────────────

    def run(self, output_file: Optional[str] = None):
        print(f"{C_CYAN}{C_BOLD}[ WHOIS LOOKUP ]{C_RESET}")
        print(f"{C_GRAY}{'─' * 55}{C_RESET}")
        print(f"  Domain    : {C_YELLOW}{self.domain}{C_RESET}")
        print(f"  Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # DNS resolution
        ip = self._resolve_dns()
        if ip:
            print(f"  Resolves  : {C_GREEN}{ip}{C_RESET}")
        else:
            print(f"  Resolves  : {C_RED}Could not resolve{C_RESET}")

        print(f"{C_GRAY}{'─' * 55}{C_RESET}\n")

        # WHOIS query
        server = self._get_whois_server()
        print(f"  {C_GRAY}Querying {server} …{C_RESET}")
        raw = self._query(server, self.domain)

        if raw.startswith("ERROR"):
            print(f"\n  {C_RED}✗ {raw}{C_RESET}")
            return

        # Follow IANA referral
        referral = self._follow_referral(raw)
        if referral and referral != server:
            print(f"  {C_GRAY}Referral → {referral}{C_RESET}")
            raw2 = self._query(referral, self.domain)
            if not raw2.startswith("ERROR"):
                raw = raw2

        parsed = self._extract(raw)

        if not parsed:
            print(f"\n  {C_YELLOW}⚠  No structured data found. Raw response:{C_RESET}\n")
            print(f"{C_GRAY}")
            for line in raw.splitlines()[:40]:
                print(f"  {line}")
            print(C_RESET)
        else:
            print()
            for label, value in parsed.items():
                if isinstance(value, list):
                    print(f"  {C_BOLD}{label:<14}{C_RESET}")
                    for v in value[:5]:
                        print(f"    {C_GREEN}•{C_RESET} {v}")
                else:
                    print(f"  {C_BOLD}{label:<14}{C_RESET} {value}")
            print()

        if output_file:
            self._save(output_file, raw, parsed, ip)

    def _save(self, path: str, raw: str, parsed: dict, ip: Optional[str]):
        lines = [
            f"WHOIS Report — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Domain  : {self.domain}",
            f"IP      : {ip or 'N/A'}",
            "─" * 40,
        ]
        for k, v in parsed.items():
            if isinstance(v, list):
                lines.append(f"{k}:")
                lines += [f"  • {x}" for x in v]
            else:
                lines.append(f"{k:<14} {v}")
        lines += ["\n─── Raw WHOIS ───\n", raw]
        with open(path, "w") as f:
            f.write("\n".join(lines))
        print(f"  {C_CYAN}Results saved → {path}{C_RESET}")
