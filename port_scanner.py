"""
Port Scanner Module
-------------------
Multi-threaded TCP port scanner with service fingerprinting.
"""

import socket
import concurrent.futures
import time
from datetime import datetime
from typing import List, Optional

# Well-known port → service name mapping
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389,
    5900, 8080, 8443, 8888, 27017
]

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Dev", 27017: "MongoDB"
}

C_GREEN  = "\033[92m"
C_RED    = "\033[91m"
C_YELLOW = "\033[93m"
C_CYAN   = "\033[96m"
C_GRAY   = "\033[90m"
C_BOLD   = "\033[1m"
C_RESET  = "\033[0m"


class PortScanner:
    def __init__(self, target: str, port_range: str, use_common: bool,
                 timeout: float, max_threads: int):
        self.target = target
        self.port_range = port_range
        self.use_common = use_common
        self.timeout = timeout
        self.max_threads = max_threads
        self.open_ports: List[dict] = []

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _resolve_target(self) -> Optional[str]:
        try:
            ip = socket.gethostbyname(self.target)
            return ip
        except socket.gaierror:
            return None

    def _parse_ports(self) -> List[int]:
        if self.use_common:
            return COMMON_PORTS
        if "-" in self.port_range:
            start, end = self.port_range.split("-")
            return list(range(int(start), int(end) + 1))
        return [int(p.strip()) for p in self.port_range.split(",")]

    def _scan_port(self, ip: str, port: int) -> Optional[dict]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((ip, port))
                if result == 0:
                    service = SERVICE_MAP.get(port, "Unknown")
                    banner = self._grab_banner(s, port)
                    return {"port": port, "service": service, "banner": banner}
        except Exception:
            pass
        return None

    @staticmethod
    def _grab_banner(sock: socket.socket, port: int) -> str:
        try:
            if port in (80, 8080, 8443, 443):
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            sock.settimeout(0.5)
            data = sock.recv(1024).decode(errors="ignore").strip()
            return data.split("\n")[0][:60] if data else ""
        except Exception:
            return ""

    # ── Run ───────────────────────────────────────────────────────────────────

    def run(self, output_file: Optional[str] = None):
        print(f"{C_CYAN}{C_BOLD}[ PORT SCANNER ]{C_RESET}")
        print(f"{C_GRAY}{'─' * 50}{C_RESET}")

        ip = self._resolve_target()
        if not ip:
            print(f"{C_RED}✗  Cannot resolve target: {self.target}{C_RESET}")
            return

        label = f"{self.target} ({ip})" if self.target != ip else ip
        ports = self._parse_ports()

        print(f"  Target  : {C_YELLOW}{label}{C_RESET}")
        print(f"  Ports   : {len(ports)} to scan")
        print(f"  Threads : {self.max_threads}  │  Timeout: {self.timeout}s")
        print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{C_GRAY}{'─' * 50}{C_RESET}\n")

        start = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as ex:
            futures = {ex.submit(self._scan_port, ip, p): p for p in ports}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.open_ports.append(result)
                    svc = result["service"].ljust(12)
                    banner = f"  {C_GRAY}{result['banner']}{C_RESET}" if result["banner"] else ""
                    print(f"  {C_GREEN}✔  {result['port']:<6}{C_RESET} {svc}{banner}")

        elapsed = time.time() - start
        self.open_ports.sort(key=lambda x: x["port"])

        print(f"\n{C_GRAY}{'─' * 50}{C_RESET}")
        print(f"  {C_BOLD}Open ports : {C_GREEN}{len(self.open_ports)}{C_RESET}")
        print(f"  Scan time  : {elapsed:.2f}s")

        if output_file:
            self._save(output_file, label, elapsed)

    def _save(self, path: str, label: str, elapsed: float):
        lines = [
            f"Port Scan Report — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Target : {label}",
            f"Elapsed: {elapsed:.2f}s",
            "─" * 40,
        ]
        for p in self.open_ports:
            lines.append(f"  {p['port']:<6} {p['service']:<12} {p['banner']}")
        lines.append(f"\nTotal open: {len(self.open_ports)}")
        with open(path, "w") as f:
            f.write("\n".join(lines))
        print(f"\n  {C_CYAN}Results saved → {path}{C_RESET}")
