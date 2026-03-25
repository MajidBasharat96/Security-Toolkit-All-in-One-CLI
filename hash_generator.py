"""
Hash Generator Module
---------------------
Generate cryptographic hashes for strings or files.
Supports MD5, SHA-1, SHA-256, SHA-512, SHA3-256, BLAKE2b.
"""

import hashlib
import os
from datetime import datetime
from typing import Optional

C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_CYAN   = "\033[96m"
C_GRAY   = "\033[90m"
C_BOLD   = "\033[1m"
C_RESET  = "\033[0m"

ALGORITHMS = {
    "md5":      hashlib.md5,
    "sha1":     hashlib.sha1,
    "sha256":   hashlib.sha256,
    "sha512":   hashlib.sha512,
    "sha3_256": hashlib.sha3_256,
    "blake2b":  hashlib.blake2b,
}

SECURITY_NOTES = {
    "md5":      ("⚠  BROKEN", "\033[91m", "Collision attacks known — avoid for security use"),
    "sha1":     ("⚠  WEAK",   "\033[93m", "Deprecated by NIST — use SHA-256+"),
    "sha256":   ("✔  SECURE", "\033[92m", "Current standard — recommended"),
    "sha512":   ("✔  SECURE", "\033[92m", "Higher security margin — excellent for passwords"),
    "sha3_256": ("✔  SECURE", "\033[92m", "Keccak-based — resistant to length-extension"),
    "blake2b":  ("✔  SECURE", "\033[92m", "Fast & modern — great for integrity checks"),
}


class HashGenerator:
    def __init__(self, algorithm: str):
        self.algorithm = algorithm

    # ── Core hashing ─────────────────────────────────────────────────────────

    def _compute(self, algo: str, data: bytes) -> str:
        h = ALGORITHMS[algo]()
        h.update(data)
        return h.hexdigest()

    def _compute_file(self, algo: str, filepath: str) -> str:
        h = ALGORITHMS[algo]()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    # ── Output helpers ────────────────────────────────────────────────────────

    def _header(self, source: str):
        print(f"{C_CYAN}{C_BOLD}[ HASH GENERATOR ]{C_RESET}")
        print(f"{C_GRAY}{'─' * 60}{C_RESET}")
        print(f"  Source    : {C_YELLOW}{source}{C_RESET}")
        print(f"  Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{C_GRAY}{'─' * 60}{C_RESET}\n")

    def _print_hash(self, algo: str, digest: str):
        label, color, note = SECURITY_NOTES[algo]
        print(f"  {C_BOLD}{algo.upper():<10}{C_RESET} {color}{label}{C_RESET}")
        print(f"  {C_GRAY}{'─' * 56}{C_RESET}")
        print(f"  {digest}")
        print(f"  {C_GRAY}↳ {note}{C_RESET}\n")

    # ── Public API ────────────────────────────────────────────────────────────

    def hash_string(self, text: str, output_file: Optional[str] = None):
        self._header(f'"{text[:40]}{"…" if len(text) > 40 else ""}"')
        algos = list(ALGORITHMS.keys()) if self.algorithm == "all" else [self.algorithm]
        results = {}
        for algo in algos:
            digest = self._compute(algo, text.encode())
            results[algo] = digest
            self._print_hash(algo, digest)
        if output_file:
            self._save(output_file, f'string: "{text}"', results)

    def hash_file(self, filepath: str, output_file: Optional[str] = None):
        if not os.path.isfile(filepath):
            print(f"\033[91m✗  File not found: {filepath}\033[0m")
            return

        size = os.path.getsize(filepath)
        self._header(f"{filepath} ({size:,} bytes)")
        algos = list(ALGORITHMS.keys()) if self.algorithm == "all" else [self.algorithm]
        results = {}
        for algo in algos:
            digest = self._compute_file(algo, filepath)
            results[algo] = digest
            self._print_hash(algo, digest)
        if output_file:
            self._save(output_file, f"file: {filepath}", results)

    def _save(self, path: str, source: str, results: dict):
        lines = [
            f"Hash Report — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Source: {source}", "─" * 40,
        ]
        for algo, digest in results.items():
            lines.append(f"  {algo.upper():<12} {digest}")
        with open(path, "w") as f:
            f.write("\n".join(lines))
        print(f"  {C_CYAN}Results saved → {path}{C_RESET}")
