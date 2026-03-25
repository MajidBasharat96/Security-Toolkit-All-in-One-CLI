"""
Password Strength Checker Module
---------------------------------
Analyses password strength using entropy, pattern detection,
and checks against common password lists.
"""

import re
import math
import secrets
import string
import getpass
from datetime import datetime
from typing import Optional

C_GREEN  = "\033[92m"
C_RED    = "\033[91m"
C_YELLOW = "\033[93m"
C_CYAN   = "\033[96m"
C_GRAY   = "\033[90m"
C_BOLD   = "\033[1m"
C_RESET  = "\033[0m"

# Top 30 most common passwords
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123",
    "password1", "111111", "iloveyou", "admin", "letmein",
    "welcome", "monkey", "dragon", "master", "sunshine",
    "princess", "baseball", "shadow", "superman", "michael",
    "football", "charlie", "donald", "password123", "starwars",
    "123123", "hello", "freedom", "whatever", "qazwsx"
}


class PasswordChecker:

    # ── Entropy ───────────────────────────────────────────────────────────────

    @staticmethod
    def _charset_size(pwd: str) -> int:
        size = 0
        if re.search(r'[a-z]', pwd): size += 26
        if re.search(r'[A-Z]', pwd): size += 26
        if re.search(r'\d',    pwd): size += 10
        if re.search(r'[ !@#$%^&*()_+\-=\[\]{}|;:\'",.<>?/`~\\]', pwd): size += 32
        return size or 1

    @staticmethod
    def _entropy(pwd: str, charset: int) -> float:
        return len(pwd) * math.log2(charset)

    # ── Checks ────────────────────────────────────────────────────────────────

    @staticmethod
    def _checks(pwd: str) -> dict:
        return {
            "length_8":    len(pwd) >= 8,
            "length_12":   len(pwd) >= 12,
            "length_16":   len(pwd) >= 16,
            "uppercase":   bool(re.search(r'[A-Z]', pwd)),
            "lowercase":   bool(re.search(r'[a-z]', pwd)),
            "digits":      bool(re.search(r'\d', pwd)),
            "symbols":     bool(re.search(r'[^a-zA-Z0-9]', pwd)),
            "no_common":   pwd.lower() not in COMMON_PASSWORDS,
            "no_repeat":   not re.search(r'(.)\1{2,}', pwd),
            "no_sequence": not re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|qwe|wer|ert)', pwd.lower()),
        }

    @staticmethod
    def _score(checks: dict, entropy: float) -> tuple[int, str, str]:
        """Returns (score 0-100, grade, colour)."""
        base = sum(checks.values()) * 8  # 10 checks × 8 = 80 pts
        # entropy bonus (up to 20 pts)
        entropy_bonus = min(20, int((entropy - 28) / 4)) if entropy > 28 else 0
        score = min(100, base + entropy_bonus)

        if score >= 85:
            return score, "STRONG 🔐",   C_GREEN
        if score >= 65:
            return score, "MODERATE ⚠️",  C_YELLOW
        if score >= 40:
            return score, "WEAK ⚠️",      C_YELLOW
        return score, "VERY WEAK 🚨", C_RED

    # ── Display ───────────────────────────────────────────────────────────────

    def _bar(self, score: int, color: str) -> str:
        filled = int(score / 5)
        empty  = 20 - filled
        return f"{color}{'█' * filled}{C_GRAY}{'░' * empty}{C_RESET}"

    def analyse(self, pwd: str, output_file: Optional[str] = None):
        print(f"\n{C_CYAN}{C_BOLD}[ PASSWORD ANALYSER ]{C_RESET}")
        print(f"{C_GRAY}{'─' * 55}{C_RESET}")

        checks   = self._checks(pwd)
        charset  = self._charset_size(pwd)
        entropy  = self._entropy(pwd, charset)
        score, grade, color = self._score(checks, entropy)

        masked = pwd[0] + "*" * (len(pwd) - 2) + pwd[-1] if len(pwd) > 2 else "**"
        print(f"  Password  : {masked}")
        print(f"  Length    : {len(pwd)} chars")
        print(f"  Charset   : {charset} possible symbols")
        print(f"  Entropy   : {entropy:.1f} bits")
        print()
        print(f"  Strength  : {color}{C_BOLD}{grade}{C_RESET}")
        print(f"  Score     : {self._bar(score, color)}  {color}{score}/100{C_RESET}")
        print()

        print(f"  {C_BOLD}Checks:{C_RESET}")
        items = [
            ("length_8",    "At least 8 characters"),
            ("length_12",   "At least 12 characters"),
            ("length_16",   "At least 16 characters"),
            ("uppercase",   "Contains uppercase letters"),
            ("lowercase",   "Contains lowercase letters"),
            ("digits",      "Contains digits"),
            ("symbols",     "Contains special symbols"),
            ("no_common",   "Not a common password"),
            ("no_repeat",   "No repeated characters (e.g. aaa)"),
            ("no_sequence", "No keyboard sequences (e.g. 123, abc)"),
        ]
        for key, label in items:
            icon  = f"{C_GREEN}✔{C_RESET}" if checks[key] else f"{C_RED}✗{C_RESET}"
            print(f"    {icon}  {label}")

        # Recommendations
        recs = []
        if not checks["length_12"]:   recs.append("Use at least 12 characters")
        if not checks["uppercase"]:    recs.append("Add uppercase letters (A-Z)")
        if not checks["digits"]:       recs.append("Include digits (0-9)")
        if not checks["symbols"]:      recs.append("Add special characters (!@#$…)")
        if not checks["no_common"]:    recs.append("Avoid common/dictionary passwords")
        if not checks["no_repeat"]:    recs.append("Avoid repeated characters (aaa)")
        if not checks["no_sequence"]:  recs.append("Avoid sequential patterns (123, abc)")

        if recs:
            print(f"\n  {C_BOLD}Recommendations:{C_RESET}")
            for r in recs:
                print(f"    {C_YELLOW}→{C_RESET} {r}")

        # Estimated crack time
        print(f"\n  {C_BOLD}Estimated brute-force time:{C_RESET}")
        combos = charset ** len(pwd)
        speeds = [
            ("Online attack (100/s)",     100),
            ("Offline slow (1M/s)",        1_000_000),
            ("Offline fast GPU (10B/s)",  10_000_000_000),
        ]
        for label, rate in speeds:
            seconds = combos / rate
            print(f"    {C_GRAY}{label:<30}{C_RESET} {self._human_time(seconds)}")

        if output_file:
            self._save(output_file, pwd, score, grade, checks, entropy, recs)

    @staticmethod
    def _human_time(seconds: float) -> str:
        if seconds < 1:          return "< 1 second"
        if seconds < 60:         return f"{seconds:.0f} seconds"
        if seconds < 3600:       return f"{seconds/60:.0f} minutes"
        if seconds < 86400:      return f"{seconds/3600:.0f} hours"
        if seconds < 31536000:   return f"{seconds/86400:.0f} days"
        if seconds < 3.15e9:     return f"{seconds/31536000:.0f} years"
        return "centuries"

    def suggest_password(self):
        """Generate a strong random password."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        pwd = "".join(secrets.choice(alphabet) for _ in range(20))
        print(f"\n{C_CYAN}{C_BOLD}[ SUGGESTED PASSWORD ]{C_RESET}")
        print(f"\n  {C_GREEN}{C_BOLD}{pwd}{C_RESET}\n")
        print(f"  {C_GRAY}(Store it in a password manager!){C_RESET}\n")
        self.analyse(pwd)

    @staticmethod
    def prompt_hidden() -> str:
        return getpass.getpass("  Enter password (hidden): ")

    def _save(self, path: str, pwd: str, score: int, grade: str,
              checks: dict, entropy: float, recs: list):
        masked = pwd[0] + "*" * (len(pwd) - 2) + pwd[-1] if len(pwd) > 2 else "**"
        lines = [
            f"Password Analysis — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Password : {masked}",
            f"Score    : {score}/100  ({grade})",
            f"Entropy  : {entropy:.1f} bits",
            "─" * 40,
            "Checks:",
        ]
        for k, v in checks.items():
            lines.append(f"  {'✔' if v else '✗'}  {k}")
        if recs:
            lines += ["\nRecommendations:"] + [f"  → {r}" for r in recs]
        with open(path, "w") as f:
            f.write("\n".join(lines))
        print(f"\n  {C_CYAN}Results saved → {path}{C_RESET}")
