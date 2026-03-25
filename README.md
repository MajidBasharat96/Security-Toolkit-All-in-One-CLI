# 🔐 Security Toolkit — All-in-One CLI

> A clean, practical, educational cybersecurity toolkit built in pure Python.  
> Port Scanner · Hash Generator · Password Analyser · WHOIS Lookup

---

## 📋 Table of Contents

- [Problem](#-problem)
- [Features](#-features)
- [Architecture](#-architecture)
- [Setup](#-setup)
- [Usage & Screenshots](#-usage--screenshots)
- [Security Impact](#-security-impact)
- [Project Structure](#-project-structure)
- [Disclaimer](#-disclaimer)

---

## 🎯 Problem

Security professionals, developers, and students routinely need access to quick,
reliable recon and analysis tools — but the landscape is fragmented:

| Task | Typical approach |
|------|-----------------|
| Port scanning | `nmap` (requires install, complex flags) |
| Hashing | `openssl`, `sha256sum` (different tools per OS) |
| Password check | Online services (privacy risk!) |
| WHOIS | Web forms, third-party APIs |

**Security Toolkit** unifies all four into a single, dependency-free Python CLI
that runs anywhere Python 3.8+ is installed — no root, no pip, no complexity.

---

## ✨ Features

### 🔍 Port Scanner
- Multi-threaded TCP connect scan (up to 1000 threads)
- Service fingerprinting (SSH, HTTP, FTP, MySQL, RDP, …)
- Banner grabbing on HTTP/S ports
- Common-ports quick mode (`--common`)
- Configurable timeout and thread count
- Export results to file

### #️⃣ Hash Generator
- Algorithms: **MD5, SHA-1, SHA-256, SHA-512, SHA3-256, BLAKE2b**
- Hash strings or entire files (streaming — handles any size)
- Security advisory per algorithm (BROKEN / WEAK / SECURE)
- `--all` flag to compute every algorithm at once
- Export results to file

### 🔑 Password Strength Checker
- 10-point check rubric (length, charset, symbols, sequences, …)
- Shannon entropy calculation
- Brute-force time estimates (online / offline slow / GPU)
- Common-password blacklist (top 30)
- Strong-password generator (`--suggest`)
- Masked display — password never shown in full

### 🌐 WHOIS Lookup
- Raw TCP WHOIS query (port 43) — no API key needed
- IANA referral following for accurate TLD routing
- Structured field extraction (Registrar, Created, Expires, NS, …)
- Live DNS resolution
- Supports 30+ TLDs (`.com`, `.net`, `.io`, `.pk`, `.ai`, …)
- Export raw + parsed results to file

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         toolkit.py (CLI)                             │
│                    argparse  ·  subcommands                          │
└──────┬──────────────┬──────────────┬──────────────┬────────────────┘
       │              │              │              │
       ▼              ▼              ▼              ▼
┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐
│   Port     │ │   Hash     │ │ Password   │ │  WHOIS     │
│  Scanner   │ │ Generator  │ │  Checker   │ │  Lookup    │
│            │ │            │ │            │ │            │
│ socket     │ │ hashlib    │ │ re         │ │ socket     │
│ threading  │ │ os         │ │ math       │ │ re         │
│ concurrent │ │            │ │ secrets    │ │            │
└────────────┘ └────────────┘ └────────────┘ └────────────┘
       │              │              │              │
       └──────────────┴──────────────┴──────────────┘
                              │
                    ┌─────────▼──────────┐
                    │   Output           │
                    │  ┌──────────────┐  │
                    │  │  Terminal    │  │
                    │  │  (coloured)  │  │
                    │  └──────────────┘  │
                    │  ┌──────────────┐  │
                    │  │  File (-o)   │  │
                    │  └──────────────┘  │
                    └────────────────────┘
```

**Design Principles:**
- **Zero external dependencies** — 100% Python standard library
- **Module isolation** — each feature is a self-contained class
- **Single responsibility** — every module does one thing well
- **Consistent output** — coloured terminal + plain-text file export

---

## ⚙️ Setup

### Requirements
- Python 3.8 or higher
- No pip installs required!

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/security-toolkit.git
cd security-toolkit

# Make executable (Linux/macOS)
chmod +x toolkit.py

# Verify installation
python toolkit.py --help
```

### Optional (Windows colour support)
```bash
pip install colorama
```

---

## 📸 Usage & Screenshots

### Port Scanner

```bash
# Scan common ports
python toolkit.py scan -t example.com --common

# Scan a range with custom settings
python toolkit.py scan -t 192.168.1.1 -p 1-65535 --threads 200 --timeout 0.5

# Save results
python toolkit.py scan -t example.com --common -o scan_results.txt
```

**Output:**
```
[ PORT SCANNER ]
──────────────────────────────────────────────────
  Target  : example.com (93.184.216.34)
  Ports   : 23 to scan
  Threads : 100  │  Timeout: 1.0s
  Started : 2026-03-25 14:30:00
──────────────────────────────────────────────────

  ✔  80     HTTP         HTTP/1.1 200 OK
  ✔  443    HTTPS

──────────────────────────────────────────────────
  Open ports : 2
  Scan time  : 3.24s
```

---

### Hash Generator

```bash
# Hash a string
python toolkit.py hash -i "hello world" -a sha256

# Hash a file with all algorithms
python toolkit.py hash -f /path/to/file.iso -a all

# Save to file
python toolkit.py hash -i "secret" -a sha512 -o hashes.txt
```

**Output:**
```
[ HASH GENERATOR ]
────────────────────────────────────────────────────────────
  Source    : "hello world"
  Timestamp : 2026-03-25 14:30:00
────────────────────────────────────────────────────────────

  SHA256     ✔  SECURE
  ────────────────────────────────────────────────────────
  b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
  ↳ Current standard — recommended
```

---

### Password Strength Checker

```bash
# Check a password
python toolkit.py password -p "MyP@ssw0rd!"

# Hidden input (more secure)
python toolkit.py password

# Generate a strong password
python toolkit.py password --suggest
```

**Output:**
```
[ PASSWORD ANALYSER ]
───────────────────────────────────────────────────────
  Password  : M**********!
  Length    : 12 chars
  Charset   : 94 possible symbols
  Entropy   : 78.8 bits

  Strength  : STRONG 🔐
  Score     : ████████████████░░░░  82/100

  Checks:
    ✔  At least 8 characters
    ✔  At least 12 characters
    ✗  At least 16 characters
    ✔  Contains uppercase letters
    ...

  Estimated brute-force time:
    Online attack (100/s)           centuries
    Offline slow (1M/s)             centuries
    Offline fast GPU (10B/s)        centuries
```

---

### WHOIS Lookup

```bash
# Look up a domain
python toolkit.py whois -d example.com

# Save output
python toolkit.py whois -d google.com -o whois_report.txt
```

**Output:**
```
[ WHOIS LOOKUP ]
───────────────────────────────────────────────────────
  Domain    : example.com
  Timestamp : 2026-03-25 14:30:00
  Resolves  : 93.184.216.34
───────────────────────────────────────────────────────

  Querying whois.verisign-grs.com …

  Registrar      RESERVED-Internet Assigned Numbers Authority
  Created        1995-08-14T04:00:00Z
  Expires        2025-08-13T04:00:00Z
  Name Servers
    • a.iana-servers.net
    • b.iana-servers.net
  DNSSEC         signedDelegation
```

---

## 🛡️ Security Impact

| Tool | Real-World Use Case |
|------|---------------------|
| **Port Scanner** | Network audit — identify exposed services before attackers do |
| **Hash Generator** | File integrity verification, password storage assessment, forensics |
| **Password Checker** | Security awareness training, policy enforcement, personal hygiene |
| **WHOIS Lookup** | Threat intelligence, phishing investigation, asset discovery |

### Why This Matters

- **Developers** can verify their deployments expose only intended ports
- **Sysadmins** can audit internal networks for shadow services
- **Security teams** can check password policies without sending data to third parties
- **Researchers** can quickly gather domain intelligence during investigations

---

## 📁 Project Structure

```
security-toolkit/
├── toolkit.py              # CLI entry point (argparse)
├── requirements.txt        # No external deps required
├── README.md
└── modules/
    ├── __init__.py
    ├── port_scanner.py     # Multi-threaded TCP scanner
    ├── hash_generator.py   # Cryptographic hash engine
    ├── password_checker.py # Entropy & pattern analyser
    └── whois_lookup.py     # Raw TCP WHOIS client
```

---

## ⚠️ Disclaimer

This toolkit is intended **for educational purposes and authorized use only**.

- Only scan systems you own or have explicit written permission to test
- WHOIS and hash operations are passive and legal
- Port scanning without authorization may be illegal in your jurisdiction
- The authors are not responsible for misuse

---

## 📄 License

MIT License — free to use, modify, and distribute with attribution.
