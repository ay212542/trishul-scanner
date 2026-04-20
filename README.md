# 🔱 TRISHUL Scanner

<div align="center">

**Advanced Open-Source Web Vulnerability Scanner**

*Modular • Async • Plugin-Based • Low False Positives*

[![CI](https://github.com/YOUR_USERNAME/trishul-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/trishul-scanner/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-22c55e)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-6366f1)](CHANGELOG.md)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen)](CONTRIBUTING.md)
[![Ethical Use](https://img.shields.io/badge/Use-Authorized%20Only-ef4444)](DISCLAIMER.md)

</div>

---

> **⚠ LEGAL DISCLAIMER**
> This tool is intended for **authorized security testing ONLY**.
> Scanning systems without explicit written permission is **illegal**.
> The authors accept **no liability** for misuse.
> See [DISCLAIMER.md](DISCLAIMER.md) for full legal terms.

---

## 📸 Overview

TRISHUL is a modular, async web vulnerability scanner designed for developers and security engineers.
It performs passive and low-impact security checks with a focus on **accuracy**, **modularity**, and **clean output**.

```
████████╗██████╗ ██╗███████╗██╗  ██╗██╗   ██╗██╗
╚══██╔══╝██╔══██╗██║██╔════╝██║  ██║██║   ██║██║
   ██║   ██████╔╝██║███████╗███████║██║   ██║██║
   ██║   ██╔══██╗██║╚════██║██╔══██║██║   ██║██║
   ██║   ██║  ██║██║███████║██║  ██║╚██████╔╝███████╗
   ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
               Advanced Web Vulnerability Scanner v1.0.0
```

---

## ✨ Features

| Module | What It Does |
|--------|-------------|
| 🕷 **Web Crawler** | Async BFS with depth control, deduplication, binary-skip |
| 🔌 **Port Scanner** | 60+ ports, asyncio TCP connect, 15 risky-port flags |
| 🛡 **Header Analyzer** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options + quality checks |
| 🔍 **Fuzz Engine** | 80+ sensitive paths, soft-404 baseline filtering |
| 🔒 **SSL Analyzer** | Expiry countdown, hostname mismatch, self-signed detection |
| 💡 **Tech Detector** | Server, framework, CDN, CMS from headers & HTML |
| 🔌 **Plugin System** | Dynamic plugin loading — drop `.py` → auto-detected |
| 📊 **Reports** | CLI (Rich), JSON, dark-mode HTML with collapsible findings |

---

## 🚀 Installation

### Requirements
- Python **3.10+**
- pip

### Install from Source

```bash
git clone https://github.com/YOUR_USERNAME/trishul-scanner.git
cd trishul-scanner

# Install dependencies
pip install -r requirements.txt

# Install as CLI tool
pip install -e .
```

### Verify Installation

```bash
trishul --help
python tests/test_basic.py
```

---

## 🎯 Usage

### Basic Scan
```bash
trishul http://testphp.vulnweb.com
```

### Generate HTML Report
```bash
trishul http://testphp.vulnweb.com -f html -o report.html
```

### JSON Export
```bash
trishul http://testphp.vulnweb.com -f json -o results.json
```

### Specific Modules Only
```bash
trishul http://example.com -m "headers,ssl,tech"
```

### Deep Crawl with Custom Rate Limit
```bash
trishul http://example.com -d 5 --rate-limit 5 --timeout 15
```

### Load Custom Plugins
```bash
trishul http://example.com --plugins-dir ./my_plugins
```

---

## ⚙ CLI Reference

```
Usage: trishul [OPTIONS] TARGET_URL

  TRISHUL Scanner — Scan TARGET_URL for web vulnerabilities.

Options:
  -d, --depth INTEGER            Crawler depth (1-10)  [default: 3]
  -o, --output TEXT              Output file path
  -f, --format [json|html|cli]   Report format  [default: cli]
  -m, --modules TEXT             Modules: all | crawler,ports,headers,
                                 fuzz,ssl,tech,plugins  [default: all]
  --rate-limit INTEGER           Max requests per second  [default: 10]
  --timeout INTEGER              Request timeout in seconds  [default: 10]
  --retries INTEGER              Max retry attempts  [default: 3]
  --plugins-dir TEXT             Path to custom plugins directory
  --no-banner                    Suppress the ASCII banner
  -v, --verbose                  Verbose output
  --help                         Show this message and exit
```

> **Legal test target**: [http://testphp.vulnweb.com](http://testphp.vulnweb.com) — provided by Acunetix for public testing.

---

## 🧩 Plugin System

All plugins live in `trishul/plugins/`. They are loaded automatically at runtime.

### Built-in Plugins

| Plugin File | Detection Method | Severity |
|-------------|-----------------|----------|
| `xss_detector.py` | Reflected parameter + DOM sink analysis | HIGH |
| `sqli_detector.py` | SQL error patterns (MySQL/PG/MSSQL/Oracle) | HIGH/CRITICAL |
| `open_redirect.py` | Redirect param analysis + Location header | MEDIUM/HIGH |

### Write Your Own Plugin

```python
# trishul/plugins/my_check.py  (or --plugins-dir)
from typing import Dict, List
from trishul.core.models import Finding, Severity
from trishul.plugins.base import BasePlugin


class MyPlugin(BasePlugin):
    name = "My Custom Check"
    description = "Detects something interesting"
    author = "Your Name"
    version = "1.0.0"

    async def run(
        self,
        url: str,
        headers: Dict[str, str],
        body: bytes,
        status_code: int,
    ) -> List[Finding]:
        findings = []
        body_text = body.decode("utf-8", errors="ignore")

        if "vulnerable_pattern" in body_text:
            findings.append(Finding(
                title="Descriptive Title",
                severity=Severity.HIGH,
                url=url,
                description="Explanation of the vulnerability",
                evidence="What was found",
                module="plugin:my_check",
                remediation="How to fix it",
                cwe="CWE-XXX",
            ))

        return findings
```

Then run:
```bash
trishul http://target.com --plugins-dir ./my_plugins
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full plugin guidelines.

---

## 📁 Project Structure

```
trishul-scanner/
├── trishul/
│   ├── cli.py                    # CLI entry point (Click + Rich)
│   ├── core/
│   │   ├── engine.py             # Scan orchestrator
│   │   ├── http_client.py        # Async HTTP + rate limiter + retry
│   │   ├── models.py             # Finding, ScanResult, ScanConfig
│   │   └── response_analyzer.py  # Soft-404 & false-positive reduction
│   ├── modules/
│   │   ├── crawler.py            # Async BFS web crawler
│   │   ├── port_scanner.py       # asyncio TCP port scanner
│   │   ├── header_analyzer.py    # Security header analysis
│   │   ├── fuzz_engine.py        # Sensitive path fuzzer
│   │   ├── ssl_analyzer.py       # SSL/TLS certificate analyzer
│   │   └── tech_detector.py      # Technology fingerprinting
│   ├── plugins/
│   │   ├── base.py               # BasePlugin ABC
│   │   ├── loader.py             # Dynamic plugin loader
│   │   ├── xss_detector.py       # XSS detection plugin
│   │   ├── sqli_detector.py      # SQLi detection plugin
│   │   └── open_redirect.py      # Open redirect plugin
│   └── reporters/
│       ├── cli_reporter.py       # Rich terminal output
│       ├── json_reporter.py      # JSON export
│       └── html_reporter.py      # HTML report (Jinja2)
├── templates/
│   └── report.html.j2            # Dark-mode HTML report template
├── tests/
│   └── test_basic.py             # Basic test suite
├── .github/
│   ├── workflows/ci.yml          # GitHub Actions CI (3 OS × 3 Python)
│   ├── ISSUE_TEMPLATE/           # Bug, Feature, Plugin templates
│   └── PULL_REQUEST_TEMPLATE.md
├── requirements.txt
├── setup.py
├── pyproject.toml
├── CHANGELOG.md
├── CONTRIBUTING.md
├── DISCLAIMER.md
├── LICENSE
└── README.md
```

---

## ⚡ Performance

| Feature | Implementation |
|---------|---------------|
| Async HTTP | `aiohttp` with connection pooling (100 connections) |
| Rate Limiting | Token bucket — configurable RPS |
| Retry Logic | Exponential backoff (configurable attempts) |
| Port Scanner | 200 concurrent async TCP checks |
| Fuzz Engine | Semaphore-controlled (20 concurrent path checks) |

---

## 🔒 Severity Levels

| Level | Color | Description |
|-------|-------|-------------|
| 🔴 CRITICAL | Red | Immediate action required — data exposure or RCE risk |
| 🟠 HIGH | Orange | Serious security flaw — fix urgently |
| 🟡 MEDIUM | Yellow | Significant issue — fix soon |
| 🔵 LOW | Blue | Minor issue — fix when possible |
| ⚪ INFO | Gray | Informational — review recommended |

---

## 🛣 Roadmap

- [ ] `robots.txt` / `sitemap.xml` aware crawling
- [ ] Cookie security checker (HttpOnly, Secure, SameSite)
- [ ] CORS misconfiguration detection
- [ ] Directory listing detection
- [ ] WAF detection
- [ ] Subdomain enumeration
- [ ] CI/CD exit code mode
- [ ] PyPI package release

---

## 🧪 Running Tests

```bash
python tests/test_basic.py
```

Expected output:
```
==================================================
  TRISHUL Scanner — Test Suite
==================================================

✔ Finding creation test passed
✔ Findings sorting test passed
✔ Response analyzer soft-404 test passed
✔ ScanConfig defaults test passed
✔ Plugin loader test passed — loaded: ['XSS Detector', 'SQL Injection Detector', 'Open Redirect Detector']

==================================================
  All tests passed! ✅
==================================================
```

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

**Quick start:**
```bash
git checkout -b feature/my-feature
# Make your changes
python tests/test_basic.py
git commit -m "feat: add my feature"
git push origin feature/my-feature
# Open a Pull Request
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## ⚠ Security Policy

If you discover a security vulnerability in TRISHUL itself, please **do not open a public issue**.
Email the maintainer privately or open a [GitHub Security Advisory](https://github.com/YOUR_USERNAME/trishul-scanner/security/advisories/new).

---

<div align="center">

**TRISHUL** — Named after the divine trident ⚔️  
*Strength. Accuracy. Purpose.*

Made with ❤️ for the security community | [Report Bug](.github/ISSUE_TEMPLATE/bug_report.md) · [Request Feature](.github/ISSUE_TEMPLATE/feature_request.md) · [Submit Plugin](.github/ISSUE_TEMPLATE/plugin_submission.md)

</div>
