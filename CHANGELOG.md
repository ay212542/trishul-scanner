# Changelog

All notable changes to TRISHUL Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2025-04-20

### 🎉 Initial Release

#### Added
- **CLI Tool** — Full-featured command-line interface with Click + Rich
  - `--depth`, `--modules`, `--format`, `--output`, `--rate-limit`, `--timeout`, `--retries`, `--plugins-dir` options
  - Legal disclaimer banner on every run
  - Graceful Ctrl+C handling

- **Async Web Crawler** — BFS crawler with depth control
  - Relative & absolute URL resolution
  - Binary file extension skipping (images, CSS, JS, etc.)
  - Same-origin enforcement
  - Deduplication via URL normalization

- **Async Port Scanner** — asyncio TCP connect scan
  - 60+ common + extended ports
  - 15 risky port classifications (Docker, Redis, MongoDB, etc.)
  - 200 concurrent connection checks
  - No root/admin privileges required

- **Security Header Analyzer** — HTTP response header checks
  - 7 security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection
  - CSP quality analysis (unsafe-inline, unsafe-eval, wildcard detection)
  - HSTS max-age quality check
  - Server/X-Powered-By information disclosure detection

- **Fuzz Engine** — Path discovery with false-positive filtering
  - 80+ sensitive paths (.env, .git, /admin, /phpmyadmin, actuator endpoints, etc.)
  - Baseline soft-404 comparison
  - Content length and MD5 hash comparison
  - Severity mapping per path category

- **SSL/TLS Analyzer** — Certificate inspection
  - HTTPS enforcement check
  - Certificate validity
  - Hostname mismatch detection
  - Self-signed certificate detection
  - Expiry date with day countdown
  - 30-day expiry warning

- **Technology Detector** — Stack fingerprinting
  - Server: Nginx, Apache, IIS, LiteSpeed, Caddy, etc.
  - Frameworks: Django, Flask, Laravel, Rails, Spring, Next.js, etc.
  - CDN: Cloudflare, Akamai, Fastly, CloudFront
  - CMS: WordPress, Drupal, Joomla, Magento, Shopify
  - Language: PHP, Python, Ruby, Java, Node.js
  - HTML `<meta generator>` parsing

- **Plugin System** — Dynamic plugin architecture
  - `BasePlugin` abstract class with well-defined contract
  - `PluginLoader` using `importlib` for dynamic discovery
  - Plugin isolation with error handling per plugin
  - `--plugins-dir` for custom plugin directories

- **Built-in Plugins**
  - `xss_detector.py` — Reflected XSS via parameter analysis + DOM sink detection
  - `sqli_detector.py` — Error-based SQLi pattern matching (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) + numeric param heuristics
  - `open_redirect.py` — Redirect parameter analysis + Location header confirmation (30 param names)

- **Response Analysis Engine**
  - Soft-404 detection via keyword matching
  - Baseline hash comparison for false-positive reduction
  - Content length delta thresholding (5%)

- **Report Generation**
  - CLI: Rich colored output, severity badges, tech/SSL tables
  - JSON: Fully structured export (all findings, metadata, SSL, tech, ports, crawled URLs)
  - HTML: Dark-mode Jinja2 template with interactive collapsible findings

- **Performance**
  - `aiohttp` async HTTP with connection pooling
  - Token bucket rate limiter
  - Exponential backoff retry (configurable attempts)
  - Semaphore-controlled parallel fuzzing

- **Documentation**
  - Comprehensive README with usage, plugin guide, and structure
  - DISCLAIMER with legal references (CFAA, CMA, IT Act)
  - CONTRIBUTING guide
  - MIT License
  - GitHub Actions CI workflow
  - Issue templates (Bug Report, Feature Request, Plugin Submission)

---

## [Unreleased]

### Planned
- robots.txt / sitemap.xml aware crawling
- Cookie security checker (HttpOnly, Secure, SameSite)
- CORS misconfiguration detection
- Directory listing detection
- WAF detection and bypass hints
- Subdomain enumeration
- CI/CD exit code integration
- Rate limit detection
- Web socket endpoint detection
