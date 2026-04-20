# Contributing to TRISHUL Scanner

Thank you for your interest in contributing to TRISHUL Scanner! 🔱

We welcome contributions in the form of:
- Bug reports and fixes
- New security modules or plugins
- Documentation improvements
- Performance optimizations
- Test coverage additions

---

## ⚠ Code of Conduct

By contributing, you agree that:
1. All contributions must be for **ethical, legal, defensive security** purposes only
2. No contributions that enable unauthorized access to systems will be accepted
3. Be respectful and constructive in all interactions

---

## 🚀 Getting Started

### 1. Fork & Clone

```bash
git clone https://github.com/<your-username>/trishul-scanner.git
cd trishul-scanner
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux / macOS
source venv/bin/activate
```

### 3. Install in Development Mode

```bash
pip install -r requirements.txt
pip install -e .
```

### 4. Verify Setup

```bash
python tests/test_basic.py
trishul --help
```

---

## 🧩 Writing a Plugin

Plugins are the easiest way to contribute! Drop a `.py` file in `trishul/plugins/`:

```python
# trishul/plugins/my_check.py
from typing import Dict, List
from trishul.core.models import Finding, Severity
from trishul.plugins.base import BasePlugin


class MyCheckPlugin(BasePlugin):
    name = "My Security Check"
    description = "What does this plugin detect?"
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

        # Your detection logic here
        if "vulnerable_pattern" in body_text:
            findings.append(
                Finding(
                    title="Descriptive Finding Title",
                    severity=Severity.HIGH,  # CRITICAL / HIGH / MEDIUM / LOW / INFO
                    url=url,
                    description="Clear explanation of the vulnerability",
                    evidence="What exactly was found and where",
                    module=f"plugin:{self.name.lower().replace(' ', '_')}",
                    remediation="How to fix this issue",
                    cwe="CWE-XXX",  # CWE reference if applicable
                    cvss=7.5,       # CVSS score if known
                )
            )

        return findings
```

### Plugin Guidelines

- ✅ Use **passive checks** only (do not inject payloads aggressively)
- ✅ Always return an **empty list** if nothing is found (never `None`)
- ✅ Include `cwe` and `remediation` fields for every finding
- ✅ Keep the plugin focused — one category of vulnerability per plugin
- ✅ Add error handling inside your plugin (don't let exceptions crash the engine)
- ❌ Do not make external HTTP requests inside a plugin (use the data passed to `run()`)
- ❌ Do not write to disk from inside a plugin

---

## 🐛 Reporting Bugs

Please use the [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md) issue template.

Include:
- Python version (`python --version`)
- OS and version
- Full command you ran
- Full error traceback
- Target URL (if it's a legal public test target like testphp.vulnweb.com)

---

## 📦 Pull Request Process

1. **Branch naming**: `feature/my-feature` or `fix/bug-description`
2. **Keep PRs focused** — one change per PR
3. **Update CHANGELOG.md** under `[Unreleased]`
4. **Update README.md** if adding a new module or CLI option
5. **Add tests** in `tests/` for new functionality
6. Make sure `python tests/test_basic.py` passes

### PR Checklist

```
- [ ] Tests pass locally
- [ ] Added entry to CHANGELOG.md [Unreleased] section
- [ ] Documentation updated if needed
- [ ] No hardcoded credentials or sensitive data
- [ ] Plugin follows passive-only guideline (if applicable)
```

---

## 🗂 Project Structure

```
trishul/
├── trishul/
│   ├── cli.py                # DO NOT break the CLI interface
│   ├── core/
│   │   ├── engine.py         # Module orchestration
│   │   ├── http_client.py    # Async HTTP — rate limiter lives here
│   │   ├── models.py         # Core data models — extend carefully
│   │   └── response_analyzer.py
│   ├── modules/              # Add new scan modules here
│   ├── plugins/              # Add new detection plugins here
│   └── reporters/            # Add new output formats here
├── templates/                # Jinja2 HTML template
└── tests/                    # Test suite
```

---

## 💬 Questions?

Open a [Discussion](https://github.com/trishul-scanner/trishul/discussions) on GitHub.

Thank you for making TRISHUL better! 🔱
