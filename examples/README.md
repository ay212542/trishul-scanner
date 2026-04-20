# TRISHUL Scanner — Examples

This folder contains example outputs and custom plugins to help you get started.

---

## 📄 `sample_report.json`

A sample JSON report output from scanning `http://testphp.vulnweb.com`.

View it to understand the report structure before writing integrations:
```bash
cat examples/sample_report.json
```

---

## 🔌 `plugins/`

Example custom plugins you can copy into `trishul/plugins/` or load with `--plugins-dir`:

| Plugin | Detects |
|--------|---------|
| `dir_listing.py` | Enabled directory browsing (CWE-548) |

### How to use example plugins

```bash
# Option 1: Copy into trishul/plugins/
copy examples\plugins\dir_listing.py trishul\plugins\

# Option 2: Point to this directory
trishul http://example.com --plugins-dir ./examples/plugins
```

---

## 🎯 Legal Test Targets

These are **publicly available** intentionally vulnerable/test targets:

| Target | URL | Notes |
|--------|-----|-------|
| Acunetix Test | http://testphp.vulnweb.com | PHP + SQL injection |
| DVWA | http://localhost/dvwa | Self-hosted |
| HackTheBox | https://hackthebox.com | Membership required |
| TryHackMe | https://tryhackme.com | Free tier available |

> ⚠ Always ensure you have **authorization** before scanning any target.
