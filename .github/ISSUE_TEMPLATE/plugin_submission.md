---
name: "\U0001F9E9 Plugin Submission"
about: Submit a new detection plugin for TRISHUL Scanner
title: "[PLUGIN] "
labels: plugin
assignees: ''
---

## 🔌 Plugin Name

**Name:**
**File:** `trishul/plugins/<filename>.py`

---

## 🎯 What Does It Detect?

Describe the vulnerability or issue this plugin detects.
Include relevant CVE/CWE numbers if applicable.

- **CWE:** CWE-XXX
- **OWASP Category:** (e.g., A03:2021 Injection)

---

## 🔍 Detection Method

Is this plugin:
- [ ] Passive (analyzes existing response data only)
- [ ] Semi-active (sends additional non-destructive requests)

Describe the detection logic briefly.

---

## ✅ False Positive Mitigation

How does the plugin reduce false positives?

---

## 🧪 Test Cases

Describe how you tested this plugin:
- Target used (must be a legal test target like testphp.vulnweb.com)
- Sample finding output

---

## 📋 Checklist

- [ ] Plugin inherits from `BasePlugin`
- [ ] Returns empty list (not `None`) when nothing is found
- [ ] Includes `cwe`, `remediation`, and `evidence` in all findings
- [ ] Does not make external HTTP requests
- [ ] Does not write to disk
- [ ] Tested on a legal target
- [ ] Added to CHANGELOG.md `[Unreleased]`
