# Security Audit Summary

**Date:** 2025-11-07
**Repository:** ThePharmer/coursera-dl
**Auditor:** Claude AI Security Audit

---

## Quick Overview

A comprehensive security audit identified **23 vulnerabilities** in the coursera-dl codebase:

- **🔴 4 CRITICAL** - Require immediate action
- **🟠 8 HIGH** - Fix within 1-4 weeks
- **🟡 7 MEDIUM** - Address within 1-3 months
- **⚪ 4 LOW** - Code quality improvements

**Overall Security Score: 2/10** ⚠️ **IMMEDIATE ACTION REQUIRED**

---

## Critical Vulnerabilities (Fix Immediately)

### 1. CAUTH Cookie Exposed in Process List
- **Location:** `coursera/commandline.py:349-354`
- **Risk:** Credentials visible to all local users via `ps aux`
- **Fix:** Use environment variables or cookies file instead

### 2. Command Injection via Downloader Arguments
- **Location:** `coursera/downloaders.py:124-137`
- **Risk:** Arbitrary command execution
- **Fix:** Whitelist validation, use `shlex.quote()`

### 3. Cookie Credentials Passed to External Processes
- **Location:** `coursera/downloaders.py:89-103`
- **Risk:** Session cookies visible in process list
- **Fix:** Use temporary cookie files with 0600 permissions

### 4. Hooks Execute Arbitrary Shell Commands
- **Location:** `coursera/workflow.py:248-255`
- **Risk:** Complete system compromise
- **Fix:** Validate hooks, restrict to safe executables

---

## High Priority Issues (Fix Within 1 Month)

1. **ReDoS via User Regex** - Add timeout and complexity limits
2. **Insecure Directory Permissions (0o777)** - Change to 0o755
3. **Path Traversal Risk** - Validate with `realpath()`, prevent symlinks
4. **No SSL Certificate Pinning** - Pin Coursera certificates
5. **Unvalidated JSON Parsing** - Add schema validation
6. **No Netrc Permission Check** - Verify 0600 before reading
7. **Server Errors Logged** - Sanitize before logging
8. **Race Condition in mkdir** - Use `exist_ok=True`

---

## Dependency Vulnerabilities

**URGENT:** Multiple dependencies have known CVEs:

```
❌ requests <2.31.0    - CVE-2023-32681 (credential leakage)
❌ urllib3 <2.0.0      - CVE-2023-43804, CVE-2023-45803
❌ attrs pinned to 18.1.0 - Missing 5 years of security updates
⚠️  Python 2 support  - EOL since January 2020
```

**Action Required:** Update `requirements.txt`:
```
beautifulsoup4>=4.12.0
requests>=2.31.0
urllib3>=2.0.7
keyring>=24.0.0
attrs>=23.0.0
```

---

## Quick Fix Commands

### 1. Update Dependencies
```bash
# Update requirements.txt
cat > requirements.txt << 'EOF'
beautifulsoup4>=4.12.0
requests>=2.31.0
urllib3>=2.0.7
pyasn1>=0.5.0
keyring>=24.0.0
configargparse>=1.5.0
attrs>=23.0.0
EOF

pip install -r requirements.txt --upgrade
```

### 2. Fix File Permissions
```python
# In utils.py line 171, change:
def mkdir_p(path, mode=0o777):  # BEFORE
# To:
def mkdir_p(path, mode=0o755):  # AFTER
```

### 3. Remove --cauth CLI Argument
```python
# Comment out in commandline.py:348-354
# group_adv_auth.add_argument(
#     '-ca', '--cauth',
#     dest='cookies_cauth',
#     action='store',
#     default=None,
#     help='cauth cookie value from browser')
```

---

## Testing Commands

Run these to verify vulnerabilities:

### Test Command Injection
```bash
# Should be blocked after fix
coursera-dl --aria2 --downloader-arguments "; echo VULNERABLE #" test-course
```

### Test Process Exposure
```bash
# Before fix: shows CAUTH in ps output
coursera-dl --cauth "SECRET_COOKIE" test-course &
ps aux | grep coursera-dl  # CAUTH visible ❌
```

### Check File Permissions
```bash
# After download, verify permissions
ls -la ~/Downloads/coursera-courses/
# Should be 755 for directories, not 777
```

---

## Immediate Action Checklist

```
Priority 1 (This Week):
[ ] Remove --cauth command-line argument
[ ] Validate --downloader-arguments with whitelist
[ ] Use temporary cookie files for external downloaders
[ ] Restrict hooks to safe executables
[ ] Update requests to >=2.31.0
[ ] Update urllib3 to >=2.0.7

Priority 2 (This Month):
[ ] Add regex timeout protection
[ ] Fix directory permissions (0o777 → 0o755)
[ ] Implement path traversal protection
[ ] Add certificate pinning
[ ] Remove Python 2 support
[ ] Add JSON schema validation

Priority 3 (Next Quarter):
[ ] Add SAST tools (Bandit, Semgrep)
[ ] Implement rate limiting
[ ] Add type hints
[ ] Create security test suite
[ ] Add SECURITY.md policy
[ ] Enable Dependabot
```

---

## Security Tools to Integrate

### Static Analysis
```bash
# Install and run Bandit
pip install bandit
bandit -r coursera/ -f json -o bandit-report.json

# Install and run Safety
pip install safety
safety check --json
```

### Pre-commit Hooks
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: ['-c', 'bandit.yaml']
```

---

## OWASP Top 10 Compliance

| Risk | Status | Priority |
|------|--------|----------|
| A03: Injection | ❌ FAIL | CRITICAL |
| A01: Broken Access Control | ❌ FAIL | HIGH |
| A06: Vulnerable Components | ❌ FAIL | HIGH |
| A02: Cryptographic Failures | ⚠️ PARTIAL | MEDIUM |
| A05: Security Misconfiguration | ⚠️ PARTIAL | MEDIUM |

**Target:** Achieve 8/10 PASS rate within 3 months

---

## Resources

- **Full Report:** See `SECURITY_AUDIT_REPORT.md` for detailed findings
- **CVE Database:** https://nvd.nist.gov/
- **Python Security:** https://python.readthedocs.io/en/latest/library/security_warnings.html
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/

---

## Contact

For questions about this audit, please open an issue in the repository.

For security vulnerability reports, please follow responsible disclosure:
1. Do NOT open public issues for security bugs
2. Email security concerns to repository maintainers
3. Allow 90 days for remediation before public disclosure

---

**Next Steps:**

1. Review full `SECURITY_AUDIT_REPORT.md`
2. Prioritize CRITICAL fixes
3. Create GitHub issues for each vulnerability
4. Implement fixes with tests
5. Run security scanners in CI/CD
6. Re-audit after fixes applied

**Estimated Remediation Time:**
- Critical fixes: 1-2 weeks
- High priority: 2-4 weeks
- Medium priority: 1-3 months
- Total security hardening: 3-6 months

---

*Generated by Claude AI Security Audit on 2025-11-07*
