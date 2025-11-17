# Security Policy

## Supported Versions

| Version | Supported          | Security Status |
| ------- | ------------------ | --------------- |
| 0.11.x  | :white_check_mark: | Active (with known issues) |
| < 0.11  | :x:                | No longer supported |

**Python Version Support:**
- Python 3.8+: ✅ Fully supported
- Python 2.7, 3.4-3.7: ⚠️ Deprecated (will be removed in v0.13.0)

---

## Known Security Issues

⚠️ **IMPORTANT:** This version has known security vulnerabilities being actively addressed.

### Critical Vulnerabilities (Fix in Progress)

#### CRIT-1: CAUTH Cookie Exposed in Process List
- **Severity:** CRITICAL (CVSS 7.8)
- **Impact:** Credentials visible to local users via `ps aux`
- **Status:** Fix planned for v0.13.0
- **Workaround:** Use `--cookies-file` instead of `--cauth`

#### CRIT-2: Command Injection via Downloader Arguments
- **Severity:** CRITICAL (CVSS 9.8)
- **Impact:** Remote Code Execution (RCE) through `--downloader-arguments`
- **Status:** Fix planned for v0.13.0
- **Workaround:** Do not use `--downloader-arguments` with untrusted input

#### CRIT-3: Arbitrary Command Execution via Hooks
- **Severity:** CRITICAL (CVSS 9.1)
- **Impact:** System compromise through malicious hooks
- **Status:** Fix planned for v0.13.0
- **Workaround:** Do not use hooks from untrusted sources

#### CRIT-4: Session Cookies Exposed to External Processes
- **Severity:** CRITICAL
- **Impact:** Session hijacking through process inspection
- **Status:** Fix planned for v0.13.0
- **Workaround:** Use internal downloader instead of external tools

### High Severity Issues

#### HIGH-1: Insecure File Permissions
- **Severity:** HIGH
- **Impact:** Downloaded files are world-readable (mode 0o777)
- **Status:** Fix planned for v0.12.0
- **Workaround:** Manually `chmod 755` after downloads

#### HIGH-2: ReDoS (Regular Expression Denial of Service)
- **Severity:** HIGH
- **Impact:** CPU exhaustion via crafted regex patterns
- **Status:** Fix planned for v0.13.0
- **Workaround:** Avoid complex regex patterns in filters

#### HIGH-3: Path Traversal Vulnerability
- **Severity:** HIGH
- **Impact:** Files could be written outside intended directory
- **Status:** Fix planned for v0.13.0
- **Workaround:** Run in isolated directory with limited permissions

### Dependency Vulnerabilities

#### Outdated Dependencies with Known CVEs
- **requests <2.31.0:** CVE-2023-32681 (credential leakage)
- **urllib3 <2.0.7:** CVE-2023-43804, CVE-2023-45803
- **Status:** Updates planned for v0.12.0

---

## Security Best Practices

### For Users

**DO:**
- ✅ Use `--cookies-file` for authentication (not `--cauth`)
- ✅ Run with restricted user permissions (non-root)
- ✅ Download to isolated directories
- ✅ Keep coursera-dl updated to latest version
- ✅ Verify downloads with checksums when available

**DO NOT:**
- ❌ Use `--cauth` flag in shared environments
- ❌ Pass untrusted input to `--downloader-arguments`
- ❌ Use hooks from untrusted sources
- ❌ Run as root/administrator
- ❌ Download to system directories

### For Developers

**DO:**
- ✅ Run security scanners (Bandit, Safety) before committing
- ✅ Add security tests for new features
- ✅ Validate all user input
- ✅ Use `shlex.quote()` for shell arguments
- ✅ Follow principle of least privilege

**DO NOT:**
- ❌ Accept unvalidated user input
- ❌ Execute shell commands without sanitization
- ❌ Store credentials in code or logs
- ❌ Use deprecated or vulnerable dependencies

---

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please follow responsible disclosure:

### How to Report

**For security vulnerabilities, please DO NOT:**
- ❌ Open a public GitHub issue
- ❌ Discuss publicly on forums or social media
- ❌ Exploit the vulnerability

**Instead, please:**

1. **Email the maintainers directly** (check repository for current maintainer emails)
2. **Include the following information:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if you have one)
   - Your contact information

3. **Use encryption if possible:**
   - PGP key available in repository (if provided)

### What to Expect

**Response Timeline:**
- **Initial response:** Within 48 hours
- **Vulnerability assessment:** Within 1 week
- **Fix timeline:** Within 30-90 days (depending on severity)
- **Public disclosure:** After fix is released or 90 days, whichever comes first

**Process:**
1. We acknowledge receipt of your report
2. We confirm the vulnerability and determine severity
3. We develop and test a fix
4. We release a security update
5. We publicly disclose the issue (with credit to reporter, if desired)

**Recognition:**
- Security researchers will be credited in release notes (unless anonymous preferred)
- We maintain a SECURITY_CONTRIBUTORS.md file

---

## Security Update Policy

### Release Schedule

**Critical Vulnerabilities (CVSS 9.0+):**
- Emergency patch within 7 days
- Immediate notification to users

**High Vulnerabilities (CVSS 7.0-8.9):**
- Patch within 30 days
- Included in next scheduled release

**Medium/Low Vulnerabilities:**
- Included in quarterly releases
- Documented in release notes

### Notification Channels

Security updates will be announced via:
1. GitHub Security Advisories
2. Release notes (CHANGELOG.md)
3. PyPI release announcements
4. Repository README

### Upgrade Recommendations

- **Critical fixes:** Upgrade immediately
- **High severity:** Upgrade within 1 week
- **Medium/Low:** Upgrade at next opportunity

---

## Roadmap for Security Improvements

### v0.12.0 (Month 1) - Dependency Updates
- [ ] Update requests to >=2.31.0 (CVE-2023-32681)
- [ ] Update urllib3 to >=2.0.7 (CVE-2023-43804, CVE-2023-45803)
- [ ] Update beautifulsoup4 to >=4.12.0
- [ ] Update attrs to >=23.0.0
- [ ] Add automated dependency scanning (Dependabot)
- [ ] Fix HIGH-1 (insecure file permissions)

### v0.13.0 (Months 2-3) - Critical Fixes
- [ ] Fix CRIT-1 (remove --cauth exposure)
- [ ] Fix CRIT-2 (validate downloader arguments)
- [ ] Fix CRIT-3 (validate hooks)
- [ ] Fix CRIT-4 (secure cookie files)
- [ ] Fix HIGH-2 (ReDoS protection)
- [ ] Fix HIGH-3 (path traversal)
- [ ] Add comprehensive security test suite
- [ ] Integrate Bandit into CI/CD

### v0.14.0 (Months 4-6) - Hardening
- [ ] Remove Python 2 support (EOL since 2020)
- [ ] Add input validation framework
- [ ] Implement SSL certificate pinning
- [ ] Add JSON schema validation
- [ ] Security audit by external firm
- [ ] Achieve OWASP Top 10 compliance

---

## Security Checklist for Contributors

Before submitting a PR, ensure:

- [ ] No hardcoded credentials or secrets
- [ ] All user input is validated
- [ ] No shell command injection vulnerabilities
- [ ] No SQL injection (if applicable)
- [ ] No path traversal vulnerabilities
- [ ] Dependencies are up-to-date
- [ ] Security tests added for new features
- [ ] Bandit security scan passes
- [ ] No sensitive data in logs
- [ ] File permissions are restrictive (not 0o777)

---

## Security Tools

### Recommended Tools for Development

**Static Analysis:**
```bash
# Install
pip install bandit safety

# Run security scanner
bandit -r coursera/ -f screen

# Check dependencies for CVEs
safety check
```

**Pre-commit Hooks:**
```bash
# Install pre-commit
pip install pre-commit

# Set up hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

**Dependency Monitoring:**
```bash
# Check for outdated packages
pip list --outdated

# Audit dependencies
pip-audit
```

---

## Frequently Asked Questions

### Q: Is it safe to use coursera-dl?

**A:** Version 0.11.x has known security issues. Follow the workarounds above and upgrade to v0.13.0+ when available. Do not use in production or with sensitive data until CRITICAL issues are resolved.

### Q: Can I use coursera-dl on a shared server?

**A:** Not recommended until v0.13.0. The CAUTH exposure and permission issues make it unsafe on shared systems.

### Q: How do I securely authenticate?

**A:** Use `--cookies-file` with a file that has 0600 permissions:
```bash
# Create cookie file
touch coursera_cookies.txt
chmod 600 coursera_cookies.txt

# Use it
coursera-dl --cookies-file coursera_cookies.txt course-name
```

### Q: What should I do if I've been using --cauth?

**A:**
1. Rotate your Coursera session (log out and back in)
2. Switch to `--cookies-file` method
3. Review system logs for unauthorized access
4. Update to v0.13.0 when available

### Q: Are my downloads safe?

**A:** Yes, if you:
- Download only from trusted Coursera courses
- Run with limited user permissions
- Use the workarounds above
- Keep software updated

---

## Contact

**Security Issues:** Email maintainers directly (see repository)
**General Questions:** Open a GitHub issue
**Security Mailing List:** (To be established)

---

## Attribution

This security policy follows best practices from:
- [OWASP Security by Design Principles](https://owasp.org/www-project-security-by-design-principles/)
- [GitHub Security Advisories](https://docs.github.com/en/code-security/security-advisories)
- [Python Security Best Practices](https://python.readthedocs.io/en/latest/library/security_warnings.html)

---

**Last Updated:** 2025-11-17
**Policy Version:** 1.0
**Next Review:** 2025-12-17

*For detailed technical analysis, see [REPOSITORY_REVIEW.md](REPOSITORY_REVIEW.md)*
