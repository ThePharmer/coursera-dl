# Dependency Status and Update Plan

**Last Updated:** 2025-11-17
**Current Version:** 0.11.5

---

## Current State

### Dependencies Overview

| Package | Current | Latest | Age | Status | Notes |
|---------|---------|--------|-----|--------|-------|
| **beautifulsoup4** | >=4.1.3 | 4.12.2 | 13 years | 🔴 OUTDATED | First release was 2012 |
| **requests** | >=2.10.0 | 2.31.0 | 8 years | 🔴 CVE | CVE-2023-32681 |
| **urllib3** | >=1.23 | 2.0.7 | 6 years | 🔴 CVE | CVE-2023-43804, CVE-2023-45803 |
| **attrs** | ==18.1.0 | 23.1.0 | 5 years | 🔴 PINNED | Pinned to 2018 version |
| **keyring** | >=4.0 | 24.2.0 | 10+ years | 🔴 OUTDATED | Missing security updates |
| **six** | >=1.5.0 | 1.16.0 | 10 years | ⚠️ EOL | Maintenance mode, Python 2 compat |
| **pyasn1** | >=0.1.7 | 0.5.0 | 10+ years | ⚠️ OUTDATED | Very old version |
| **configargparse** | >=0.12.0 | 1.5.5 | 9 years | ⚠️ OUTDATED | Many bug fixes missed |

---

## Known CVEs

### Critical Vulnerabilities

#### CVE-2023-32681: requests <2.31.0
**Severity:** HIGH (CVSS 6.1)
**Description:** Credential leakage vulnerability
**Impact:** Credentials may be leaked in redirects
**Status:** 🔴 UNPATCHED in v0.11.5
**Fix:** Update to requests>=2.31.0

**Details:**
```
When following redirects, requests may leak credentials
to untrusted domains under certain conditions.
```

**Reference:** https://nvd.nist.gov/vuln/detail/CVE-2023-32681

---

#### CVE-2023-43804: urllib3 <2.0.6
**Severity:** MEDIUM (CVSS 5.9)
**Description:** Cookie leakage on cross-origin redirects
**Impact:** Session cookies may leak to untrusted hosts
**Status:** 🔴 UNPATCHED in v0.11.5
**Fix:** Update to urllib3>=2.0.7

**Reference:** https://nvd.nist.gov/vuln/detail/CVE-2023-43804

---

#### CVE-2023-45803: urllib3 <2.0.7
**Severity:** MEDIUM (CVSS 4.2)
**Description:** Request smuggling via quoted request target
**Impact:** HTTP request smuggling attacks
**Status:** 🔴 UNPATCHED in v0.11.5
**Fix:** Update to urllib3>=2.0.7

**Reference:** https://nvd.nist.gov/vuln/detail/CVE-2023-45803

---

## Dependency Details

### beautifulsoup4

**Current:** >=4.1.3 (from 2012)
**Latest:** 4.12.2
**Recommendation:** >=4.12.0

**Changes Since 4.1.3:**
- 11+ years of bug fixes
- Python 3 performance improvements
- Better HTML5 parsing
- Security fixes for malformed HTML
- lxml parser improvements

**Breaking Changes:** None expected

**Update Risk:** 🟢 LOW - Highly backward compatible

---

### requests

**Current:** >=2.10.0 (from 2016)
**Latest:** 2.31.0
**Recommendation:** >=2.31.0

**Changes Since 2.10.0:**
- CVE-2023-32681 fix (credential leakage)
- CVE-2018-18074 fix (redirect authentication)
- Improved SSL/TLS handling
- Better connection pooling
- Bug fixes and performance improvements

**Breaking Changes:**
- Removed support for Python 2.6, 3.3
- Changed default timeout behavior (now None instead of infinite)
- Stricter SSL verification

**Update Risk:** 🟡 MEDIUM - Some behavior changes

**Migration Notes:**
```python
# BEFORE (v2.10.0)
response = requests.get(url)  # No timeout

# AFTER (v2.31.0) - Same behavior
response = requests.get(url, timeout=None)  # Explicit

# RECOMMENDED
response = requests.get(url, timeout=30)  # Set reasonable timeout
```

---

### urllib3

**Current:** >=1.23 (from 2018)
**Latest:** 2.0.7
**Recommendation:** >=2.0.7

**⚠️ MAJOR VERSION CHANGE: 1.x → 2.x**

**Changes Since 1.23:**
- CVE-2023-43804 fix (cookie leakage)
- CVE-2023-45803 fix (request smuggling)
- CVE-2021-33503 fix (catastrophic backtracking)
- Dropped Python 2 support
- Modern SSL/TLS defaults
- Better IPv6 support

**Breaking Changes:**
- **Requires Python 3.7+** (drops Python 2.7, 3.6)
- Removed deprecated `urllib3.contrib.pyopenssl`
- Changed default `Retry` behavior
- Stricter SSL/TLS verification

**Update Risk:** 🔴 HIGH - Major version, requires Python 3.7+

**Migration Notes:**
```python
# BEFORE (1.x)
import urllib3
urllib3.disable_warnings()  # Old method

# AFTER (2.x)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # Explicit

# Connection pooling (behavior unchanged)
http = urllib3.PoolManager()
resp = http.request('GET', 'https://example.com')
```

**Compatibility Shim (if needed):**
```python
# For gradual migration
try:
    import urllib3.exceptions as urllib3_exceptions
except ImportError:
    # Fallback for urllib3 1.x
    import urllib3 as urllib3_exceptions
```

---

### attrs

**Current:** ==18.1.0 (from 2018, PINNED)
**Latest:** 23.1.0
**Recommendation:** >=23.0.0

**⚠️ PINNED VERSION - Why?**
Unknown reason for pinning. Likely accidental or outdated constraint.

**Changes Since 18.1.0:**
- 5 years of bug fixes
- Performance improvements
- Better type hints support
- Python 3.10, 3.11 optimizations
- Security improvements

**Breaking Changes:**
- Dropped Python 2.7, 3.5, 3.6 support
- Changed default `eq=True` behavior in some edge cases
- Removed deprecated APIs

**Update Risk:** 🟡 MEDIUM - Pinned version suggests potential issues

**Migration Notes:**
```python
# BEFORE (18.1.0)
import attr

@attr.s
class MyClass:
    x = attr.ib()

# AFTER (23.1.0) - Same API
import attr

@attr.s
class MyClass:
    x = attr.ib()

# MODERN (23.1.0) - New features
from attrs import define

@define
class MyClass:
    x: int  # Type hints supported
```

---

### keyring

**Current:** >=4.0 (from ~2013)
**Latest:** 24.2.0
**Recommendation:** >=24.0.0

**Changes Since 4.0:**
- 10+ years of security updates
- Better encryption
- More backend support (Windows Credential Manager, macOS Keychain, Secret Service)
- Python 3 optimizations

**Breaking Changes:**
- Dropped Python 2 support
- Changed backend priority
- Some API method signatures changed

**Update Risk:** 🟡 MEDIUM - May affect credential storage

**Migration Notes:**
```python
# BEFORE (4.x)
import keyring
keyring.set_password('coursera', 'username', 'password')
password = keyring.get_password('coursera', 'username')

# AFTER (24.x) - Same API (backward compatible)
import keyring
keyring.set_password('coursera', 'username', 'password')
password = keyring.get_password('coursera', 'username')
```

---

### six

**Current:** >=1.5.0 (from ~2013)
**Latest:** 1.16.0
**Recommendation:** >=1.16.0 (or REMOVE in v0.14.0)

**Status:** Maintenance mode only (Python 2 → 3 compatibility)

**Changes Since 1.5.0:**
- Bug fixes
- Better Python 3.9, 3.10, 3.11 support

**Breaking Changes:** None

**Update Risk:** 🟢 LOW

**⚠️ DEPRECATION NOTICE:**
`six` will be removed in v0.14.0 when Python 2 support is dropped.

**Migration Notes:**
```python
# BEFORE (with six)
import six
if six.PY3:
    from urllib.parse import urlparse
else:
    from urlparse import urlparse

# AFTER (Python 3.8+ only)
from urllib.parse import urlparse  # Direct import
```

---

### pyasn1

**Current:** >=0.1.7 (from ~2013)
**Latest:** 0.5.0
**Recommendation:** >=0.5.0

**Changes Since 0.1.7:**
- 10+ years of bug fixes
- Better ASN.1 parsing
- Security improvements
- Python 3 optimizations

**Breaking Changes:** Minimal

**Update Risk:** 🟢 LOW

---

### configargparse

**Current:** >=0.12.0 (from ~2016)
**Latest:** 1.5.5
**Recommendation:** >=1.5.0

**Changes Since 0.12.0:**
- Many bug fixes
- Better config file parsing
- Python 3 improvements

**Breaking Changes:** None expected

**Update Risk:** 🟢 LOW

---

## Update Plan

### Phase 1: v0.12.0 (Week 3)

**Goal:** Patch all CVEs, update all dependencies

#### Step 1: Update requirements.txt

```diff
# requirements.txt

- beautifulsoup4>=4.1.3
+ beautifulsoup4>=4.12.0

- requests>=2.10.0
+ requests>=2.31.0

- urllib3>=1.23
+ urllib3>=2.0.7

- pyasn1>=0.1.7
+ pyasn1>=0.5.0

- keyring>=4.0
+ keyring>=24.0.0

- six>=1.5.0
+ six>=1.16.0

- configargparse>=0.12.0
+ configargparse>=1.5.0

- attrs==18.1.0
+ attrs>=23.0.0
```

#### Step 2: Update setup.py

```diff
# setup.py

trove_classifiers = [
    'Development Status :: 4 - Beta',
    'Environment :: Console',
    'Intended Audience :: End Users/Desktop',
    'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
    'Operating System :: OS Independent',
-   'Programming Language :: Python :: 2',
-   'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
-   'Programming Language :: Python :: 3.4',
-   'Programming Language :: Python :: 3.5',
-   'Programming Language :: Python :: 3.6',
+   'Programming Language :: Python :: 3.8',
+   'Programming Language :: Python :: 3.9',
+   'Programming Language :: Python :: 3.10',
+   'Programming Language :: Python :: 3.11',
    'Programming Language :: Python :: Implementation :: CPython',
    'Programming Language :: Python :: Implementation :: PyPy',
    'Programming Language :: Python',
    'Topic :: Education',
]
```

#### Step 3: Test Compatibility

```bash
# Create test environment
python3.8 -m venv test_env
source test_env/bin/activate

# Install updated dependencies
pip install -r requirements.txt

# Run full test suite
pytest coursera/test -v --cov=coursera

# Test each downloader
coursera-dl --help
coursera-dl --wget --help
coursera-dl --aria2 --help

# Integration test (if possible)
# coursera-dl --cookies-file test.txt test-course
```

#### Step 4: Document Breaking Changes

**BREAKING CHANGES in v0.12.0:**

1. **Python Version:**
   - Minimum: Python 3.7 → Python 3.8
   - Reason: urllib3 2.x requires Python 3.7+, but we standardize on 3.8+

2. **urllib3 API Changes:**
   - `urllib3.disable_warnings()` now requires explicit exception class
   - Stricter SSL verification (may reject some certificates)

3. **requests Timeout:**
   - Default timeout is now `None` (no change in behavior)
   - Recommended to set explicit timeout

**NON-BREAKING:**
- beautifulsoup4: Fully backward compatible
- attrs: API unchanged for our usage
- keyring: API unchanged
- pyasn1: API unchanged
- configargparse: API unchanged

---

### Phase 2: v0.14.0 (Week 15)

**Goal:** Remove Python 2 compatibility

#### Remove six dependency

```diff
# requirements.txt

  beautifulsoup4>=4.12.0
  requests>=2.31.0
  urllib3>=2.0.7
  pyasn1>=0.5.0
  keyring>=24.0.0
- six>=1.16.0
  configargparse>=1.5.0
  attrs>=23.0.0
```

#### Update all code

```python
# BEFORE
from six.moves import urllib
from six.moves import http_cookiejar as cookielib
import six

if six.PY3:
    string_types = str
else:
    string_types = basestring

# AFTER
from urllib import parse, request
from http import cookiejar as cookielib

string_types = str  # Python 3 only
```

---

## Testing Strategy

### Unit Tests

```bash
# Test with each Python version
for version in 3.8 3.9 3.10 3.11; do
    python${version} -m pytest coursera/test -v
done
```

### Integration Tests

```bash
# Test each downloader
coursera-dl --wget --help
coursera-dl --curl --help
coursera-dl --aria2 --help
coursera-dl --axel --help

# Test authentication (with dummy credentials)
coursera-dl --cookies-file test.txt --list-courses
```

### Compatibility Tests

```python
# test_urllib3_compat.py
def test_urllib3_2x_import():
    """Test urllib3 2.x imports work"""
    import urllib3
    assert urllib3.__version__.startswith('2.')

def test_requests_2_31_import():
    """Test requests 2.31+ imports work"""
    import requests
    major, minor, _ = requests.__version__.split('.')
    assert int(major) >= 2 and int(minor) >= 31
```

---

## Rollback Plan

If dependency updates cause issues:

### Option 1: Gradual Rollback

```txt
# requirements-fallback.txt
beautifulsoup4>=4.9.0  # Newer, but not latest
requests>=2.28.0       # Has CVE fix, but older
urllib3>=1.26.0        # Still 1.x, but patched
```

### Option 2: Full Rollback

Keep v0.11.5 requirements, but add patches:
```python
# Apply CVE fixes as backports
# (Not recommended - better to update)
```

### Option 3: Lock to Specific Versions

```txt
# requirements-locked.txt
beautifulsoup4==4.12.2
requests==2.31.0
urllib3==2.0.7
attrs==23.1.0
```

---

## Monitoring

### Automated Dependency Checks

**GitHub Dependabot:**
```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
```

**Safety (in CI/CD):**
```bash
# Check for CVEs
pip install safety
safety check --json

# Fail on known vulnerabilities
safety check --exit-code 1
```

**pip-audit:**
```bash
# Modern tool for dependency auditing
pip install pip-audit
pip-audit
```

---

## Dependencies After Each Phase

### v0.11.5 (Current)
```
Python: 2.7, 3.4-3.11
Dependencies: 8 (3 with CVEs, 5 outdated)
Known CVEs: 3
```

### v0.12.0 (After Phase 1)
```
Python: 3.8-3.11
Dependencies: 8 (0 with CVEs, 0 outdated)
Known CVEs: 0
```

### v0.14.0 (After Phase 3)
```
Python: 3.8-3.12
Dependencies: 7 (six removed)
Known CVEs: 0
Type Hints: Yes
```

---

## Summary

### Current Issues

- 🔴 3 known CVEs
- 🔴 5+ year old dependencies
- 🔴 Pinned attrs version
- ⚠️ Python 2 support (EOL)

### After v0.12.0

- ✅ 0 known CVEs
- ✅ All dependencies current
- ✅ No pinned versions
- ⚠️ Python 2 deprecated (removed in v0.14.0)

### After v0.14.0

- ✅ 0 known CVEs
- ✅ Python 3.8+ only
- ✅ Modern dependencies
- ✅ Automated dependency monitoring

---

## References

- [CVE Database](https://nvd.nist.gov/)
- [Python Package Index](https://pypi.org/)
- [Safety Database](https://pyup.io/safety/)
- [Snyk Vulnerability DB](https://snyk.io/vuln/)
- [GitHub Advisory Database](https://github.com/advisories)

---

**Last Updated:** 2025-11-17
**Next Review:** After v0.12.0 release

*For security policy, see [SECURITY.md](SECURITY.md)*
*For roadmap, see [ROADMAP.md](ROADMAP.md)*
