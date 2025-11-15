# Security Remediation Roadmap

**Project:** coursera-dl
**Date Created:** 2025-11-15
**Status:** In Progress
**Overall Timeline:** 6 months (Week 1 - Month 6)

---

## Executive Summary

This roadmap addresses **23 security vulnerabilities** identified in the security audit, organized into 4 priority phases. The remediation process will take approximately 6 months to complete all security improvements, with critical fixes targeted for completion within the first 2 weeks.

**Security Score:**
- Current: 2/10 ⚠️ CRITICAL
- Target (Phase 1): 5/10
- Target (Phase 2): 7/10
- Target (Final): 9/10 ✅

---

## Remediation Phases Overview

| Phase | Timeline | Vulnerabilities Fixed | Priority Level |
|-------|----------|----------------------|----------------|
| **Phase 1** | Week 1-2 | 4 Critical + Dependencies | 🔴 CRITICAL |
| **Phase 2** | Week 3-6 | 8 High Severity | 🟠 HIGH |
| **Phase 3** | Month 2-3 | 7 Medium Severity | 🟡 MEDIUM |
| **Phase 4** | Month 4-6 | 4 Low + Infrastructure | ⚪ LOW |

---

## Phase 1: Critical Fixes (Week 1-2) 🔴

**Timeline:** Days 1-14
**Goal:** Eliminate critical security vulnerabilities and update vulnerable dependencies
**Success Criteria:** All CRITICAL vulnerabilities resolved, security score reaches 5/10

### Week 1: Days 1-7

#### Day 1-2: CRIT-1 - Remove CAUTH CLI Exposure
**Vulnerability:** Cookie credentials exposed in process list
**Location:** `coursera/commandline.py:349-354`, `coursera/coursera_dl.py:248-250`

**Tasks:**
- [ ] Remove `--cauth` command-line argument from parser
- [ ] Update documentation to remove references to `--cauth`
- [ ] Add deprecation warning if environment variable is detected
- [ ] Update help text to recommend `--cookies-file` instead
- [ ] Test authentication flow without `--cauth` option

**Deliverables:**
- Modified `coursera/commandline.py` (remove lines 349-354)
- Modified `coursera/coursera_dl.py` (remove CAUTH CLI handling)
- Updated README.md with secure authentication methods
- Test cases validating secure credential handling

**Effort:** 8 hours
**Assigned To:** Security Team

---

#### Day 2-3: CRIT-2 - Fix Command Injection in Downloader Arguments
**Vulnerability:** Arbitrary command execution via `--downloader-arguments`
**Location:** `coursera/downloaders.py:124-137`, `coursera/commandline.py:276-281`

**Tasks:**
- [ ] Implement whitelist validation for downloader arguments
- [ ] Use `shlex.quote()` to sanitize all user inputs
- [ ] Add regex validation: `^[a-zA-Z0-9_\-=]+$`
- [ ] Create safe argument parser function
- [ ] Add comprehensive unit tests for injection attempts
- [ ] Document allowed arguments in help text

**Implementation:**
```python
import shlex
import re

SAFE_ARG_PATTERN = re.compile(r'^[a-zA-Z0-9_\-=]+$')
ALLOWED_ARGS = {
    '--max-connection-per-server',
    '--split',
    '--min-split-size',
    '--continue',
    '--max-tries'
}

def validate_downloader_arguments(args_string):
    """Validate and sanitize downloader arguments."""
    if not args_string:
        return []

    args = args_string.split()
    validated = []

    for arg in args:
        # Check if argument name is in whitelist
        arg_name = arg.split('=')[0]
        if arg_name not in ALLOWED_ARGS:
            raise ValueError(f"Argument {arg_name} not allowed")

        # Validate argument format
        if not SAFE_ARG_PATTERN.match(arg):
            raise ValueError(f"Invalid argument format: {arg}")

        validated.append(shlex.quote(arg))

    return validated
```

**Deliverables:**
- New `validate_downloader_arguments()` function
- Updated `coursera/downloaders.py` with validation
- Security tests for command injection attempts
- Updated documentation with allowed arguments

**Effort:** 12 hours
**Assigned To:** Core Dev Team

---

#### Day 3-4: CRIT-3 - Secure Cookie Passing to External Processes
**Vulnerability:** Session cookies visible in process list
**Location:** `coursera/downloaders.py:89-103`, `coursera/downloaders.py:150-151`, `coursera/downloaders.py:168-169`

**Tasks:**
- [ ] Create temporary cookie file generator with 0600 permissions
- [ ] Modify WgetDownloader to use `--load-cookies` instead of `--header`
- [ ] Modify CurlDownloader to use `--cookie` with file path
- [ ] Implement secure cleanup of temporary cookie files
- [ ] Add try/finally blocks for guaranteed cleanup
- [ ] Test with all supported downloaders (wget, curl, aria2, axel)

**Implementation:**
```python
import tempfile
import os

class SecureCookieFile:
    """Context manager for secure temporary cookie files."""

    def __init__(self, cookie_values):
        self.cookie_values = cookie_values
        self.temp_file = None

    def __enter__(self):
        # Create temp file with secure permissions
        fd, self.temp_file = tempfile.mkstemp(prefix='coursera_cookies_', suffix='.txt')
        os.chmod(self.temp_file, 0o600)

        # Write cookies in Netscape format
        with os.fdopen(fd, 'w') as f:
            f.write(self.cookie_values)

        return self.temp_file

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Securely delete temp file
        if self.temp_file and os.path.exists(self.temp_file):
            os.unlink(self.temp_file)
```

**Deliverables:**
- New `SecureCookieFile` context manager
- Updated downloader classes to use cookie files
- Security tests validating file permissions
- Integration tests for all downloaders

**Effort:** 10 hours
**Assigned To:** Core Dev Team

---

#### Day 4-5: CRIT-4 - Restrict Hook Execution
**Vulnerability:** Arbitrary shell command execution via hooks
**Location:** `coursera/workflow.py:248-255`

**Tasks:**
- [ ] Implement executable whitelist for hooks
- [ ] Add hook validation before execution
- [ ] Use `subprocess.run()` with `shell=False`
- [ ] Add explicit security warnings in documentation
- [ ] Create hook security policy document
- [ ] Add option to disable hooks with `--no-hooks` flag

**Implementation:**
```python
import subprocess
import os
from pathlib import Path

ALLOWED_HOOK_EXECUTABLES = {
    'python', 'python3',
    'bash', 'sh',
    'node', 'npm',
    'ffmpeg'
}

def validate_hook(hook_command):
    """Validate hook command against security policy."""
    if isinstance(hook_command, str):
        parts = hook_command.split()
    else:
        parts = hook_command

    if not parts:
        raise ValueError("Empty hook command")

    executable = Path(parts[0]).name

    if executable not in ALLOWED_HOOK_EXECUTABLES:
        raise SecurityError(
            f"Hook executable '{executable}' not in whitelist. "
            f"Allowed: {', '.join(ALLOWED_HOOK_EXECUTABLES)}"
        )

    return parts

def _run_hooks(self, section, hooks):
    """Run hooks with security validation."""
    if self.args.no_hooks:
        logging.info("Hooks disabled by --no-hooks flag")
        return

    original_dir = os.getcwd()
    try:
        for hook in hooks:
            logging.info('Running hook %s for section %s.', hook, section.dir)

            # Validate hook before execution
            hook_parts = validate_hook(hook)

            os.chdir(section.dir)

            # Execute with shell=False for security
            result = subprocess.run(
                hook_parts,
                shell=False,
                capture_output=True,
                timeout=300  # 5 minute timeout
            )

            if result.returncode != 0:
                logging.error("Hook failed: %s", result.stderr.decode())
    finally:
        os.chdir(original_dir)
```

**Deliverables:**
- Hook validation function
- Updated `_run_hooks()` with security controls
- `--no-hooks` command-line flag
- Security documentation for hooks
- Unit tests for hook validation

**Effort:** 10 hours
**Assigned To:** Security Team

---

### Week 2: Days 8-14

#### Day 8-10: Update Vulnerable Dependencies
**Vulnerability:** Multiple CVEs in outdated packages
**Location:** `requirements.txt`

**Tasks:**
- [ ] Update `requirements.txt` with minimum secure versions
- [ ] Test compatibility with updated dependencies
- [ ] Update `attrs` from 18.1.0 to >=23.0.0
- [ ] Update `requests` to >=2.31.0 (fixes CVE-2023-32681)
- [ ] Update `urllib3` to >=2.0.7 (fixes CVE-2023-43804, CVE-2023-45803)
- [ ] Update `keyring` to >=24.0.0
- [ ] Update `beautifulsoup4` to >=4.12.0
- [ ] Run full test suite with new dependencies
- [ ] Document any breaking changes

**Updated requirements.txt:**
```txt
beautifulsoup4>=4.12.0
requests>=2.31.0
urllib3>=2.0.7
pyasn1>=0.5.0
keyring>=24.0.0
configargparse>=1.5.0
attrs>=23.0.0
```

**Deliverables:**
- Updated `requirements.txt`
- Compatibility test results
- Migration guide if breaking changes exist
- Updated CI/CD with new dependency versions

**Effort:** 16 hours
**Assigned To:** DevOps Team

---

#### Day 11-12: Testing and Validation
**Tasks:**
- [ ] Run security scanner (Bandit) on updated code
- [ ] Perform manual penetration testing on fixed vulnerabilities
- [ ] Execute full regression test suite
- [ ] Test command injection attempts (should be blocked)
- [ ] Verify process list doesn't expose credentials
- [ ] Test all external downloaders with secure cookie files
- [ ] Validate hook restrictions work correctly

**Deliverables:**
- Security scan report
- Penetration test results
- Test coverage report (target: >80%)
- Validation checklist sign-off

**Effort:** 12 hours
**Assigned To:** QA Team

---

#### Day 13-14: Documentation and Release
**Tasks:**
- [ ] Update CHANGELOG.md with security fixes
- [ ] Create SECURITY.md with reporting instructions
- [ ] Update README.md with secure usage examples
- [ ] Write security advisory for users
- [ ] Prepare release notes for v1.0-security
- [ ] Tag release in git

**Deliverables:**
- Updated documentation
- Security advisory
- Release notes
- Git tag v1.0-security

**Effort:** 8 hours
**Assigned To:** Documentation Team

---

**Phase 1 Milestones:**
- ✅ All CRITICAL vulnerabilities resolved
- ✅ Zero known CVEs in dependencies
- ✅ Security score improved from 2/10 to 5/10
- ✅ Security release published

**Phase 1 Total Effort:** 76 hours (~2 weeks with 2 developers)

---

## Phase 2: High Priority Fixes (Week 3-6) 🟠

**Timeline:** Days 15-42
**Goal:** Resolve all HIGH severity vulnerabilities
**Success Criteria:** Security score reaches 7/10, OWASP compliance improved

### Week 3: Days 15-21

#### HIGH-1: ReDoS Protection (Days 15-17)
**Vulnerability:** Regular expression denial of service
**Location:** `coursera/workflow.py:40,60`, `coursera/filtering.py:108`

**Tasks:**
- [ ] Implement regex timeout mechanism
- [ ] Add regex complexity validation
- [ ] Limit regex pattern length to 200 characters
- [ ] Use `regex` library with timeout support
- [ ] Add try/except with timeout handling
- [ ] Create DoS test cases

**Implementation:**
```python
import regex
import signal

MAX_REGEX_LENGTH = 200
REGEX_TIMEOUT_SECONDS = 5

class RegexTimeout(Exception):
    pass

def safe_regex_search(pattern, text, timeout=REGEX_TIMEOUT_SECONDS):
    """Execute regex search with timeout protection."""
    if len(pattern) > MAX_REGEX_LENGTH:
        raise ValueError(f"Regex pattern too long (max {MAX_REGEX_LENGTH})")

    try:
        # Use regex library with timeout support
        compiled = regex.compile(pattern, timeout=timeout)
        return compiled.search(text)
    except TimeoutError:
        raise RegexTimeout(f"Regex execution exceeded {timeout}s timeout")
```

**Deliverables:**
- `safe_regex_search()` function
- Updated filter functions
- ReDoS test cases
- Performance benchmarks

**Effort:** 16 hours

---

#### HIGH-2: Fix Directory Permissions (Days 17-18)
**Vulnerability:** Insecure 0o777 permissions
**Location:** `coursera/utils.py:171-182`

**Tasks:**
- [ ] Change default `mkdir_p()` mode from 0o777 to 0o755
- [ ] Update all directory creation calls
- [ ] Add file permission constants
- [ ] Implement secure file creation (0o644)
- [ ] Test permission settings across platforms
- [ ] Verify umask is respected

**Implementation:**
```python
# Security-conscious permission constants
DIR_PERMISSIONS = 0o755   # rwxr-xr-x
FILE_PERMISSIONS = 0o644  # rw-r--r--
SECURE_DIR = 0o700        # rwx------ (for sensitive dirs)
SECURE_FILE = 0o600       # rw------- (for credentials)

def mkdir_p(path, mode=DIR_PERMISSIONS):  # Changed from 0o777
    """Create subdirectory hierarchy with secure permissions."""
    try:
        os.makedirs(path, mode)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            # Verify permissions even if dir exists
            os.chmod(path, mode)
        else:
            raise

def secure_file_write(filepath, content, mode=FILE_PERMISSIONS):
    """Write file with secure permissions."""
    # Create with restrictive permissions first
    fd = os.open(filepath, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.write(fd, content.encode())
    finally:
        os.close(fd)
```

**Deliverables:**
- Updated permission constants
- Modified `mkdir_p()` function
- New `secure_file_write()` function
- Permission validation tests

**Effort:** 8 hours

---

#### HIGH-3: Path Traversal Protection (Days 18-21)
**Vulnerability:** Filename sanitization bypass
**Location:** `coursera/utils.py:95-135`

**Tasks:**
- [ ] Use `os.path.basename()` to strip path components
- [ ] Implement `realpath()` validation
- [ ] Add download directory boundary checking
- [ ] Prevent symlink following attacks
- [ ] Create comprehensive path traversal tests
- [ ] Add logging for suspicious filenames

**Implementation:**
```python
import os
from pathlib import Path

def secure_filename(filename, target_directory):
    """Securely sanitize filename and prevent path traversal."""
    # First apply existing sanitization
    cleaned = clean_filename(filename)

    # Strip any path components
    cleaned = os.path.basename(cleaned)

    # Build full path
    full_path = os.path.join(target_directory, cleaned)

    # Resolve to absolute path (follows symlinks)
    resolved_path = os.path.realpath(full_path)
    resolved_dir = os.path.realpath(target_directory)

    # Verify final path is within target directory
    if not resolved_path.startswith(resolved_dir + os.sep):
        raise SecurityError(
            f"Path traversal attempt detected: {filename} "
            f"resolves outside target directory"
        )

    # Check for symlink attacks
    if os.path.islink(full_path):
        raise SecurityError(f"Symlink detected: {full_path}")

    return cleaned

def validate_download_path(filepath, base_dir):
    """Validate file path before writing."""
    real_file = os.path.realpath(filepath)
    real_base = os.path.realpath(base_dir)

    if not real_file.startswith(real_base + os.sep):
        logging.error("Path traversal blocked: %s not in %s", filepath, base_dir)
        raise SecurityError("Path traversal attempt blocked")

    return real_file
```

**Deliverables:**
- `secure_filename()` function
- `validate_download_path()` function
- Path traversal test suite
- Security logging

**Effort:** 12 hours

---

### Week 4-5: Days 22-35

#### HIGH-4: SSL Certificate Pinning (Days 22-26)
**Vulnerability:** No certificate pinning for Coursera
**Location:** `coursera/cookies.py:375-385`

**Tasks:**
- [ ] Obtain Coursera certificate chain
- [ ] Implement certificate pinning using `requests`
- [ ] Add option to disable pinning for corporate proxies
- [ ] Create certificate update mechanism
- [ ] Add certificate expiry warnings
- [ ] Test with valid and invalid certificates
- [ ] Upgrade TLS to v1.3 if available

**Implementation:**
```python
import ssl
import hashlib
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

# Coursera certificate SHA256 fingerprints (update as needed)
COURSERA_CERT_PINS = [
    '1a2b3c4d5e6f...',  # Primary certificate
    '9z8y7x6w5v4u...',  # Backup certificate
]

class PinnedTLSAdapter(HTTPAdapter):
    """HTTP adapter with certificate pinning."""

    def __init__(self, cert_pins=None, allow_unpinned=False):
        self.cert_pins = cert_pins or COURSERA_CERT_PINS
        self.allow_unpinned = allow_unpinned
        super().__init__()

    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ssl_version=ssl.PROTOCOL_TLS)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Prefer TLS 1.3 if available
        if hasattr(ssl, 'TLSVersion') and hasattr(ssl.TLSVersion, 'TLSv1_3'):
            context.minimum_version = ssl.TLSVersion.TLSv1_3

        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

    def cert_verify(self, conn, url, verify, cert):
        """Verify certificate pinning."""
        if self.allow_unpinned:
            logging.warning("Certificate pinning disabled (corporate proxy mode)")
            return

        # Get certificate from connection
        cert_der = conn.sock.getpeercert(binary_form=True)
        cert_hash = hashlib.sha256(cert_der).hexdigest()

        if cert_hash not in self.cert_pins:
            raise ssl.SSLError(
                f"Certificate pinning failed. "
                f"Got {cert_hash}, expected one of {self.cert_pins}"
            )

# Usage
session.mount('https://', PinnedTLSAdapter())
```

**Deliverables:**
- `PinnedTLSAdapter` class
- Certificate pin configuration
- `--allow-unpinned-certs` flag for corporate proxies
- Certificate validation tests
- Documentation for certificate updates

**Effort:** 20 hours

---

#### HIGH-5: JSON Schema Validation (Days 27-30)
**Vulnerability:** Unvalidated JSON parsing
**Location:** Multiple locations in `coursera/api.py`

**Tasks:**
- [ ] Install `jsonschema` library
- [ ] Create JSON schemas for all API responses
- [ ] Implement validation wrapper function
- [ ] Add defensive dict access with `.get()`
- [ ] Replace direct dictionary access
- [ ] Create test cases with malformed JSON
- [ ] Add schema versioning support

**Implementation:**
```python
from jsonschema import validate, ValidationError
import logging

# Example schema for course materials
COURSE_MATERIALS_SCHEMA = {
    "type": "object",
    "required": ["linked"],
    "properties": {
        "linked": {
            "type": "object",
            "required": ["onDemandCourseMaterialItems.v2"],
            "properties": {
                "onDemandCourseMaterialItems.v2": {
                    "type": "array",
                    "items": {"type": "object"}
                }
            }
        }
    }
}

def safe_json_parse(response, schema=None, path=None):
    """Safely parse and validate JSON response."""
    try:
        data = response.json()
    except ValueError as e:
        logging.error("Invalid JSON from %s: %s", path or 'API', e)
        raise

    # Validate against schema if provided
    if schema:
        try:
            validate(instance=data, schema=schema)
        except ValidationError as e:
            logging.error("JSON schema validation failed: %s", e.message)
            raise

    return data

def safe_get(dictionary, key_path, default=None):
    """Safely navigate nested dictionary."""
    keys = key_path.split('.')
    current = dictionary

    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default

    return current

# Usage example
dom = safe_json_parse(response, schema=COURSE_MATERIALS_SCHEMA)
items = safe_get(dom, 'linked.onDemandCourseMaterialItems.v2', default=[])
```

**Deliverables:**
- JSON schema definitions
- `safe_json_parse()` function
- `safe_get()` helper function
- Updated API parsing code
- Schema validation tests

**Effort:** 18 hours

---

#### HIGH-6: Netrc Permission Validation (Days 31-32)
**Vulnerability:** No .netrc permission checking
**Location:** `coursera/credentials.py:113-138`

**Tasks:**
- [ ] Add file permission check before reading .netrc
- [ ] Require 0600 or 0400 permissions
- [ ] Raise warning for insecure permissions
- [ ] Follow OpenSSH strict permission model
- [ ] Add automatic chmod suggestion
- [ ] Test on Linux, macOS, and Windows

**Implementation:**
```python
import stat
import os

def validate_netrc_permissions(netrc_path):
    """Validate .netrc file has secure permissions."""
    if not os.path.exists(netrc_path):
        return True  # File doesn't exist, will create securely

    # Get file stats
    file_stat = os.stat(netrc_path)
    file_mode = stat.S_IMODE(file_stat.st_mode)

    # Check for world or group readable
    if file_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise PermissionError(
            f".netrc file {netrc_path} has insecure permissions {oct(file_mode)}. "
            f"Run: chmod 600 {netrc_path}"
        )

    # Verify owner-only read/write (0600) or owner-only read (0400)
    allowed_modes = [0o600, 0o400]
    if file_mode not in allowed_modes:
        logging.warning(
            ".netrc permissions %s are unusual (expected 0600 or 0400)",
            oct(file_mode)
        )

    return True

def authenticate_through_netrc(path=None):
    """Authenticate using .netrc with permission validation."""
    netrc_path = path or os.path.join(os.path.expanduser('~'), '.netrc')

    # Validate permissions before reading
    validate_netrc_permissions(netrc_path)

    # Rest of existing authentication logic
    auths = netrc.netrc(netrc_path).authenticators(netrc_machine)
    # ...
```

**Deliverables:**
- `validate_netrc_permissions()` function
- Updated authentication flow
- Permission validation tests
- Cross-platform testing

**Effort:** 8 hours

---

#### HIGH-7: Sanitize Error Logging (Days 33-34)
**Vulnerability:** Information disclosure via error messages
**Location:** `coursera/network.py:50-56`

**Tasks:**
- [ ] Create error message sanitization function
- [ ] Only log full responses in debug mode
- [ ] Truncate long error messages
- [ ] Redact potential credentials from logs
- [ ] Add structured logging
- [ ] Create safe logging wrapper

**Implementation:**
```python
import re
import logging

SENSITIVE_PATTERNS = [
    r'CAUTH=[a-zA-Z0-9]+',
    r'csrf[_-]?token["\s:=]+[a-zA-Z0-9]+',
    r'api[_-]?key["\s:=]+[a-zA-Z0-9]+',
    r'password["\s:=]+[^"\s]+',
]

def sanitize_log_message(message, max_length=500):
    """Sanitize log message to remove sensitive data."""
    if not message:
        return message

    # Truncate long messages
    if len(message) > max_length:
        message = message[:max_length] + '... (truncated)'

    # Redact sensitive patterns
    for pattern in SENSITIVE_PATTERNS:
        message = re.sub(pattern, '[REDACTED]', message, flags=re.IGNORECASE)

    return message

def safe_log_error(logger, error, url, response=None):
    """Safely log error without exposing sensitive information."""
    logger.error("Error %s getting page %s", error, url)

    if response and logging.getLogger().level == logging.DEBUG:
        # Only log full response in debug mode
        sanitized = sanitize_log_message(response.text)
        logger.debug("Server response: %s", sanitized)
    elif response:
        # In non-debug mode, only log status code
        logger.error("Server returned status code: %d", response.status_code)

# Usage
try:
    reply.raise_for_status()
except requests.exceptions.HTTPError as e:
    if not quiet:
        safe_log_error(logging, e, url, reply)
    raise
```

**Deliverables:**
- `sanitize_log_message()` function
- `safe_log_error()` wrapper
- Updated error handling
- Log sanitization tests

**Effort:** 10 hours

---

#### HIGH-8: Fix Race Conditions (Days 35)
**Vulnerability:** TOCTOU in directory creation
**Location:** `coursera/utils.py:171-182`

**Tasks:**
- [ ] Use `os.makedirs()` with `exist_ok=True`
- [ ] Add directory ownership verification
- [ ] Implement atomic directory creation
- [ ] Verify with `realpath()` after creation
- [ ] Test race condition scenarios
- [ ] Add multi-process tests

**Implementation:**
```python
import os
import errno

def mkdir_p(path, mode=0o755):
    """Create directory atomically with race condition protection."""
    try:
        # Python 3.2+ supports exist_ok parameter
        os.makedirs(path, mode=mode, exist_ok=True)

        # Verify ownership and permissions after creation
        stat_info = os.stat(path)

        # Check we own the directory
        if stat_info.st_uid != os.getuid():
            raise SecurityError(
                f"Directory {path} is owned by different user "
                f"(expected {os.getuid()}, got {stat_info.st_uid})"
            )

        # Verify it's actually a directory, not a symlink
        real_path = os.path.realpath(path)
        if real_path != os.path.abspath(path):
            raise SecurityError(
                f"Path {path} is a symlink to {real_path} (potential attack)"
            )

        # Ensure permissions are correct (may have been modified by umask)
        os.chmod(path, mode)

    except OSError as exc:
        if exc.errno != errno.EEXIST:
            raise
```

**Deliverables:**
- Updated `mkdir_p()` with race protection
- Ownership validation
- Symlink detection
- Race condition tests

**Effort:** 8 hours

---

**Phase 2 Milestones:**
- ✅ All HIGH severity vulnerabilities resolved
- ✅ Input validation framework implemented
- ✅ File operation security hardened
- ✅ Security score improved from 5/10 to 7/10

**Phase 2 Total Effort:** 100 hours (~4 weeks with 2 developers)

---

## Phase 3: Medium Priority Fixes (Month 2-3) 🟡

**Timeline:** Days 43-90
**Goal:** Address MEDIUM severity issues and improve overall security posture
**Success Criteria:** Security score reaches 8/10

### Month 2: Days 43-60

#### MED-1: MathJax CDN Security (Days 43-45)
**Vulnerability:** CDN code without integrity check
**Location:** `coursera/commandline.py:410-415`

**Tasks:**
- [ ] Add Subresource Integrity (SRI) hash validation
- [ ] Bundle MathJax locally as alternative
- [ ] Validate URL scheme is HTTPS
- [ ] Add Content-Security-Policy meta tags
- [ ] Create offline mode option
- [ ] Test with and without CDN

**Effort:** 12 hours

---

#### MED-2: Fix Timing Attacks (Days 46-47)
**Vulnerability:** Non-constant time cookie validation
**Location:** `coursera/cookies.py:209-218`

**Tasks:**
- [ ] Implement constant-time comparison
- [ ] Use `hmac.compare_digest()` for sensitive checks
- [ ] Add random delays to authentication
- [ ] Implement rate limiting for auth attempts
- [ ] Add account lockout after failures
- [ ] Test timing attack resistance

**Effort:** 10 hours

---

#### MED-3: Remove Python 2 Support (Days 48-55)
**Vulnerability:** Unmaintained Python 2 code paths
**Location:** Throughout codebase

**Tasks:**
- [ ] Remove `six` library dependency
- [ ] Update all Python 2 compatibility code
- [ ] Use Python 3.7+ features (f-strings, typing, etc.)
- [ ] Remove `__future__` imports
- [ ] Update CI/CD to test only Python 3.8+
- [ ] Update documentation to require Python 3.8+
- [ ] Run full test suite on Python 3.8, 3.9, 3.10, 3.11

**Effort:** 32 hours

---

#### MED-4: Fix Monkey Patching (Days 56-58)
**Vulnerability:** Cookie monkey patching
**Location:** `coursera/cookies.py:25-57`

**Tasks:**
- [ ] Create proper Cookie subclass instead of patching
- [ ] Submit fix upstream to Python
- [ ] Document the workaround
- [ ] Test alternative cookie parsing libraries
- [ ] Add comprehensive cookie tests
- [ ] Consider using `http.cookiejar` improvements

**Effort:** 12 hours

---

#### MED-5: Implement Rate Limiting (Days 59-60)
**Vulnerability:** No request rate limiting
**Location:** Network operations

**Tasks:**
- [ ] Implement exponential backoff with jitter
- [ ] Add `--rate-limit` command-line option
- [ ] Respect HTTP 429 (Too Many Requests)
- [ ] Add retry logic with increasing delays
- [ ] Create request throttling decorator
- [ ] Test rate limiting behavior

**Implementation:**
```python
import time
import random
from functools import wraps

class RateLimiter:
    def __init__(self, requests_per_second=2):
        self.rate = requests_per_second
        self.last_request = 0
        self.min_interval = 1.0 / requests_per_second

    def wait(self):
        """Wait if necessary to respect rate limit."""
        elapsed = time.time() - self.last_request
        if elapsed < self.min_interval:
            sleep_time = self.min_interval - elapsed
            # Add jitter to prevent thundering herd
            jitter = random.uniform(0, 0.1 * sleep_time)
            time.sleep(sleep_time + jitter)
        self.last_request = time.time()

def rate_limited(limiter):
    """Decorator to rate limit function calls."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            limiter.wait()
            return func(*args, **kwargs)
        return wrapper
    return decorator
```

**Effort:** 10 hours

---

### Month 3: Days 61-90

#### MED-6: Secure Temporary Files (Days 61-63)
**Vulnerability:** Predictable temp file paths
**Location:** `coursera/cookies.py:309-310`

**Tasks:**
- [ ] Use `tempfile.mkdtemp()` for cache directories
- [ ] Add random component to cache filenames
- [ ] Verify file ownership before reading
- [ ] Use `O_EXCL` flag for exclusive creation
- [ ] Clean up old temp files
- [ ] Test multi-user scenarios

**Effort:** 12 hours

---

#### MED-7: CSRF Token Validation (Days 64-66)
**Vulnerability:** No CSRF validation
**Location:** `coursera/cookies.py:72-108`

**Tasks:**
- [ ] Validate CSRF tokens in responses
- [ ] Store expected tokens
- [ ] Implement token rotation
- [ ] Add token expiry checking
- [ ] Test CSRF protection
- [ ] Document CSRF workflow

**Effort:** 12 hours

---

#### Days 67-90: Security Infrastructure
**Tasks:**
- [ ] Integrate SAST tools (Bandit, Semgrep)
- [ ] Add pre-commit security hooks
- [ ] Set up dependency scanning (Safety, pip-audit)
- [ ] Create security test suite
- [ ] Add security CI/CD pipeline
- [ ] Implement secrets scanning (TruffleHog)
- [ ] Create security dashboard
- [ ] Document security processes

**Effort:** 96 hours

---

**Phase 3 Milestones:**
- ✅ All MEDIUM severity vulnerabilities resolved
- ✅ Python 2 support removed
- ✅ Security automation implemented
- ✅ Security score improved from 7/10 to 8/10

**Phase 3 Total Effort:** 196 hours (~6 weeks with 2 developers)

---

## Phase 4: Code Quality & Infrastructure (Month 4-6) ⚪

**Timeline:** Days 91-180
**Goal:** Achieve security excellence and establish long-term security practices
**Success Criteria:** Security score reaches 9/10, comprehensive security program

### Month 4: Days 91-120

#### LOW-1: Cryptographic Random (Days 91-92)
**Tasks:**
- [ ] Replace `random.choice()` with `secrets.choice()`
- [ ] Use `secrets.token_urlsafe()` for tokens
- [ ] Update all random generation
- [ ] Test entropy quality

**Effort:** 8 hours

---

#### LOW-2: Add Type Hints (Days 93-110)
**Tasks:**
- [ ] Add type hints to all functions
- [ ] Install and configure `mypy`
- [ ] Add type checking to CI/CD
- [ ] Use `typing` module for complex types
- [ ] Document type hints usage
- [ ] Achieve 100% type coverage

**Effort:** 72 hours

---

#### LOW-3: Fix String Comparisons (Days 111-112)
**Tasks:**
- [ ] Replace `is ''` with `== ''`
- [ ] Use proper string comparison operators
- [ ] Run linter to find similar issues
- [ ] Add linting to CI/CD

**Effort:** 8 hours

---

#### LOW-4: Code Cleanup (Days 113-120)
**Tasks:**
- [ ] Remove unused imports
- [ ] Clean up dead code
- [ ] Run `autoflake` and `pylint`
- [ ] Implement `isort` for import sorting
- [ ] Add code quality tools to pre-commit
- [ ] Achieve pylint score >9.0

**Effort:** 32 hours

---

### Month 5-6: Days 121-180

#### Security Program Establishment

**Continuous Monitoring (Days 121-135):**
- [ ] Set up Dependabot for automated dependency updates
- [ ] Configure GitHub Security Advisories
- [ ] Implement automated security scanning
- [ ] Create security metrics dashboard
- [ ] Set up vulnerability alerting
- [ ] Document incident response process

**Effort:** 60 hours

---

**Security Documentation (Days 136-150):**
- [ ] Create comprehensive SECURITY.md
- [ ] Write secure coding guidelines
- [ ] Document threat model
- [ ] Create security architecture diagrams
- [ ] Write penetration testing guide
- [ ] Create security training materials

**Effort:** 60 hours

---

**Security Testing (Days 151-165):**
- [ ] Develop comprehensive security test suite
- [ ] Add fuzzing tests with Atheris
- [ ] Create penetration testing scripts
- [ ] Implement chaos engineering tests
- [ ] Add security regression tests
- [ ] Document security testing procedures

**Effort:** 60 hours

---

**Compliance & Certification (Days 166-180):**
- [ ] Achieve OWASP Top 10 compliance (8/10 PASS)
- [ ] Complete CWE coverage analysis
- [ ] Pass external security audit
- [ ] Obtain security certification
- [ ] Create compliance report
- [ ] Publish security whitepaper

**Effort:** 60 hours

---

**Phase 4 Milestones:**
- ✅ All LOW severity issues resolved
- ✅ Type safety implemented (100% coverage)
- ✅ Security program established
- ✅ OWASP Top 10 compliance achieved
- ✅ Security score improved from 8/10 to 9/10

**Phase 4 Total Effort:** 360 hours (~12 weeks with 2 developers)

---

## Success Metrics & KPIs

### Security Score Progression
| Phase | Timeline | Target Score | Actual Score | Status |
|-------|----------|--------------|--------------|--------|
| Start | Day 0 | - | 2/10 | ⚠️ Critical |
| Phase 1 | Week 2 | 5/10 | TBD | 🔄 In Progress |
| Phase 2 | Week 6 | 7/10 | TBD | ⏳ Pending |
| Phase 3 | Month 3 | 8/10 | TBD | ⏳ Pending |
| Phase 4 | Month 6 | 9/10 | TBD | ⏳ Pending |

### Vulnerability Remediation
| Severity | Total | Phase 1 | Phase 2 | Phase 3 | Phase 4 |
|----------|-------|---------|---------|---------|---------|
| Critical | 4 | 4 | - | - | - |
| High | 8 | - | 8 | - | - |
| Medium | 7 | - | - | 7 | - |
| Low | 4 | - | - | - | 4 |
| **Total** | **23** | **4** | **8** | **7** | **4** |

### OWASP Top 10 Compliance
| Assessment | A01 | A02 | A03 | A04 | A05 | A06 | A07 | A08 | A09 | A10 | Score |
|------------|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-------|
| Current | ❌ | ⚠️ | ❌ | ⚠️ | ❌ | ❌ | ⚠️ | ⚠️ | ⚠️ | ✅ | 2/10 |
| Phase 1 | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ✅ | ⚠️ | ⚠️ | ⚠️ | ✅ | 5/10 |
| Phase 2 | ✅ | ✅ | ✅ | ✅ | ⚠️ | ✅ | ✅ | ⚠️ | ⚠️ | ✅ | 7/10 |
| Phase 3 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ | ✅ | 8/10 |
| Target | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 9/10 |

---

## Resource Allocation

### Team Requirements
| Phase | Duration | Developers | Security | QA | DevOps | Total Hours |
|-------|----------|-----------|----------|-----|--------|-------------|
| Phase 1 | 2 weeks | 2 | 1 | 1 | 1 | 76 |
| Phase 2 | 4 weeks | 2 | 1 | 0.5 | 0.5 | 100 |
| Phase 3 | 6 weeks | 2 | 1 | 0.5 | 1 | 196 |
| Phase 4 | 12 weeks | 2 | 0.5 | 0.5 | 0.5 | 360 |
| **Total** | **24 weeks** | - | - | - | - | **732** |

### Budget Estimate (Approximate)
- **Phase 1:** $15,000 (Critical fixes)
- **Phase 2:** $20,000 (High priority)
- **Phase 3:** $39,000 (Medium priority + automation)
- **Phase 4:** $72,000 (Code quality + security program)
- **Total:** ~$146,000

---

## Risk Management

### Phase 1 Risks
| Risk | Impact | Mitigation |
|------|--------|------------|
| Breaking changes from dependency updates | HIGH | Comprehensive testing, gradual rollout |
| Incomplete command injection blocking | CRITICAL | Extensive fuzzing, penetration testing |
| User resistance to removed features | MEDIUM | Clear communication, migration guide |

### Phase 2 Risks
| Risk | Impact | Mitigation |
|------|--------|------------|
| Performance impact from validation | MEDIUM | Benchmarking, optimization |
| Certificate pinning breaks corporate proxies | MEDIUM | Configurable pinning, clear documentation |
| Complex regex timeout implementation | MEDIUM | Use proven libraries, extensive testing |

### Phase 3 Risks
| Risk | Impact | Mitigation |
|------|--------|------------|
| Python 2 removal alienates users | LOW | Deprecation notice, Python 3 migration guide |
| Rate limiting too aggressive | MEDIUM | Configurable limits, monitoring |

### Phase 4 Risks
| Risk | Impact | Mitigation |
|------|--------|------------|
| Type hints introduce bugs | LOW | Gradual adoption, mypy strictness levels |
| Security overhead slows development | LOW | Automation, clear processes |

---

## Communication Plan

### Stakeholder Updates
- **Weekly:** Status reports to project leadership
- **Bi-weekly:** Security metrics dashboard updates
- **Monthly:** Steering committee presentations
- **Quarterly:** External security advisory publications

### User Communication
- **Phase 1 Start:** Security advisory about critical vulnerabilities
- **Phase 1 Complete:** Release announcement for security patches
- **Phase 2 Complete:** Feature deprecation notices
- **Phase 3 Complete:** Python 2 EOL announcement
- **Phase 4 Complete:** Security certification announcement

### Documentation Updates
- **Continuous:** Update CHANGELOG.md with each fix
- **Phase End:** Comprehensive security documentation
- **Final:** Complete security whitepaper

---

## Testing Strategy

### Phase 1 Testing
- [ ] Manual penetration testing of all CRITICAL vulnerabilities
- [ ] Automated security scanning with Bandit
- [ ] Dependency vulnerability scanning
- [ ] Full regression test suite
- [ ] Process monitoring validation

### Phase 2 Testing
- [ ] Input validation fuzzing
- [ ] Path traversal attack simulations
- [ ] TLS/SSL configuration testing
- [ ] Performance benchmarking
- [ ] Integration testing with all downloaders

### Phase 3 Testing
- [ ] Python 3.8-3.11 compatibility testing
- [ ] Rate limiting behavior validation
- [ ] CSRF attack simulations
- [ ] Multi-user security testing
- [ ] Load testing

### Phase 4 Testing
- [ ] Type checking with mypy
- [ ] Security regression testing
- [ ] Chaos engineering tests
- [ ] External penetration testing
- [ ] Compliance validation

---

## Rollback Plan

### Phase 1 Rollback
- **Trigger:** Critical functionality broken
- **Process:** Revert to previous version, hotfix critical issue
- **Timeline:** 4 hours maximum downtime

### Phase 2-4 Rollback
- **Trigger:** Performance degradation >20% or major bugs
- **Process:** Feature flagging allows gradual rollback
- **Timeline:** 24 hours maximum

### Emergency Procedures
1. Identify critical failure
2. Notify stakeholders
3. Execute rollback playbook
4. Conduct root cause analysis
5. Plan remediation
6. Communicate timeline to users

---

## Maintenance & Continuous Improvement

### Post-Remediation Activities
- **Weekly:** Automated dependency updates via Dependabot
- **Monthly:** Security scan reviews
- **Quarterly:** Threat model updates
- **Annually:** Full security audit

### Security Program
- [ ] Establish security champions program
- [ ] Create security bug bounty program
- [ ] Implement security training for developers
- [ ] Regular security awareness campaigns
- [ ] Continuous vulnerability disclosure program

### Long-term Goals
- Maintain security score >9/10
- Zero critical vulnerabilities
- <7 day mean time to remediate (MTTR)
- 100% automated security testing
- Annual third-party security audits

---

## Appendix A: Quick Reference Checklist

### Phase 1 (Week 1-2) ✓
- [ ] Remove `--cauth` CLI argument (CRIT-1)
- [ ] Fix command injection (CRIT-2)
- [ ] Secure cookie file passing (CRIT-3)
- [ ] Restrict hook execution (CRIT-4)
- [ ] Update dependencies (CVEs)
- [ ] Security testing & validation
- [ ] Release v1.0-security

### Phase 2 (Week 3-6) ✓
- [ ] ReDoS protection (HIGH-1)
- [ ] Fix directory permissions (HIGH-2)
- [ ] Path traversal protection (HIGH-3)
- [ ] SSL certificate pinning (HIGH-4)
- [ ] JSON schema validation (HIGH-5)
- [ ] Netrc permission checking (HIGH-6)
- [ ] Sanitize error logging (HIGH-7)
- [ ] Fix race conditions (HIGH-8)

### Phase 3 (Month 2-3) ✓
- [ ] MathJax SRI (MED-1)
- [ ] Fix timing attacks (MED-2)
- [ ] Remove Python 2 (MED-3)
- [ ] Fix monkey patching (MED-4)
- [ ] Rate limiting (MED-5)
- [ ] Secure temp files (MED-6)
- [ ] CSRF validation (MED-7)
- [ ] Security automation

### Phase 4 (Month 4-6) ✓
- [ ] Cryptographic random (LOW-1)
- [ ] Type hints (LOW-2)
- [ ] String comparisons (LOW-3)
- [ ] Code cleanup (LOW-4)
- [ ] Security program
- [ ] Documentation
- [ ] Compliance

---

## Appendix B: Tools & Technologies

### Security Scanning
- **SAST:** Bandit, Semgrep, CodeQL
- **Dependency:** Safety, pip-audit, Snyk, Dependabot
- **Secrets:** TruffleHog, detect-secrets, GitGuardian
- **Container:** Trivy, Grype (if applicable)

### Testing Tools
- **Fuzzing:** Atheris, Python-AFL
- **Penetration:** OWASP ZAP, Burp Suite
- **Load:** Locust, Apache JMeter

### Code Quality
- **Linting:** pylint, flake8, ruff
- **Formatting:** black, autopep8
- **Type Checking:** mypy, pyright
- **Import Sorting:** isort

### CI/CD Integration
- **GitHub Actions:** Automated security scans
- **Pre-commit:** Local security checks
- **Dependabot:** Automated dependency updates

---

## Appendix C: Success Criteria Checklist

### Phase 1 Success
- ✅ Zero CRITICAL vulnerabilities remaining
- ✅ All dependencies updated to secure versions
- ✅ No CVEs in production dependencies
- ✅ Process list does not expose credentials
- ✅ Command injection blocked
- ✅ Security score ≥5/10

### Phase 2 Success
- ✅ Zero HIGH vulnerabilities remaining
- ✅ Input validation framework complete
- ✅ File operations secured
- ✅ TLS properly configured
- ✅ Security score ≥7/10

### Phase 3 Success
- ✅ Zero MEDIUM vulnerabilities remaining
- ✅ Python 2 support removed
- ✅ Security automation in place
- ✅ Pre-commit hooks configured
- ✅ Security score ≥8/10

### Phase 4 Success
- ✅ Zero known vulnerabilities
- ✅ 100% type hint coverage
- ✅ Pylint score >9.0
- ✅ OWASP Top 10 compliance
- ✅ External audit passed
- ✅ Security score ≥9/10

---

## Document Control

**Version:** 1.0
**Last Updated:** 2025-11-15
**Next Review:** 2025-12-15
**Owner:** Security Team
**Status:** Active

**Approval:**
- [ ] Security Lead
- [ ] Engineering Manager
- [ ] Product Owner
- [ ] CTO/CISO

---

**End of Remediation Roadmap**

*This roadmap should be reviewed and updated monthly to reflect progress and changing priorities.*
