# coursera-dl Development Roadmap

**Last Updated:** 2025-11-17
**Planning Horizon:** 6 months (Nov 2025 - May 2026)

---

## Vision

Transform coursera-dl from a feature-rich but security-vulnerable tool into a **secure, modern, well-tested Python application** that serves as a reliable solution for downloading Coursera materials.

---

## Current State (v0.11.5)

### Strengths
- ✅ Well-architected codebase
- ✅ Supports old and new Coursera platforms
- ✅ Multiple download strategies
- ✅ Excellent documentation
- ✅ Active user community

### Issues
- 🔴 4 CRITICAL security vulnerabilities
- 🔴 8 HIGH severity issues
- 🟡 7 MEDIUM severity issues
- ⚠️ Dependencies 5+ years outdated
- ⚠️ Python 2 support (EOL since 2020)
- ⚠️ No CI/CD security scanning

**Overall Security Score:** 2/10 ⚠️

---

## Roadmap Phases

### Phase 1: Foundation & Security Baseline
**Version:** 0.12.0
**Timeline:** Month 1 (Weeks 1-4)
**Goal:** Establish foundation and eliminate dependency vulnerabilities

### Phase 2: Critical Security Fixes
**Version:** 0.13.0
**Timeline:** Months 2-3 (Weeks 5-12)
**Goal:** Fix all CRITICAL and HIGH severity vulnerabilities

### Phase 3: Modernization
**Version:** 0.14.0
**Timeline:** Months 4-6 (Weeks 13-24)
**Goal:** Remove technical debt, improve maintainability

---

## Phase 1: Foundation & Security Baseline (v0.12.0)

**Target Release:** Week 4
**Security Score Target:** 4/10 → 6/10

### Week 1: Documentation & Quick Wins

**Documentation:**
- [x] Complete repository audit (REPOSITORY_REVIEW.md)
- [x] Create security policy (SECURITY.md)
- [x] Establish roadmap (ROADMAP.md)
- [x] Document dependency status (DEPENDENCIES.md)
- [ ] Update README with security warnings

**Code Quality (Low-Risk Fixes):**
- [ ] Fix string identity comparisons (`is ''` → `== ''`) - api.py:967, 1612
- [ ] Remove unused imports - utils.py:14
- [ ] Fix directory permissions (0o777 → 0o755) - utils.py:171
- [ ] Improve exception handling specificity - parallel.py:33, coursera_dl.py:245

**Test Infrastructure:**
- [ ] Add pytest fixtures for integration tests
- [ ] Create baseline integration tests (3 critical paths)
- [ ] Add security test placeholders (xfail)
- [ ] Update coverage configuration

**Deliverables:**
- ✅ Comprehensive audit report
- ✅ Security policy
- ✅ Test infrastructure
- ✅ CI/CD foundation

---

### Week 2: CI/CD & Automated Security

**GitHub Actions:**
- [ ] Set up test workflow (Python 3.8-3.11, Linux/Mac/Windows)
- [ ] Integrate Bandit security scanner
- [ ] Integrate Safety dependency checker
- [ ] Configure Codecov for coverage tracking
- [ ] Add pre-commit hooks (black, flake8, bandit)

**Issue Templates:**
- [ ] Bug report template
- [ ] Security fix tracking template
- [ ] Feature request template

**Deliverables:**
- ✅ Automated testing on all commits
- ✅ Security scanning in CI/CD
- ✅ Standardized issue tracking

---

### Week 3: Dependency Updates

**Critical Updates:**
```txt
# BEFORE
requests>=2.10.0         # CVE-2023-32681
urllib3>=1.23           # CVE-2023-43804, CVE-2023-45803
attrs==18.1.0           # 5 years outdated
beautifulsoup4>=4.1.3   # 13 years old

# AFTER
requests>=2.31.0        # CVE fixes
urllib3>=2.0.7          # CVE fixes (MAJOR VERSION)
attrs>=23.0.0           # Current
beautifulsoup4>=4.12.0  # Current
keyring>=24.0.0         # Security updates
configargparse>=1.5.0   # Bug fixes
```

**Tasks:**
- [ ] Update requirements.txt
- [ ] Test urllib3 2.x compatibility (BREAKING)
- [ ] Test attrs 23.x compatibility
- [ ] Run full test suite on updated dependencies
- [ ] Document breaking changes
- [ ] Update documentation

**Breaking Changes Expected:**
- urllib3 2.x removes Python 2 support
- Some API changes in urllib3
- attrs import patterns may change

**Deliverables:**
- ✅ All dependencies patched (CVE-free)
- ✅ Compatibility tests pass
- ✅ Migration guide for users

---

### Week 4: Integration Testing & Release

**Integration Tests:**
- [ ] Mock Coursera API responses
- [ ] Test full download workflow
- [ ] Test authentication flow
- [ ] Test each downloader (wget, curl, aria2, axel, internal)
- [ ] Test error handling
- [ ] Test resume functionality

**Release Preparation:**
- [ ] Update CHANGELOG.md
- [ ] Update version to 0.12.0
- [ ] Tag release in git
- [ ] Build and test package
- [ ] Publish to PyPI (test first)
- [ ] Announce release

**v0.12.0 Success Criteria:**
- ✅ 0 known CVEs in dependencies
- ✅ CI/CD pipeline operational
- ✅ Test coverage ≥50%
- ✅ All tests pass on Python 3.8-3.11
- ✅ Security score improved to 6/10

---

## Phase 2: Critical Security Fixes (v0.13.0)

**Target Release:** Week 12
**Security Score Target:** 6/10 → 8/10

### Week 5-6: CRIT-1 & CRIT-2 Fixes

**CRIT-1: Remove CAUTH Exposure**
- [ ] Remove `--cauth` CLI argument (commandline.py:348-354)
- [ ] Update documentation to use `--cookies-file` only
- [ ] Add deprecation notice in v0.12.x
- [ ] Migration guide for existing users
- [ ] Test authentication still works

**CRIT-2: Command Injection Prevention**
- [ ] Create argument validation module (validators.py)
- [ ] Implement whitelist for downloader arguments
- [ ] Add `shlex.quote()` escaping
- [ ] Add comprehensive security tests
- [ ] Document allowed arguments

**Code Changes:**
```python
# validators.py (new)
ALLOWED_DOWNLOADER_ARGS = {
    '--max-tries', '--timeout', '--retry-wait',
    '--quiet', '--verbose', '--continue'
}

def validate_downloader_args(args: List[str]) -> List[str]:
    """Validate and sanitize downloader arguments"""
    for arg in args:
        if not any(arg.startswith(allowed) for allowed in ALLOWED_DOWNLOADER_ARGS):
            raise ValueError(f"Disallowed argument: {arg}")
    return [shlex.quote(arg) for arg in args]
```

**Deliverables:**
- ✅ CRIT-1 fixed (CAUTH removed)
- ✅ CRIT-2 fixed (no command injection)
- ✅ Security tests added
- ✅ Migration guide

---

### Week 7-8: CRIT-3 & CRIT-4 Fixes

**CRIT-3: Hook Validation**
- [ ] Create hook allowlist mechanism
- [ ] Add hook validation before execution
- [ ] Document safe hook usage
- [ ] Add security warnings

**CRIT-4: Secure Cookie Files**
- [ ] Use temporary cookie files for external downloaders
- [ ] Set restrictive permissions (0o600)
- [ ] Clean up temp files after use
- [ ] Test on Linux/Mac/Windows

**Code Changes:**
```python
# downloaders.py
def _prepare_cookies(self, command, url):
    # Create temp file with restrictive permissions
    fd, cookie_file = tempfile.mkstemp(suffix='.txt', prefix='coursera_')
    os.chmod(cookie_file, 0o600)

    try:
        # Write cookies to temp file
        with os.fdopen(fd, 'w') as f:
            f.write(self._get_cookies(url))
        command.extend(['--cookie', cookie_file])
    finally:
        os.unlink(cookie_file)
```

**Deliverables:**
- ✅ CRIT-3 fixed (hooks validated)
- ✅ CRIT-4 fixed (secure cookie files)
- ✅ Cross-platform testing

---

### Week 9-10: HIGH Priority Fixes

**HIGH-2: ReDoS Protection**
- [ ] Add regex timeout using `regex` module
- [ ] Validate user-supplied regex patterns
- [ ] Add complexity limits
- [ ] Test with catastrophic backtracking patterns

**HIGH-3: Path Traversal Protection**
- [ ] Implement safe path joining
- [ ] Validate resolved paths stay within base directory
- [ ] Add symlink protection
- [ ] Test with malicious paths

**HIGH-4: JSON Schema Validation**
- [ ] Define JSON schemas for API responses
- [ ] Use `jsonschema` library for validation
- [ ] Add fallback for schema violations
- [ ] Test with malformed API responses

**Deliverables:**
- ✅ 3 HIGH severity issues fixed
- ✅ Security test coverage ≥80%

---

### Week 11-12: Testing & Release

**Comprehensive Testing:**
- [ ] Security penetration testing
- [ ] Fuzz testing for input validation
- [ ] End-to-end integration tests
- [ ] Performance regression tests
- [ ] Cross-platform testing

**External Security Audit:**
- [ ] (Optional) Hire external security firm
- [ ] Address any new findings
- [ ] Document audit results

**Release Preparation:**
- [ ] Update CHANGELOG.md
- [ ] Update SECURITY.md (close vulnerabilities)
- [ ] Update version to 0.13.0
- [ ] Create security advisory for fixed CVEs
- [ ] Tag and publish release

**v0.13.0 Success Criteria:**
- ✅ 0 CRITICAL vulnerabilities
- ✅ 0 HIGH vulnerabilities
- ✅ Security score 8/10
- ✅ Test coverage ≥70%
- ✅ All integration tests pass

---

## Phase 3: Modernization (v0.14.0)

**Target Release:** Week 24
**Code Quality Target:** 8/10

### Week 13-15: Drop Python 2 Support

**Motivation:**
- Python 2 EOL since January 2020 (5+ years)
- Security risk (no patches)
- Blocks use of modern features

**Tasks:**
- [ ] Remove `six` dependency
- [ ] Remove Python 2 compatibility code
- [ ] Use Python 3.8+ features (f-strings, walrus operator, etc.)
- [ ] Update type hints with modern syntax
- [ ] Remove `from __future__ import` statements
- [ ] Update CI/CD (remove Python 2.7 testing)

**Benefits:**
- Cleaner codebase
- Better performance
- Access to modern features
- Smaller dependency footprint

**Deliverables:**
- ✅ Python 3.8+ only
- ✅ Removed ~500 lines of compatibility code
- ✅ Updated documentation

---

### Week 16-18: Add Type Hints

**Goal:** Add type hints to all public APIs

**Tasks:**
- [ ] Install mypy and configure
- [ ] Add type hints to all function signatures
- [ ] Add type hints for class attributes
- [ ] Use `typing` module (Optional, List, Dict, etc.)
- [ ] Run mypy in CI/CD
- [ ] Fix all type errors

**Example:**
```python
# BEFORE
def download_course(session, class_name, path):
    ...

# AFTER
def download_course(
    session: requests.Session,
    class_name: str,
    path: Path,
    overwrite: bool = False
) -> DownloadResult:
    ...
```

**Deliverables:**
- ✅ 100% of public APIs type-hinted
- ✅ mypy passing in strict mode
- ✅ Better IDE support

---

### Week 19-21: Refactoring

**Split api.py (1,632 lines → multiple files):**
```
api/
├── __init__.py
├── on_demand.py      # OnDemandCoursera class
├── legacy.py         # CourseraLegacy class
├── parsers.py        # HTML/JSON parsing
└── models.py         # Data classes
```

**Remove Monkeypatch:**
- [ ] Create CourseraCookie wrapper class
- [ ] Replace monkeypatch with wrapper
- [ ] Test cookie handling still works

**Extract Configuration:**
- [ ] Create CourseraConfig dataclass
- [ ] Centralize all configuration
- [ ] Simplify CLI argument handling

**Compile Regex Patterns:**
- [ ] Move regex compilation to module level
- [ ] Benchmark performance improvement

**Deliverables:**
- ✅ Codebase more maintainable
- ✅ No files >800 lines
- ✅ ~40% performance improvement (regex)

---

### Week 22-24: Testing & Documentation

**Testing:**
- [ ] Increase coverage to 75%+
- [ ] Add performance benchmarks
- [ ] Add mutation testing
- [ ] Document testing strategy

**Documentation:**
- [ ] API documentation (Sphinx)
- [ ] Developer guide
- [ ] Architecture decision records (ADRs)
- [ ] Performance tuning guide
- [ ] Security best practices guide

**Release:**
- [ ] Update CHANGELOG.md
- [ ] Update version to 0.14.0
- [ ] Tag and publish release
- [ ] Blog post about improvements

**v0.14.0 Success Criteria:**
- ✅ Code quality 8/10
- ✅ Test coverage ≥75%
- ✅ Type hints on all public APIs
- ✅ No files >800 lines
- ✅ Full API documentation

---

## Future Considerations (v0.15.0+)

### Potential Features

**Better API:**
- Use Coursera's GraphQL API (if available)
- More robust error handling
- Progress tracking UI

**Performance:**
- Async/await for API calls
- Parallel video segment downloads
- Smarter caching

**Features:**
- Download subtitles in multiple languages
- Generate course notes/summaries
- Integration with note-taking apps
- Docker image for easy deployment

**Quality:**
- Achieve 90%+ test coverage
- Zero flake8/pylint warnings
- Full type coverage (mypy --strict)
- Comprehensive documentation

---

## Metrics & KPIs

### Security Metrics

| Metric | v0.11.5 | v0.12.0 | v0.13.0 | v0.14.0 |
|--------|---------|---------|---------|---------|
| CRITICAL vulns | 4 | 4 | 0 | 0 |
| HIGH vulns | 8 | 6 | 0 | 0 |
| Known CVEs | 3 | 0 | 0 | 0 |
| Security score | 2/10 | 6/10 | 8/10 | 9/10 |

### Code Quality Metrics

| Metric | v0.11.5 | v0.12.0 | v0.13.0 | v0.14.0 |
|--------|---------|---------|---------|---------|
| Test coverage | 40% | 50% | 70% | 75% |
| Type coverage | 0% | 0% | 20% | 100% |
| Code quality | 6/10 | 6/10 | 7/10 | 8/10 |
| Largest file | 1632 | 1632 | 1632 | <800 |
| Python versions | 2.7-3.11 | 3.8-3.11 | 3.8-3.11 | 3.8-3.12 |

---

## Dependencies

### Current State (v0.11.5)
```
beautifulsoup4>=4.1.3    # 13 years old
requests>=2.10.0         # CVE-2023-32681
urllib3>=1.23           # CVE-2023-43804
attrs==18.1.0           # 5 years old
six>=1.5.0              # Maintenance mode
```

### After v0.12.0
```
beautifulsoup4>=4.12.0   # Current
requests>=2.31.0        # Patched
urllib3>=2.0.7          # Patched
attrs>=23.0.0           # Current
six>=1.16.0             # (removed in v0.14.0)
```

### After v0.14.0
```
beautifulsoup4>=4.12.0
requests>=2.31.0
urllib3>=2.0.7
attrs>=23.0.0
# six removed (Python 3.8+ only)
```

---

## Risk Management

### High Risk Items

| Risk | Mitigation | Contingency |
|------|------------|-------------|
| urllib3 2.x breaks compatibility | Extensive testing in v0.12.0 | Provide compatibility shim |
| Removing --cauth angers users | Deprecation notice, migration guide | Keep for 1 version with warning |
| Coursera changes API | Version detection, graceful fallback | Maintain legacy support |
| Performance regression | Benchmarking, profiling | Optimize hot paths |

### Medium Risk Items

| Risk | Mitigation |
|------|------------|
| External downloader changes | Version detection |
| Platform-specific issues | CI/CD on Linux/Mac/Windows |
| Regex timeout false positives | Tune timeout values |

---

## Communication Plan

### Release Announcements

**v0.12.0:**
- GitHub release notes
- PyPI announcement
- Update README

**v0.13.0:**
- GitHub security advisory (for fixed CVEs)
- Blog post about security improvements
- Email to known users (if list available)

**v0.14.0:**
- Major announcement (Python 2 removal)
- Migration guide
- Community outreach

### User Communication

- **Deprecation notices:** 1 version in advance
- **Breaking changes:** Clear migration guides
- **Security issues:** Responsible disclosure
- **New features:** Documentation and examples

---

## Success Criteria

### Overall Goals

By end of Phase 3 (v0.14.0):

- ✅ **Security:** 0 CRITICAL, 0 HIGH vulnerabilities
- ✅ **Quality:** Code quality 8/10
- ✅ **Testing:** Coverage ≥75%
- ✅ **Modern:** Python 3.8+, type hints, no tech debt
- ✅ **Docs:** Comprehensive user & developer docs
- ✅ **CI/CD:** Automated testing & security scanning
- ✅ **Community:** Active, engaged users

---

## Resource Requirements

### Development Effort

| Phase | Weeks | Hours/Week | Total Hours |
|-------|-------|------------|-------------|
| Phase 1 (v0.12.0) | 4 | 20 | 80 |
| Phase 2 (v0.13.0) | 8 | 20 | 160 |
| Phase 3 (v0.14.0) | 12 | 15 | 180 |
| **Total** | **24** | **~17** | **420** |

### Team Composition

**Phase 1:** 1 developer (foundation work)
**Phase 2:** 1 developer + security consultant
**Phase 3:** 1-2 developers (refactoring)

---

## Changelog

| Date | Version | Change |
|------|---------|--------|
| 2025-11-17 | 1.0 | Initial roadmap created |

---

*For detailed findings, see [REPOSITORY_REVIEW.md](REPOSITORY_REVIEW.md)*
*For security policy, see [SECURITY.md](SECURITY.md)*
*For dependency status, see [DEPENDENCIES.md](DEPENDENCIES.md)*
