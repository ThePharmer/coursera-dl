# -*- coding: utf-8 -*-

"""
Pytest configuration and shared fixtures for coursera-dl tests.
"""

import pytest
import tempfile
import shutil
import os
from unittest.mock import Mock


@pytest.fixture
def temp_course_dir():
    """
    Temporary directory for test downloads.

    Yields:
        str: Path to temporary directory

    Cleanup:
        Automatically removes directory after test
    """
    tmpdir = tempfile.mkdtemp(prefix='coursera_test_')
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture
def mock_coursera_session():
    """
    Mock authenticated Coursera session.

    Returns:
        Mock: Mock session object with cookies
    """
    session = Mock()
    session.cookies = {'CAUTH': 'test_token_value'}
    session.get = Mock()
    session.post = Mock()
    return session


@pytest.fixture
def sample_course_json():
    """
    Sample API response for a course.

    Returns:
        dict: Sample course data structure
    """
    return {
        "elements": [{
            "id": "test-course-v1",
            "name": "Test Course",
            "slug": "test-course",
            "description": "A test course for integration testing"
        }]
    }


@pytest.fixture
def sample_lecture_data():
    """
    Sample lecture data for testing parsing.

    Returns:
        dict: Sample lecture structure
    """
    return {
        "id": "lecture-001",
        "name": "Introduction to Testing",
        "slug": "intro-testing",
        "resources": [
            {
                "type": "video",
                "url": "https://example.com/video.mp4",
                "name": "lecture-video.mp4"
            },
            {
                "type": "pdf",
                "url": "https://example.com/slides.pdf",
                "name": "lecture-slides.pdf"
            }
        ]
    }


def pytest_configure(config):
    """
    Configure pytest markers for test categorization.
    """
    config.addinivalue_line(
        "markers",
        "integration: marks tests as integration tests (require network/API)"
    )
    config.addinivalue_line(
        "markers",
        "security: marks tests as security vulnerability tests"
    )
    config.addinivalue_line(
        "markers",
        "slow: marks tests as slow running (>1 second)"
    )
    config.addinivalue_line(
        "markers",
        "unit: marks tests as fast unit tests (default)"
    )
