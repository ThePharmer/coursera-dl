# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`coursera-dl` is a Python CLI tool for downloading Coursera course materials (videos, PDFs, slides, etc.). It supports both old platform (time-based) and new platform (on-demand) courses.

## Development Setup

**Install dependencies:**
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

**Run the script locally:**
```bash
python -m coursera.coursera_dl -u <user> -p <password> <course-name>
# Or with cookie-based auth (recommended):
python -m coursera.coursera_dl -ca '<CAUTH-value>' <course-name>
```

## Testing

**Run all tests with coverage:**
```bash
py.test coursera/test -v --cov coursera --cov-report html
```

**Run specific test file:**
```bash
py.test coursera/test/test_filter.py -v
```

**Run specific test:**
```bash
py.test coursera/test/test_filter.py::TestClassName::test_method_name -v
```

**Run tests across multiple Python versions:**
```bash
tox
```

**With pyenv (for testing multiple Python versions):**
```bash
pyenv install 3.6.0 3.7.0 3.8.0 3.9.0
pyenv local 3.6.0 3.7.0 3.8.0 3.9.0
tox
```

## Code Quality

**Run linters (mentioned in CONTRIBUTING.md):**
```bash
flake8 coursera/
pylint coursera/
```

## Fabric Tasks

The project uses Fabric for common tasks (see `fabfile.py`):
```bash
fab clean      # Clean build artifacts
fab build      # Build distribution
fab coverage   # Run tests with coverage
fab tox        # Run tox
```

## Architecture

### Core Module Structure

- **`coursera_dl.py`** - Main entry point and orchestration
- **`api.py`** - Coursera API implementations (on-demand, old platform)
  - Handles course materials extraction via API endpoints
  - Quiz/exam downloading and conversion to HTML
  - Notebook (Jupyter) downloading support
- **`cookies.py`** - Authentication and session management
  - Cookie-based authentication (CAUTH parameter - prioritized)
  - netrc file support
  - TLS adapter for secure connections
- **`workflow.py`** - Core download workflow
  - Iterates through modules → sections → lectures
  - Resource filtering and organization
  - File naming and directory structure
- **`downloaders.py`** - Downloader implementations
  - Internal downloader (using requests)
  - External downloaders: aria2, wget, curl, axel
- **`parallel.py`** - Download execution strategies
  - `ParallelDownloader` - concurrent downloads
  - `ConsecutiveDownloader` - sequential downloads
- **`extractors.py`** - Course content extraction from HTML/JSON
- **`network.py`** - HTTP operations and page fetching
- **`commandline.py`** - CLI argument parsing (uses configargparse)
- **`filtering.py`** - Resource filtering logic (by format, section, lecture)
- **`formatting.py`** - File/directory name formatting
- **`utils.py`** - Utilities (BeautifulSoup wrappers, filename cleaning, etc.)
- **`define.py`** - Constants and URL patterns

### Authentication Flow

1. **Cookie-based (recommended)**: Uses CAUTH cookie value from browser
2. **Netrc file**: Credentials stored in `~/.netrc`
3. Session created with TLS v1.2 adapter for security

### Download Workflow

1. Parse command-line arguments
2. Authenticate and get session cookies
3. Fetch course page and extract structure (modules/sections/lectures)
4. Filter resources based on user preferences (formats, section/lecture filters)
5. Download resources using selected downloader (parallel or consecutive)
6. Organize files into directory structure: `course-name/module/section/lecture-resources`

### Key Design Patterns

- **Strategy Pattern**: Different downloader implementations (`downloaders.py`)
- **Iterator Pattern**: Module/section/lecture iteration (`workflow.py`)
- **Factory Pattern**: Downloader selection based on CLI args
- **API Abstraction**: Multiple Coursera API versions handled transparently

## Authentication Notes

- Username/password authentication was deprecated and removed (Python 3.11+ compatibility)
- Cookie-based authentication is now the primary method
- Use CAUTH cookie value from browser: `coursera-dl -ca '<cookie-value>' <course>`
- Alternatively, use netrc file: `coursera-dl -n -- <course>`

## External Dependencies

Key dependencies (see `requirements.txt`):
- **requests** (≥2.10.0) - HTTP library with TLS support
- **beautifulsoup4** (≥4.1.3) - HTML parsing
- **six** (≥1.5.0) - Python 2/3 compatibility
- **attrs** (==18.1.0) - Class decorators
- **configargparse** (≥0.12.0) - Config file + CLI args

## Python Version Support

The project supports Python 2.7 and Python 3.4+, though Python 3.9+ is recommended for better SSL/TLS support.
