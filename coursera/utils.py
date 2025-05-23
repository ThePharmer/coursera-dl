# -*- coding: utf-8 -*-

"""
This module provides utility functions that are used within the script.
"""

import os
import re
import sys
import time
import json
import errno
import random
import string
import logging
import datetime


from bs4 import BeautifulSoup as BeautifulSoup_
from html import unescape

import six
from six import iteritems
from six.moves.urllib.parse import ParseResult
from six.moves.urllib_parse import unquote_plus

#  six.moves doesn’t support urlparse
if six.PY3:  # pragma: no cover
    from urllib.parse import urlparse, urljoin
else:
    from urlparse import urlparse, urljoin

# Python3 (and six) don't provide string
if six.PY3:
    from string import ascii_letters as string_ascii_letters
    from string import digits as string_digits
else:
    from string import letters as string_ascii_letters
    from string import digits as string_digits

from .define import COURSERA_URL, WINDOWS_UNC_PREFIX

# Force us of bs4 with html.parser


def BeautifulSoup(page): return BeautifulSoup_(page, 'html.parser')


if six.PY2:
    def decode_input(x):
        stdin_encoding = sys.stdin.encoding
        if stdin_encoding is None:
            stdin_encoding = "UTF-8"
        return x.decode(stdin_encoding)
else:
    def decode_input(x):
        return x


def spit_json(obj, filename):
    with open(filename, 'w') as file_object:
        json.dump(obj, file_object, indent=4)


def slurp_json(filename):
    with open(filename) as file_object:
        return json.load(file_object)


def is_debug_run():
    """
    Check whether we're running with DEBUG loglevel.

    @return: True if running with DEBUG loglevel.
    @rtype: bool
    """
    return logging.getLogger().isEnabledFor(logging.DEBUG)


def random_string(length):
    """
    Return a pseudo-random string of specified length.
    """
    valid_chars = string_ascii_letters + string_digits

    return ''.join(random.choice(valid_chars) for i in range(length))


def unescape_html(s):
    s = unescape(s)         # Decode HTML entities
    s = unquote_plus(s)     # Decode URL-encoded characters
    return s


def clean_filename(s, minimal_change=False):
    """
    Sanitize a string to be used as a filename.

    If minimal_change is set to true, then we only strip the bare minimum of
    characters that are problematic for filesystems (namely, ':', '/' and
    '\x00', '\n').
    """

    # First, deal with URL encoded strings
    s = unescape(s)
    s = unquote_plus(s)

    # Strip forbidden characters
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx
    s = (
        s.replace(':', '-')
        .replace('/', '-')
        .replace('<', '-')
        .replace('>', '-')
        .replace('"', '-')
        .replace('\\', '-')
        .replace('|', '-')
        .replace('?', '-')
        .replace('*', '-')
        .replace('\x00', '-')
        .replace('\n', ' ')
    )

    # Remove trailing dots and spaces; forbidden on Windows
    s = s.rstrip(' .')

    if minimal_change:
        return s

    s = s.replace('(', '').replace(')', '')
    s = s.rstrip('.')  # Remove excess of trailing dots

    s = s.strip().replace(' ', '_')
    valid_chars = '-_.()%s%s' % (string.ascii_letters, string.digits)
    return ''.join(c for c in s if c in valid_chars)


def normalize_path(path):
    """
    Normalizes path on Windows OS. This means prepending
    <backslash><backslash>?<backslash> to the path to get access to
    Win32 device namespace instead of Win32 file namespace.
    See https://msdn.microsoft.com/en-us/library/aa365247%28v=vs.85%29.aspx#maxpath

    @param path: Path to normalize.
    @type path: str

    @return: Normalized path.
    @rtype str
    """
    if sys.platform != 'win32':
        return path

    if path.startswith(WINDOWS_UNC_PREFIX):
        return path

    return WINDOWS_UNC_PREFIX + os.path.abspath(path)


def get_anchor_format(a):
    """
    Extract the resource file-type format from the anchor.
    """

    # (. or format=) then (file_extension) then (? or $)
    # e.g. "...format=txt" or "...download.mp4?..."
    fmt = re.search(r"(?:\.|format=)(\w+)(?:\?.*)?$", a)
    return fmt.group(1) if fmt else None


def mkdir_p(path, mode=0o777):
    """
    Create subdirectory hierarchy given in the paths argument.
    """

    try:
        os.makedirs(path, mode)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def clean_url(url):
    """
    Remove params, query and fragment parts from URL so that `os.path.basename`
    and `os.path.splitext` can work correctly.

    @param url: URL to clean.
    @type url: str

    @return: Cleaned URL.
    @rtype: str
    """
    parsed = urlparse(url.strip())
    reconstructed = ParseResult(
        parsed.scheme, parsed.netloc, parsed.path,
        params='', query='', fragment='')
    return reconstructed.geturl()


def fix_url(url):
    """
    Strip whitespace characters from the beginning and the end of the url
    and add a default scheme.
    """
    if url is None:
        return None

    url = url.strip()

    if url and not urlparse(url).scheme:
        url = "http://" + url

    return url


def is_course_complete(last_update):
    """
    Determine is the course is likely to have been terminated or not.

    We return True if the timestamp given by last_update is 30 days or older
    than today's date.  Otherwise, we return True.

    The intended use case for this is to detect if a given courses has not
    seen any update in the last 30 days or more.  Otherwise, we return True,
    since it is probably too soon to declare the course complete.
    """
    rv = False
    if last_update >= 0:
        delta = time.time() - last_update
        max_delta = total_seconds(datetime.timedelta(days=30))
        if delta > max_delta:
            rv = True
    return rv


def total_seconds(td):
    """
    Compute total seconds for a timedelta.

    Added for backward compatibility, pre 2.7.
    """
    return (td.microseconds +
            (td.seconds + td.days * 24 * 3600) * 10 ** 6) // 10 ** 6


def make_coursera_absolute_url(url):
    """
    If given url is relative adds coursera netloc,
    otherwise returns it without any changes.
    """

    if not bool(urlparse(url).netloc):
        return urljoin(COURSERA_URL, url)

    return url


def extend_supplement_links(destination, source):
    """
    Extends (merges) destination dictionary with supplement_links
    from source dictionary. Values are expected to be lists, or any
    data structure that has `extend` method.

    @param destination: Destination dictionary that will be extended.
    @type destination: @see CourseraOnDemand._extract_links_from_text

    @param source: Source dictionary that will be used to extend
        destination dictionary.
    @type source: @see CourseraOnDemand._extract_links_from_text
    """
    for key, value in iteritems(source):
        if key not in destination:
            destination[key] = value
        else:
            destination[key].extend(value)


def print_ssl_error_message(exception):
    """
    Print SSLError message with URL to instructions on how to fix it.
    """
    message = """
#####################################################################
# ATTENTION! PLEASE READ THIS!
#
# The following error has just occurred:
# %s %s
#
# Please read instructions on how to fix this error here:
# https://github.com/coursera-dl/coursera-dl#sslerror-errno-1-_sslc504-error14094410ssl-routinesssl3_read_bytessslv3-alert-handshake-failure
#####################################################################
""" % (type(exception).__name__, str(exception))
    logging.error(message)
