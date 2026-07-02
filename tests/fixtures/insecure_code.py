"""Test fixture: Security issues for Bandit.

This file deliberately contains security anti-patterns for testing
the BanditAnalyzer.
"""
# ruff: noqa
# type: ignore
# nosec — we actually want these to be caught

import hashlib
import os
import subprocess


# B105: hardcoded password
PASSWORD = "super_secret_password_123"

# B303: use of insecure hash function
def hash_data(data: str) -> str:
    """Uses MD5 — insecure hash. Should be flagged (B303)."""
    return hashlib.md5(data.encode()).hexdigest()


# B602: subprocess call with shell=True
def run_command(cmd: str) -> str:
    """Shell injection risk. Should be flagged (B602)."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


# B108: hardcoded temp directory
def get_temp_file():
    """Hardcoded /tmp. Should be flagged (B108)."""
    return "/tmp/myapp_data.txt"


# B110: try-except-pass
def risky_operation():
    """Silently swallowing exceptions. Should be flagged (B110)."""
    try:
        do_something_dangerous()
    except Exception:
        pass


def do_something_dangerous():
    pass
