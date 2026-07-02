"""Test fixture: Unsafe retry patterns.

This file deliberately contains unsafe retry patterns for testing the
RetryAnalyzer. Patterns include: no jitter, no max attempts, constant delay,
bare tenacity decorators, and missing stop conditions.
"""
# ruff: noqa
# type: ignore

import time
import random


# --- Pattern 1: While True loop with sleep, no jitter, no max attempts ---

def retry_no_jitter_no_max(url: str):
    """Retry loop with constant sleep, no jitter, no max attempts.
    Should produce: FF-RETRY-NOJITTER, FF-RETRY-NOMAX, FF-RETRY-CONSTANT
    """
    while True:
        try:
            response = make_request(url)
            return response
        except Exception:
            time.sleep(5)  # constant delay, no jitter


# --- Pattern 2: Retry with max attempts but no jitter ---

def retry_with_max_no_jitter(url: str, max_retries: int = 3):
    """Has max attempts via for loop, but no jitter.
    Should produce: FF-RETRY-NOJITTER, FF-RETRY-CONSTANT
    """
    for attempt in range(max_retries):
        try:
            return make_request(url)
        except Exception:
            if attempt < max_retries - 1:
                time.sleep(2)  # constant, no jitter


# --- Pattern 3: Retry with jitter (SAFE — should NOT be flagged for jitter) ---

def retry_with_jitter(url: str, max_retries: int = 3):
    """Has both max attempts and jitter — should NOT be flagged for jitter."""
    for attempt in range(max_retries):
        try:
            return make_request(url)
        except Exception:
            if attempt < max_retries - 1:
                delay = min(60, 2 ** attempt)
                time.sleep(random.uniform(0, delay))


# --- Pattern 4: Tenacity bare @retry (no arguments) ---

try:
    from tenacity import retry, stop_after_attempt, wait_random_exponential

    @retry
    def bare_retry_function():
        """Bare @retry — no stop, no wait. Should be flagged."""
        return make_request("https://example.com")


    # --- Pattern 5: Tenacity @retry with stop but no wait ---

    @retry(stop=stop_after_attempt(3))
    def retry_no_wait():
        """Has stop but no wait strategy. Should produce FF-RETRY-NOWAIT."""
        return make_request("https://example.com")


    # --- Pattern 6: Safe tenacity usage ---

    @retry(stop=stop_after_attempt(3), wait=wait_random_exponential(multiplier=1, max=60))
    def safe_tenacity_retry():
        """Properly configured — should NOT be flagged."""
        return make_request("https://example.com")

except ImportError:
    pass


# --- Helper ---

def make_request(url: str):
    """Dummy request function."""
    raise ConnectionError("simulated failure")
