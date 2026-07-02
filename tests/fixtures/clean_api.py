"""Test fixture: Clean Python API code.

This file should PASS all FailFast checks. It follows production best
practices: timeouts on HTTP calls, proper retry with jitter, low complexity,
no security issues.
"""
# ruff: noqa
# type: ignore

import random
import time
from typing import Any


def fetch_user(user_id: str, timeout: float = 10.0) -> dict[str, Any]:
    """Fetch user data with proper timeout."""
    import requests

    response = requests.get(
        f"https://api.example.com/users/{user_id}",
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def retry_with_backoff(
    func,
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
):
    """Retry with capped exponential backoff and full jitter."""
    for attempt in range(max_attempts):
        try:
            return func()
        except Exception:
            if attempt == max_attempts - 1:
                raise
            delay = min(max_delay, base_delay * (2 ** attempt))
            time.sleep(random.uniform(0, delay))


def calculate_total(items: list[dict[str, float]]) -> float:
    """Simple, low-complexity calculation."""
    total = 0.0
    for item in items:
        price = item.get("price", 0.0)
        quantity = item.get("quantity", 1.0)
        total += price * quantity
    return round(total, 2)
