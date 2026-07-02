"""Test fixture: HTTP calls without timeout parameters.

This file deliberately contains unsafe HTTP patterns for testing the
TimeoutAnalyzer. Every call in this file should be flagged.
"""
# ruff: noqa
# type: ignore

import httpx
import requests


def fetch_user_data(user_id: str):
    """No timeout on requests.get — should be flagged."""
    response = requests.get(f"https://api.example.com/users/{user_id}")
    return response.json()


def post_payment(amount: float):
    """No timeout on requests.post — should be flagged."""
    response = requests.post(
        "https://api.example.com/payments",
        json={"amount": amount},
    )
    return response.json()


def fetch_with_httpx(url: str):
    """No timeout on httpx.get — should be flagged."""
    response = httpx.get(url)
    return response.json()


async def async_fetch(url: str):
    """No timeout on httpx async client — should be flagged."""
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        return response.json()


class ApiClient:
    def __init__(self):
        self.client = httpx.Client()

    def get_data(self, path: str):
        """No timeout on self.client.get — should be flagged."""
        return self.client.get(f"https://api.example.com{path}")


# --- These should NOT be flagged (they have timeouts) ---

def safe_fetch(url: str):
    """Has timeout — should NOT be flagged."""
    response = requests.get(url, timeout=10)
    return response.json()


def safe_httpx_fetch(url: str):
    """Has timeout — should NOT be flagged."""
    response = httpx.get(url, timeout=30.0)
    return response.json()
