"""Test fixture with clean fallback logic."""

# Fake client helper for testing
class FakeClient:
    class chat:
        class completions:
            @staticmethod
            def create(*args, **kwargs):
                return "completion"

client = FakeClient()

def safe_fallback():
    # Safe: Try-Except block executes a secondary LLM call (fallback) on failure
    try:
        response = client.chat.completions.create(model="gpt-4", messages=[])
        return response
    except Exception:
        # Fallback to secondary client call
        response = client.chat.completions.create(model="gpt-3.5-turbo", messages=[])
        return response
