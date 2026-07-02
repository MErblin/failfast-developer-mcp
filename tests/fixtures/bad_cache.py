"""Test fixture with missing cache layer."""
# Fake openai client helper for testing
class FakeClient:
    class chat:
        class completions:
            @staticmethod
            def create(*args, **kwargs):
                return "completion"

client = FakeClient()

def missing_cache():
    return client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "What is the capital of France?"}]
    )
