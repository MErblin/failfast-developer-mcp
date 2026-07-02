"""Test fixture with missing observability telemetry."""
import openai

# Fake openai client helper for testing
class FakeClient:
    class chat:
        class completions:
            @staticmethod
            def create(*args, **kwargs):
                return "completion"

client = FakeClient()

def missing_telemetry():
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "hello"}]
    )
    return response
