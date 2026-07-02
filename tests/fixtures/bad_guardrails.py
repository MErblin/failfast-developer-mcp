"""Test fixture with missing guardrails/validation."""
# Fake openai client helper for testing
class FakeClient:
    class chat:
        class completions:
            @staticmethod
            def create(*args, **kwargs):
                return "completion"

client = FakeClient()

def missing_guardrails(user_query: str):
    prompt = f"Translate this text to French: {user_query}"
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response
