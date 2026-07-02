"""Test fixture with missing fallback logic."""
# Fake openai client helper for testing
class FakeClient:
    class chat:
        class completions:
            @staticmethod
            def create(*args, **kwargs):
                return "completion"

client = FakeClient()

def missing_fallback():
    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Calculate..."}]
        )
        return response
    except Exception as e:
        print(f"Error calling LLM: {e}")
        raise e
