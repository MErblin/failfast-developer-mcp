"""Test fixture with correct, safe architectural practices for LLMs/Agents."""

# Fake client mock for testing
class FakeClient:
    class chat:
        class completions:
            @staticmethod
            def create(*args, **kwargs):
                return "completion"

client = FakeClient()


def safe_observability():
    # Safe: Imports a telemetry library (langfuse)
    import langfuse
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "hi"}]
    )
    return response


def safe_guardrails():
    # Safe: Uses Pydantic validation
    from pydantic import BaseModel
    class OutputSchema(BaseModel):
        reply: str

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "hi"}]
    )
    return response


def safe_prompt():
    # Safe: Short inline prompt variable (< 200 chars or < 3 lines)
    prompt = "Translate: Hello"
    return client.chat.completions.create(model="gpt-4", messages=[{"role": "user", "content": prompt}])


def safe_cache():
    # Safe: Imports gptcache
    import gptcache
    return client.chat.completions.create(model="gpt-4", messages=[{"role": "user", "content": "hi"}])


def safe_fallback():
    # Safe: Try-Except block executes a secondary LLM call (fallback) on failure
    try:
        response = client.chat.completions.create(model="gpt-4", messages=[])
        return response
    except Exception:
        # Fallback to secondary client call
        response = client.chat.completions.create(model="gpt-3.5-turbo", messages=[])
        return response
