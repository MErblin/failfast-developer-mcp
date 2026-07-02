"""Test fixture with bad architectural practices for LLM/Agent applications."""

# Fake openai client helper for testing
class FakeClient:
    class chat:
        class completions:
            @staticmethod
            def create(*args, **kwargs):
                return "completion"

client = FakeClient()


# 1. Trigger FF-AI-OBSERVABILITY (Imports openai but does not import telemetry library)
def missing_telemetry():
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "hello"}]
    )
    return response


# 2. Trigger FF-AI-GUARDRAILS (Has LLM call but lacks Pydantic validation or guardrail SDK imports)
def missing_guardrails(user_query: str):
    prompt = f"Translate this text to French: {user_query}"
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response


# 3. Trigger FF-AI-PROMPT-INLINE (Has a variable named 'system_prompt' matching keyword with long string > 200 chars and > 3 lines)
def inline_prompt():
    system_prompt = """You are a highly specialized medical assistant.
    Your task is to take clinical notes and extract patient diagnoses.
    Please ensure you format the output as a bulleted list.
    Only extract diagnoses mentioned in the text.
    Do not make assumptions or add external info.
    If no diagnoses are found, return 'None'."""
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "Notes..."}
        ]
    )
    return response


# 4. Trigger FF-AI-CACHE (Has LLM call but lacks caching libraries like gptcache/redis)
def missing_cache():
    return client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "What is the capital of France?"}]
    )


# 5. Trigger FF-AI-FALLBACK (LLM call wrapped in try-except but except handler only prints/logs/raises, no backup call)
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


# --- SAFE REPRESENTATIONS (should NOT be flagged) ---

def safe_observability():
    # Safe: Imports a telemetry library
    import langfuse
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "hi"}]
    )
    return response


def safe_guardrails():
    # Safe: Uses Pydantic to parse outputs (structured outputs)
    from pydantic import BaseModel
    class OutputSchema(BaseModel):
        reply: str

    # Pydantic is imported, so parser counts this as safe validation mapping
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
    # Safe: Try-Except block wraps LLM call and except block makes a secondary LLM call (fallback)
    try:
        response = client.chat.completions.create(model="gpt-4", messages=[])
        return response
    except Exception:
        # Fallback to secondary call
        response = client.chat.completions.create(model="gpt-3.5-turbo", messages=[])
        return response
