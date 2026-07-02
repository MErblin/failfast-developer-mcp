"""Test fixture with inline prompt template."""
# Fake openai client helper for testing
class FakeClient:
    class chat:
        class completions:
            @staticmethod
            def create(*args, **kwargs):
                return "completion"

client = FakeClient()

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
