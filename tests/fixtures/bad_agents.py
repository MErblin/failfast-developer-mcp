"""Test fixture containing buggy, un-guarded, and unsafe AI/agentic code patterns."""

# Simulated client for AST detection
class FakeClient:
    class chat:
        class completions:
            @staticmethod
            def create(*args, **kwargs):
                pass

client = FakeClient()


def runaway_agent():
    """Buggy agent: loop calls LLM without a step/iteration counter boundary check."""
    while True:
        # Calls create() - an LLM call pattern
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "What is next?"}]
        )
        if "final_answer" in response:
            break


def safe_agent():
    """Safe agent: loop calls LLM but enforces a maximum step limit."""
    steps = 0
    max_steps = 10
    while True:
        if steps >= max_steps:
            break
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "What is next?"}]
        )
        steps += 1
        if "final_answer" in response:
            break


def call_bedrock_unsafe(bedrock_client):
    """Buggy Bedrock: invoke_model called without guardrail Identifier/Version."""
    bedrock_client.invoke_model(
        modelId="anthropic.claude-v2",
        contentType="application/json",
        accept="application/json",
        body="{}"
    )


def call_bedrock_safe(bedrock_client):
    """Safe Bedrock: invoke_model has guardrail identifier and version."""
    bedrock_client.invoke_model(
        modelId="anthropic.claude-v2",
        guardrailIdentifier="g-12345",
        guardrailVersion="1",
        contentType="application/json",
        accept="application/json",
        body="{}"
    )


def call_vertex_unsafe():
    """Buggy Vertex AI: GenerativeModel initialized without safety_settings."""
    from google.generativeai import GenerativeModel
    model = GenerativeModel(model_name="gemini-pro")
    return model


def call_vertex_safe():
    """Safe Vertex AI: GenerativeModel initialized with safety_settings."""
    from google.generativeai import GenerativeModel
    model = GenerativeModel(
        model_name="gemini-pro",
        safety_settings=[{"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_LOW_AND_ABOVE"}]
    )
    return model


def call_azure_unsafe():
    """Buggy Azure OpenAI: client initialized without api_version or with legacy version."""
    from openai import AzureOpenAI
    # 1. Missing api_version
    client1 = AzureOpenAI(azure_endpoint="https://foo.openai.azure.com/")
    # 2. Legacy api_version (year <= 2022)
    client2 = AzureOpenAI(
        azure_endpoint="https://foo.openai.azure.com/",
        api_version="2022-12-01"
    )
    return client1, client2


def call_azure_safe():
    """Safe Azure OpenAI: client initialized with modern api_version."""
    from openai import AzureOpenAI
    client = AzureOpenAI(
        azure_endpoint="https://foo.openai.azure.com/",
        api_version="2024-02-15-preview"
    )
    return client


def parse_output_unsafe():
    """Buggy parsing: json.loads called directly on variable containing 'content' without try-except."""
    import json
    response_content = "some raw string from llm"
    data = json.loads(response_content)
    return data


def parse_output_safe():
    """Safe parsing: json.loads called on content within a try-except block."""
    import json
    response_content = "some raw string from llm"
    try:
        data = json.loads(response_content)
    except json.JSONDecodeError:
        data = {"error": "failed to parse"}
    return data
