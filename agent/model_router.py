from langchain.chat_models import init_chat_model
from dotenv import load_dotenv

load_dotenv()

_PROVIDERS = {
    "anthropic": lambda: init_chat_model("claude-sonnet-4-6", model_provider="anthropic"),
    # gemini-flash-latest resolves to gemini-3.6-flash, which only has a 20/day free-tier
    # quota; gemini-3.5-flash-lite has 500/day and passed all 4 harness test cases,
    # including multi-step tool chaining.
    "google": lambda: init_chat_model("gemini-3.5-flash-lite", model_provider="google_genai"),
    "groq": lambda: init_chat_model("llama-3.3-70b-versatile", model_provider="groq"),
}


def get_model(provider: str = "google"):
    if provider not in _PROVIDERS:
        raise ValueError(f"Unknown provider '{provider}'. Choose from: {list(_PROVIDERS)}")
    return _PROVIDERS[provider]()
