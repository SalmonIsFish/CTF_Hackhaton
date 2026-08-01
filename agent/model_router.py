import os
from typing import List

from google.genai.errors import APIError
from langchain.chat_models import init_chat_model
from dotenv import load_dotenv

load_dotenv()


def _load_keys(single_env_var: str) -> List[str]:
    """Read a comma-separated `<VAR>S` env var (e.g. GOOGLE_API_KEYS) for multi-key
    rotation across teammates' keys; falls back to the single `<VAR>` if the plural form
    isn't set, so nobody's existing .env breaks."""
    plural_value = os.getenv(single_env_var + "S")
    if plural_value:
        keys = [key.strip() for key in plural_value.split(",") if key.strip()]
        if keys:
            return keys
    single_value = os.getenv(single_env_var)
    return [single_value] if single_value else []


def _is_quota_error(exc: BaseException) -> bool:
    """True if exc, or anything in its __cause__ chain, is a 429/RESOURCE_EXHAUSTED APIError.
    langchain-google-genai's ChatGoogleGenerativeAI wraps the real google.genai.errors.APIError
    in its own ChatGoogleGenerativeAIError (`raise ... from e`) before it ever reaches a caller
    — confirmed against a real quota-exhaustion run, not just the mocked unit test — so checking
    isinstance(exc, APIError) directly (the original implementation) never matched a real quota
    error, only a directly-raised one. Walking __cause__ catches both shapes."""
    seen = exc
    while seen is not None:
        if isinstance(seen, APIError) and (seen.code == 429 or seen.status == "RESOURCE_EXHAUSTED"):
            return True
        seen = seen.__cause__
    return False


class _RotatingChatModel:
    """Wraps one or more same-provider model instances (one per API key) and falls back to
    the next key when the current one hits a quota/rate-limit error, instead of failing the
    whole run. Sticky index: remembers the last-working key across calls within a run rather
    than always retrying from key 0. Only a 429/RESOURCE_EXHAUSTED error triggers rotation —
    this is a quota fallback, not a generic retry-on-any-error mechanism."""

    def __init__(self, models: list):
        if not models:
            raise ValueError("_RotatingChatModel needs at least one underlying model")
        self._models = list(models)
        self._index = 0

    def bind_tools(self, tools) -> "_RotatingChatModel":
        return _RotatingChatModel([model.bind_tools(tools) for model in self._models])

    def invoke(self, messages, *args, **kwargs):
        last_exc = None
        for _ in range(len(self._models)):
            model = self._models[self._index]
            try:
                return model.invoke(messages, *args, **kwargs)
            except Exception as exc:
                if _is_quota_error(exc):
                    last_exc = exc
                    self._index = (self._index + 1) % len(self._models)
                    continue
                raise
        raise last_exc


def _build_rotating_model(model_name: str, provider: str, single_env_var: str) -> _RotatingChatModel:
    keys = _load_keys(single_env_var)
    if not keys:
        # No explicit key found in env — build a single model and let the provider library's
        # own default lookup (env var it reads itself, ADC, etc.) apply, same as before.
        return _RotatingChatModel([init_chat_model(model_name, model_provider=provider)])
    return _RotatingChatModel(
        [init_chat_model(model_name, model_provider=provider, api_key=key) for key in keys]
    )


_PROVIDERS = {
    "anthropic": lambda: init_chat_model("claude-sonnet-4-6", model_provider="anthropic"),
    # gemini-flash-latest resolves to gemini-3.6-flash, which only has a 20/day free-tier
    # quota; gemini-3.5-flash-lite has 500/day and passed all 4 harness test cases,
    # including multi-step tool chaining. GOOGLE_API_KEYS (comma-separated) rotates across
    # teammates' keys on a 429; falls back to the single GOOGLE_API_KEY if unset.
    "google": lambda: _build_rotating_model("gemini-3.5-flash-lite", "google_genai", "GOOGLE_API_KEY"),
    "groq": lambda: init_chat_model("llama-3.3-70b-versatile", model_provider="groq"),
}


def get_model(provider: str = "google"):
    if provider not in _PROVIDERS:
        raise ValueError(f"Unknown provider '{provider}'. Choose from: {list(_PROVIDERS)}")
    return _PROVIDERS[provider]()
