import os
import time
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
    whole run. List order is priority order (put teammates' free keys first, a paid overflow
    key last — see .env.example) — a key that 429s is skipped for COOLDOWN_SECONDS rather
    than being retried immediately (wastes a call) or abandoned permanently.

    Replaces an earlier "sticky index" design (advance forward, never look back) after
    confirming agent/api.py's get_app_for_provider() is @lru_cache'd — build_graph() runs
    once and the resulting model is reused for every /solve request for the server's whole
    lifetime, so a permanently-sticky index would mean one teammate's burst exhausting a free
    key's ~60s RPM window (tighter than the daily cap, see CLAUDE.md) permanently pushes every
    later request onto the next key (eventually the paid one) even after that window clears.
    Cooldown-based skipping self-heals: once COOLDOWN_SECONDS has passed, list order is
    consulted again, so a recovered free key is retried before the paid one. Only a
    429/RESOURCE_EXHAUSTED error triggers rotation — this is a quota fallback, not a generic
    retry-on-any-error mechanism."""

    # Comfortably longer than Gemini free-tier's 60s RPM window (see CLAUDE.md: "confirmed 15
    # requests/minute, separate from and tighter than the documented 500/day") so a key isn't
    # retried while still inside the window that just rejected it.
    COOLDOWN_SECONDS = 90

    def __init__(self, models: list):
        if not models:
            raise ValueError("_RotatingChatModel needs at least one underlying model")
        self._models = list(models)
        self._cooldown_until = [0.0] * len(self._models)

    def bind_tools(self, tools) -> "_RotatingChatModel":
        wrapped = _RotatingChatModel([model.bind_tools(tools) for model in self._models])
        wrapped._cooldown_until = list(self._cooldown_until)
        return wrapped

    def invoke(self, messages, *args, **kwargs):
        now = time.time()
        candidates = [i for i in range(len(self._models)) if self._cooldown_until[i] <= now]
        if not candidates:
            # Every key is mid-cooldown (a genuinely simultaneous exhaustion across all of
            # them) -- attempt the one that will recover soonest rather than failing outright.
            candidates = [min(range(len(self._models)), key=lambda i: self._cooldown_until[i])]
        last_exc = None
        for i in candidates:
            try:
                return self._models[i].invoke(messages, *args, **kwargs)
            except Exception as exc:
                if _is_quota_error(exc):
                    last_exc = exc
                    self._cooldown_until[i] = now + self.COOLDOWN_SECONDS
                    continue
                raise
        raise last_exc


def _build_rotating_model(model_name: str, provider: str, single_env_var: str) -> List:
    """Returns a list of model instances (one per key), not yet wrapped in
    _RotatingChatModel, so callers can append further fallback models (e.g. a paid
    overflow on a different provider) before wrapping."""
    keys = _load_keys(single_env_var)
    if not keys:
        # No explicit key found in env — build a single model and let the provider library's
        # own default lookup (env var it reads itself, ADC, etc.) apply, same as before.
        return [init_chat_model(model_name, model_provider=provider)]
    return [init_chat_model(model_name, model_provider=provider, api_key=key) for key in keys]


OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


def _build_openrouter_overflow_model():
    """Paid last-resort fallback once every free GOOGLE_API_KEYS entry is exhausted —
    deliberately the SAME model (gemini-3.5-flash-lite) reached through OpenRouter's
    OpenAI-compatible endpoint, not a different model. OpenRouter is prepaid credits, so
    spend is hard-capped at whatever balance is loaded (unlike a plain Google Cloud billing
    budget, which is alert-only by default and does not itself stop spending — confirmed
    before recommending this). Returns None if OPENROUTER_API_KEY isn't set, so this is
    purely additive; nobody's existing .env needs to change."""
    key = os.getenv("OPENROUTER_API_KEY")
    if not key:
        return None
    return init_chat_model(
        "google/gemini-3.5-flash-lite",
        model_provider="openai",
        api_key=key,
        base_url=OPENROUTER_BASE_URL,
    )


def _build_google_model() -> _RotatingChatModel:
    # gemini-flash-latest resolves to gemini-3.6-flash, which only has a 20/day free-tier
    # quota; gemini-3.5-flash-lite has 500/day and passed all 4 harness test cases,
    # including multi-step tool chaining. GOOGLE_API_KEYS (comma-separated) rotates across
    # teammates' keys on a 429; falls back to the single GOOGLE_API_KEY if unset.
    models = _build_rotating_model("gemini-3.5-flash-lite", "google_genai", "GOOGLE_API_KEY")
    overflow = _build_openrouter_overflow_model()
    if overflow is not None:
        # Appended last: _RotatingChatModel's cooldown logic tries list order first, so every
        # free key is preferred over this paid one on every call, not just the first time.
        models.append(overflow)
    return _RotatingChatModel(models)


_PROVIDERS = {
    "anthropic": lambda: init_chat_model("claude-sonnet-4-6", model_provider="anthropic"),
    "google": _build_google_model,
    "groq": lambda: init_chat_model("llama-3.3-70b-versatile", model_provider="groq"),
}


def get_model(provider: str = "google"):
    if provider not in _PROVIDERS:
        raise ValueError(f"Unknown provider '{provider}'. Choose from: {list(_PROVIDERS)}")
    return _PROVIDERS[provider]()
