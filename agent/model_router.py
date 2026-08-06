import os
import time
from typing import List

from google.genai.errors import APIError
from langchain.chat_models import init_chat_model
from dotenv import load_dotenv

load_dotenv()

# Cap how long a single model call may hang. The network *tools* all have their own timeouts, but
# a model.invoke() (think()/triage() in agent/graph.py) had none -- so a stalled Gemini request
# could freeze a whole /solve run, and the live demo with it, indefinitely. think() already catches
# model-layer exceptions and ends the run cleanly, so a fired timeout surfaces as a graceful end,
# not a crash. Generous by default (a normal solve completes well within it); override via env.
try:
    MODEL_TIMEOUT_SECONDS = float(os.getenv("MODEL_TIMEOUT_SECONDS", "60"))
except ValueError:
    MODEL_TIMEOUT_SECONDS = 60.0


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


def _is_dead_key_error(exc: BaseException) -> bool:
    """True if exc, or anything in its __cause__ chain, is a 401/UNAUTHENTICATED APIError --
    a credential that is simply broken (revoked, expired, or -- the real case that triggered
    this -- an 'AQ.'-prefixed auth key whose bound service account was deleted/disabled,
    ACCESS_TOKEN_TYPE_UNSUPPORTED/ACCOUNT_STATE_INVALID), as opposed to _is_quota_error's
    'this key is fine but temporarily rate-limited' case. Distinguished because the right
    response differs: a quota error is worth retrying once COOLDOWN_SECONDS passes, but a dead
    key never recovers on its own, so treating it the same way would mean silently re-trying a
    permanently broken key every COOLDOWN_SECONDS for the rest of the run. See
    _RotatingChatModel.invoke, which gives this class of error its own, much longer cooldown."""
    seen = exc
    while seen is not None:
        if isinstance(seen, APIError) and (seen.code == 401 or seen.status == "UNAUTHENTICATED"):
            return True
        seen = seen.__cause__
    return False


# A separate, transient class of failure from quota exhaustion -- confirmed live: "503
# UNAVAILABLE ... This model is currently experiencing high demand ... Please try again later."
# Google's own message says this resolves itself; it's shared infrastructure being temporarily
# overloaded, not a per-key problem, so rotating to a different key (the quota-error response)
# doesn't obviously help and isn't the right response -- a short retry on the SAME key is.
# Before this, a transient 503 hit _RotatingChatModel.invoke()'s bare `raise` (the "not a quota
# error" path) and killed the whole run outright instead of just trying again.
TRANSIENT_RETRY_ATTEMPTS = 3
TRANSIENT_RETRY_BACKOFF_SECONDS = 2.0


def _is_transient_error(exc: BaseException) -> bool:
    """True if exc, or anything in its __cause__ chain, is a transient server-side APIError
    (503/UNAVAILABLE, 500/INTERNAL, 504/DEADLINE_EXCEEDED) -- distinct from _is_quota_error's
    429/RESOURCE_EXHAUSTED check."""
    seen = exc
    while seen is not None:
        if isinstance(seen, APIError) and (
            seen.code in (500, 503, 504)
            or seen.status in ("UNAVAILABLE", "INTERNAL", "DEADLINE_EXCEEDED")
        ):
            return True
        seen = seen.__cause__
    return False


def _invoke_with_transient_retry(model, messages, args, kwargs):
    """Retry a single model.invoke() call up to TRANSIENT_RETRY_ATTEMPTS times, with a short
    linearly-increasing backoff, ONLY for _is_transient_error failures -- any other exception
    (including a quota error, handled one layer up by _RotatingChatModel) propagates on the
    first attempt, unchanged."""
    last_exc: BaseException = RuntimeError("unreachable: TRANSIENT_RETRY_ATTEMPTS must be >= 1")
    for attempt in range(TRANSIENT_RETRY_ATTEMPTS):
        try:
            return model.invoke(messages, *args, **kwargs)
        except Exception as exc:
            if _is_transient_error(exc) and attempt < TRANSIENT_RETRY_ATTEMPTS - 1:
                last_exc = exc
                time.sleep(TRANSIENT_RETRY_BACKOFF_SECONDS * (attempt + 1))
                continue
            raise
    raise last_exc


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
    consulted again, so a recovered free key is retried before the paid one. Only two error
    shapes trigger ROTATION to a different key — this is a fallback for known-recoverable
    problems with the CURRENT key, not a generic retry-on-any-error mechanism: a
    429/RESOURCE_EXHAUSTED quota error (cooldown COOLDOWN_SECONDS, since the window passes on
    its own) and a 401/UNAUTHENTICATED dead-key error (cooldown DEAD_KEY_COOLDOWN_SECONDS,
    effectively permanent, since a broken credential does not fix itself) — see
    _is_quota_error/_is_dead_key_error. A dead PRIMARY key still reaches a paid OpenRouter
    overflow appended to the list (see _build_google_model), which is the whole reason this
    distinction exists: without it, a 401 on every call would just raise immediately and never
    reach the working fallback sitting right after it. A separate, transient class of error
    (503/UNAVAILABLE and similar -- shared infrastructure temporarily overloaded, not a
    per-key issue) gets a few retries on the SAME key first, via _invoke_with_transient_retry,
    before falling through to this class's own exception handling."""

    # Comfortably longer than Gemini free-tier's 60s RPM window (see CLAUDE.md: "confirmed 15
    # requests/minute, separate from and tighter than the documented 500/day") so a key isn't
    # retried while still inside the window that just rejected it.
    COOLDOWN_SECONDS = 90

    # A dead key (see _is_dead_key_error) does not recover on its own the way a quota window
    # does -- regenerating one requires a human. Cooling it down for the rest of the process
    # lifetime, rather than COOLDOWN_SECONDS, avoids burning one wasted call per request on a
    # key confirmed broken (real case: an "AQ." auth key whose bound service account was
    # deleted, 401 ACCESS_TOKEN_TYPE_UNSUPPORTED on every single call, not just sometimes).
    DEAD_KEY_COOLDOWN_SECONDS = 10**9

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
                return _invoke_with_transient_retry(self._models[i], messages, args, kwargs)
            except Exception as exc:
                if _is_quota_error(exc):
                    last_exc = exc
                    self._cooldown_until[i] = now + self.COOLDOWN_SECONDS
                    continue
                if _is_dead_key_error(exc):
                    last_exc = exc
                    self._cooldown_until[i] = now + self.DEAD_KEY_COOLDOWN_SECONDS
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
        return [init_chat_model(model_name, model_provider=provider, timeout=MODEL_TIMEOUT_SECONDS)]
    return [
        init_chat_model(
            model_name, model_provider=provider, api_key=key, timeout=MODEL_TIMEOUT_SECONDS
        )
        for key in keys
    ]


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
        timeout=MODEL_TIMEOUT_SECONDS,
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


# Groq uses gpt-oss-120b, NOT llama-3.3-70b-versatile: CLAUDE.md documents the Llama model as
# reproducibly emitting malformed tool-call syntax that Groq rejects outright (400 tool_use_failed),
# making it useless as a fallback the moment any tool call is needed. gpt-oss-120b has reliable
# tool-call syntax (its weakness is multi-step chaining, per CLAUDE.md) -- a working fallback beats
# a broken one. Groq is never the primary provider; this path is only reached if explicitly selected.
_PROVIDERS = {
    "anthropic": lambda: init_chat_model(
        "claude-sonnet-4-6", model_provider="anthropic", timeout=MODEL_TIMEOUT_SECONDS
    ),
    "google": _build_google_model,
    "groq": lambda: init_chat_model(
        "openai/gpt-oss-120b", model_provider="groq", timeout=MODEL_TIMEOUT_SECONDS
    ),
}


def get_model(provider: str = "google"):
    if provider not in _PROVIDERS:
        raise ValueError(f"Unknown provider '{provider}'. Choose from: {list(_PROVIDERS)}")
    return _PROVIDERS[provider]()
