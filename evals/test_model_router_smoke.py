"""Standalone tests for agent/model_router.py's multi-key rotation logic.

Uses stub model objects instead of real API calls — no live network dependency, matching the
offline/deterministic style of evals/test_tools_smoke.py. The point here is the rotation
logic itself (does a 429 actually advance to the next key, does it stay sticky, does a
non-quota error propagate instead of rotating), not whether any real provider is reachable.
"""
from google.genai.errors import APIError

from agent.model_router import (
    TRANSIENT_RETRY_ATTEMPTS,
    _is_dead_key_error,
    _is_quota_error,
    _is_transient_error,
    _load_keys,
    _RotatingChatModel,
)


class _WrappedQuotaError(Exception):
    """Stands in for langchain-google-genai's real ChatGoogleGenerativeAIError, which wraps
    the underlying google.genai.errors.APIError via `raise ... from e` rather than letting it
    propagate directly -- confirmed against a real 429 during live testing. A rotation check
    that does `except APIError` (the original, buggy implementation) never sees this shape."""


class _WrappedDeadKeyError(Exception):
    """Same wrapping shape as _WrappedQuotaError, for the 401 dead-key case -- confirmed
    against a real run where a Google 'AQ.'-prefixed auth key's bound service account had been
    deleted, producing 401 UNAUTHENTICATED / ACCESS_TOKEN_TYPE_UNSUPPORTED on every call."""


class _StubModel:
    def __init__(
        self, fail_with_quota_error: bool = False, fail_with_other_error: bool = False,
        fail_wrapped: bool = False, fail_transient_times: int = 0,
        fail_with_dead_key_error: bool = False, fail_dead_key_wrapped: bool = False,
    ):
        self.fail_with_quota_error = fail_with_quota_error
        self.fail_with_other_error = fail_with_other_error
        self.fail_wrapped = fail_wrapped
        self.fail_transient_times = fail_transient_times
        self.fail_with_dead_key_error = fail_with_dead_key_error
        self.fail_dead_key_wrapped = fail_dead_key_wrapped
        self.calls = 0

    def invoke(self, messages):
        self.calls += 1
        if self.fail_with_quota_error:
            raise APIError(
                code=429,
                response_json={"error": {"status": "RESOURCE_EXHAUSTED", "message": "quota exceeded"}},
            )
        if self.fail_wrapped:
            try:
                raise APIError(
                    code=429,
                    response_json={"error": {"status": "RESOURCE_EXHAUSTED", "message": "quota exceeded"}},
                )
            except APIError as inner:
                raise _WrappedQuotaError("Error calling model") from inner
        if self.fail_with_dead_key_error:
            raise APIError(
                code=401,
                response_json={"error": {"status": "UNAUTHENTICATED", "message": "bound service account is deleted"}},
            )
        if self.fail_dead_key_wrapped:
            try:
                raise APIError(
                    code=401,
                    response_json={"error": {"status": "UNAUTHENTICATED", "message": "bound service account is deleted"}},
                )
            except APIError as inner:
                raise _WrappedDeadKeyError("Error calling model") from inner
        if self.fail_with_other_error:
            raise APIError(code=400, response_json={"error": {"status": "INVALID_ARGUMENT", "message": "bad request"}})
        if self.calls <= self.fail_transient_times:
            raise APIError(
                code=503,
                response_json={"error": {"status": "UNAVAILABLE", "message": "high demand, try again later"}},
            )
        return f"ok from stub (calls={self.calls})"

    def bind_tools(self, tools):
        return self


print("=== _load_keys: plural env var takes priority and splits on commas ===")
import os

os.environ["TEST_KEY_VARS"] = "key-a, key-b ,key-c"
os.environ["TEST_KEY_VAR"] = "solo-key"
assert _load_keys("TEST_KEY_VAR") == ["key-a", "key-b", "key-c"], _load_keys("TEST_KEY_VAR")

print("=== _load_keys: falls back to the singular var when the plural is unset ===")
del os.environ["TEST_KEY_VARS"]
assert _load_keys("TEST_KEY_VAR") == ["solo-key"], _load_keys("TEST_KEY_VAR")

print("=== _load_keys: empty list when neither is set ===")
del os.environ["TEST_KEY_VAR"]
assert _load_keys("TEST_KEY_VAR_NOT_SET") == [], _load_keys("TEST_KEY_VAR_NOT_SET")

print("\n=== _RotatingChatModel: a 429 on the current key rotates to the next and succeeds ===")
bad_key = _StubModel(fail_with_quota_error=True)
good_key = _StubModel()
rotating = _RotatingChatModel([bad_key, good_key])
result = rotating.invoke("hi")
print(result)
assert result == "ok from stub (calls=1)", result
assert bad_key.calls == 1 and good_key.calls == 1, "expected exactly one attempt on each key"
assert rotating._cooldown_until[0] > 0, "expected the failed key to be marked in cooldown"
assert rotating._cooldown_until[1] == 0, "expected the working key to have no cooldown"

print("\n=== _RotatingChatModel: mid-cooldown — the next call goes straight to the working key ===")
result_2 = rotating.invoke("hi again")
print(result_2)
assert result_2 == "ok from stub (calls=2)", result_2
assert bad_key.calls == 1, "expected the already-exhausted key to NOT be retried while in cooldown"

print("\n=== _RotatingChatModel: once cooldown elapses, list order is preferred again (self-heals) ===")
import time as _time
rotating._cooldown_until[0] = _time.time() - 1  # simulate the ~90s cooldown having passed
bad_key.fail_with_quota_error = False  # simulate its RPM window having cleared
result_3 = rotating.invoke("hi a third time")
assert result_3 == "ok from stub (calls=2)", result_3
assert bad_key.calls == 2, "expected the recovered key to be preferred over the still-good one, per list order"

print("\n=== _RotatingChatModel: every key exhausted re-raises the last quota error ===")
all_bad = _RotatingChatModel([_StubModel(fail_with_quota_error=True), _StubModel(fail_with_quota_error=True)])
try:
    all_bad.invoke("hi")
    raise AssertionError("expected an APIError when every key is quota-exhausted")
except APIError as exc:
    print("got expected APIError:", exc.code, exc.status)
    assert exc.code == 429

print("\n=== _RotatingChatModel: a non-quota error propagates immediately, no rotation ===")
other_error_model = _StubModel(fail_with_other_error=True)
never_reached = _StubModel()
no_rotate = _RotatingChatModel([other_error_model, never_reached])
try:
    no_rotate.invoke("hi")
    raise AssertionError("expected the non-quota APIError to propagate")
except APIError as exc:
    assert exc.code == 400, f"expected the original 400 to propagate unchanged, got {exc.code}"
    assert never_reached.calls == 0, "expected rotation to NOT trigger on a non-quota error"

print(
    "\n=== _RotatingChatModel: rotates PAST a dead (401) key to a working fallback -- the real"
    "\n    scenario this exists for: a Google 'AQ.' auth key whose bound service account was"
    "\n    deleted, with a paid OpenRouter overflow model appended after it ==="
)
dead_key_model = _StubModel(fail_with_dead_key_error=True)
overflow_model = _StubModel()
dead_key_rotator = _RotatingChatModel([dead_key_model, overflow_model])
dead_key_result = dead_key_rotator.invoke("hi")
assert dead_key_result == "ok from stub (calls=1)", (
    f"expected rotation to reach the working overflow model, got {dead_key_result!r}"
)
assert dead_key_model.calls == 1 and overflow_model.calls == 1, (
    "expected exactly one attempt against the dead key before rotating"
)

print(
    "\n=== _RotatingChatModel: a dead key stays skipped on the NEXT call too (does not retry"
    "\n    every COOLDOWN_SECONDS the way a quota error does -- a broken credential doesn't"
    "\n    self-heal, so retrying it wastes a call every time) ==="
)
dead_key_result_2 = dead_key_rotator.invoke("hi again")
assert dead_key_result_2 == "ok from stub (calls=2)", dead_key_result_2
assert dead_key_model.calls == 1, (
    f"expected the dead key to still be skipped on a second call, got {dead_key_model.calls} attempts"
)

print("\n=== _RotatingChatModel: rotates on a REAL-SHAPED wrapped 401 (langchain's wrapping) ===")
wrapped_dead_key_model = _StubModel(fail_dead_key_wrapped=True)
wrapped_overflow_model = _StubModel()
wrapped_dead_key_rotator = _RotatingChatModel([wrapped_dead_key_model, wrapped_overflow_model])
wrapped_dead_key_result = wrapped_dead_key_rotator.invoke("hi")
assert wrapped_dead_key_result == "ok from stub (calls=1)", wrapped_dead_key_result

print("\n=== _RotatingChatModel: every key dead re-raises the last 401 (nothing left to fall back to) ===")
all_dead = _RotatingChatModel([_StubModel(fail_with_dead_key_error=True), _StubModel(fail_with_dead_key_error=True)])
try:
    all_dead.invoke("hi")
    raise AssertionError("expected an APIError when every key is dead")
except APIError as exc:
    assert exc.code == 401, f"expected the 401 to propagate once nothing is left, got {exc.code}"

print("\n=== _is_dead_key_error: detects a 401 directly, via __cause__, and rejects unrelated errors ===")
assert _is_dead_key_error(
    APIError(code=401, response_json={"error": {"status": "UNAUTHENTICATED", "message": "x"}})
), "expected a direct 401 to be detected"
wrapped_401 = _WrappedDeadKeyError("outer")
try:
    raise APIError(code=401, response_json={"error": {"status": "UNAUTHENTICATED", "message": "x"}})
except APIError as inner:
    wrapped_401.__cause__ = inner
assert _is_dead_key_error(wrapped_401), "expected a wrapped 401 to be detected via __cause__"
assert not _is_dead_key_error(ValueError("unrelated")), "expected a plain unrelated error to not match"
assert not _is_dead_key_error(
    APIError(code=429, response_json={"error": {"status": "RESOURCE_EXHAUSTED", "message": "x"}})
), "expected a quota error to NOT also match as a dead-key error"

print("\n=== _is_quota_error: detects a 429 wrapped in another exception's __cause__ chain ===")
try:
    _WrappedQuotaError("outer").__class__
    raise APIError(code=429, response_json={"error": {"status": "RESOURCE_EXHAUSTED", "message": "x"}})
except APIError as inner:
    wrapped = _WrappedQuotaError("outer")
    wrapped.__cause__ = inner
    assert _is_quota_error(wrapped), "expected a wrapped 429 to be detected via __cause__"
assert not _is_quota_error(ValueError("unrelated")), "expected a plain unrelated error to not match"

print("\n=== _RotatingChatModel: rotates on a REAL-SHAPED wrapped 429 (regression for the bug where")
print("    `except APIError` never matched langchain's wrapped exception in production) ===")
bad_wrapped = _StubModel(fail_wrapped=True)
good_after_wrap = _StubModel()
rotating_wrapped = _RotatingChatModel([bad_wrapped, good_after_wrap])
result_wrapped = rotating_wrapped.invoke("hi")
assert result_wrapped == "ok from stub (calls=1)", result_wrapped
assert rotating_wrapped._cooldown_until[0] > 0

print("\n=== _RotatingChatModel: bind_tools() rebinds every underlying model, still rotates ===")
bad_bind = _StubModel(fail_with_quota_error=True)
good_bind = _StubModel()
bound = _RotatingChatModel([bad_bind, good_bind]).bind_tools(["dummy_tool"])
bound_result = bound.invoke("hi")
assert bound_result == "ok from stub (calls=1)", bound_result
assert bound._cooldown_until[0] > 0

print(
    "\n=== _is_transient_error: detects a 503/UNAVAILABLE APIError directly and via __cause__, "
    "distinct from a quota error -- regression test for a real, confirmed failure: a live "
    "'503 UNAVAILABLE ... high demand ... try again later' error hit the bare `raise` path "
    "(not a quota error, so no rotation) and killed the whole run outright instead of retrying "
    "a transient, self-resolving condition ==="
)
transient_503 = APIError(code=503, response_json={"error": {"status": "UNAVAILABLE", "message": "high demand"}})
assert _is_transient_error(transient_503), "expected a direct 503/UNAVAILABLE to be detected"
assert not _is_quota_error(transient_503), "a 503 must NOT be misclassified as a quota error"

wrapped_transient = _WrappedQuotaError("outer")
wrapped_transient.__cause__ = transient_503
assert _is_transient_error(wrapped_transient), "expected a wrapped 503 to be detected via __cause__"

assert not _is_transient_error(ValueError("unrelated")), "expected a plain unrelated error to not match"
quota_503_check = APIError(code=429, response_json={"error": {"status": "RESOURCE_EXHAUSTED", "message": "x"}})
assert not _is_transient_error(quota_503_check), "a quota error must NOT be misclassified as transient"

print(
    "\n=== _RotatingChatModel: a transient 503 is retried on the SAME key (not rotated away "
    "from), and succeeds once the underlying condition clears ==="
)
import agent.model_router as _model_router_module  # local import, avoids polluting module namespace above

_sleep_calls = []
_original_sleep = _model_router_module.time.sleep
_model_router_module.time.sleep = lambda seconds: _sleep_calls.append(seconds)  # no real delay in tests
try:
    flaky_then_fine = _StubModel(fail_transient_times=TRANSIENT_RETRY_ATTEMPTS - 1)
    never_needed = _StubModel()
    retry_rotating = _RotatingChatModel([flaky_then_fine, never_needed])
    retry_result = retry_rotating.invoke("hi")
    print(retry_result)
    assert retry_result == f"ok from stub (calls={TRANSIENT_RETRY_ATTEMPTS})", retry_result
    assert flaky_then_fine.calls == TRANSIENT_RETRY_ATTEMPTS, (
        f"expected exactly {TRANSIENT_RETRY_ATTEMPTS} attempts on the same key, got {flaky_then_fine.calls}"
    )
    assert never_needed.calls == 0, "expected the second key to never be touched -- this isn't a quota rotation"
    assert retry_rotating._cooldown_until[0] == 0, (
        "expected NO cooldown from a transient error -- rotation/cooldown is a quota-only mechanism"
    )
    assert len(_sleep_calls) == TRANSIENT_RETRY_ATTEMPTS - 1, (
        f"expected a backoff sleep between each retry, got {_sleep_calls}"
    )

    print(
        "\n=== _RotatingChatModel: transient errors beyond TRANSIENT_RETRY_ATTEMPTS propagate "
        "as a normal (non-quota) error, no rotation ==="
    )
    always_transient = _StubModel(fail_transient_times=TRANSIENT_RETRY_ATTEMPTS + 5)
    unreached = _StubModel()
    exhausted_retry = _RotatingChatModel([always_transient, unreached])
    try:
        exhausted_retry.invoke("hi")
        raise AssertionError("expected the persistent 503 to propagate once retries are exhausted")
    except APIError as exc:
        assert exc.code == 503, f"expected the original 503 to propagate, got {exc.code}"
        assert always_transient.calls == TRANSIENT_RETRY_ATTEMPTS, (
            f"expected exactly {TRANSIENT_RETRY_ATTEMPTS} attempts before giving up, got {always_transient.calls}"
        )
        assert unreached.calls == 0, "expected no rotation to the next key for a transient (non-quota) error"
finally:
    _model_router_module.time.sleep = _original_sleep
