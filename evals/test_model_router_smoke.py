"""Standalone tests for agent/model_router.py's multi-key rotation logic.

Uses stub model objects instead of real API calls — no live network dependency, matching the
offline/deterministic style of evals/test_tools_smoke.py. The point here is the rotation
logic itself (does a 429 actually advance to the next key, does it stay sticky, does a
non-quota error propagate instead of rotating), not whether any real provider is reachable.
"""
from google.genai.errors import APIError

from agent.model_router import _is_quota_error, _load_keys, _RotatingChatModel


class _WrappedQuotaError(Exception):
    """Stands in for langchain-google-genai's real ChatGoogleGenerativeAIError, which wraps
    the underlying google.genai.errors.APIError via `raise ... from e` rather than letting it
    propagate directly -- confirmed against a real 429 during live testing. A rotation check
    that does `except APIError` (the original, buggy implementation) never sees this shape."""


class _StubModel:
    def __init__(self, fail_with_quota_error: bool = False, fail_with_other_error: bool = False, fail_wrapped: bool = False):
        self.fail_with_quota_error = fail_with_quota_error
        self.fail_with_other_error = fail_with_other_error
        self.fail_wrapped = fail_wrapped
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
        if self.fail_with_other_error:
            raise APIError(code=400, response_json={"error": {"status": "INVALID_ARGUMENT", "message": "bad request"}})
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
