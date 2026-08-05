"""Shared HTTP header-key sanitization, used by every tool that accepts a headers dict from the
model (fetch_url, upload_file) instead of each reimplementing the same fixes.

Not a @tool itself -- see agent/tools/_response_text.py for the same "leading underscore =
internal helper" convention.
"""
import re

# Matches a value that is itself a whole "Header-Name: value" line -- see repair_headers below.
_HEADER_LINE_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):\s*(.+)$")

# Canonical spelling for headers the model is likely to need, keyed by a "squashed" form
# (lowercase, non-alphanumeric characters stripped) so any separator style the model invents --
# underscores (X_Forwarded_For), no separator/camelCase (contentType), extra spaces, etc. -- maps
# back to the one spelling the server actually recognizes. Confirmed live: a model sent
# {"contentType": "application/x-www-form-urlencoded"} instead of {"Content-Type": ...} on every
# single POST across a whole picoCTF run (login attempts and the actual intended exploit alike),
# silently breaking PHP's $_POST parsing every time -- no error, the request just quietly never
# carried a body PHP would parse, so every step looked superficially fine while being completely
# non-functional. A docstring warning alone was already tried once, after a *different* mangled
# form (underscore-for-hyphen) -- it stopped that specific form but not this new one, so this is
# now a real code-level fix instead of relying on prompting to cover every future variant.
_CANONICAL_HEADERS = [
    "Content-Type", "Content-Length", "Cookie", "Authorization", "User-Agent", "Accept",
    "Accept-Encoding", "Accept-Language", "Referer", "Origin", "Host", "X-Forwarded-For",
    "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP", "X-Requested-With", "Cache-Control",
    "If-Modified-Since", "If-None-Match", "Connection", "Upgrade", "X-Api-Key", "X-Csrf-Token",
]
_SQUASHED_TO_CANONICAL = {
    re.sub(r"[^a-z0-9]", "", name.lower()): name for name in _CANONICAL_HEADERS
}


def _clean_header_key(key: str) -> str:
    """Strip whitespace and stray surrounding quote characters a model sometimes bakes into a
    header key (e.g. "'Content-Type'" instead of "Content-Type"), then canonicalize against a
    list of common header names regardless of separator style (contentType, content_type,
    Content Type all normalize to Content-Type). A key that doesn't match any known header is
    left as-is -- only well-known standard header names can be safely guessed at; a genuinely
    custom header's exact spelling can't be inferred."""
    cleaned = key.strip()
    while len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in "'\"":
        cleaned = cleaned[1:-1].strip()
    squashed = re.sub(r"[^a-z0-9]", "", cleaned.lower())
    return _SQUASHED_TO_CANONICAL.get(squashed, cleaned)


def repair_headers(headers: dict) -> dict:
    """A third, distinct header-mangling failure mode observed live (beyond the ones
    _clean_header_key already handles): the whole "Header-Name: value" line ends up as a
    header's VALUE under a throwaway key (observed: {"undefined": "Content-Type:
    application/json"}), instead of being split into a real key/value pair. When it happens, the
    model then typically gives up and retries with an empty headers dict instead of a corrected
    one -- silently breaking the request rather than surfacing an error to react to. If a value
    looks like "Name: value", re-split it and use the real name as the key; a legitimate header
    value essentially never itself starts with "Token: rest", so this is safe to apply
    unconditionally rather than only for a specific known-bad key."""
    repaired: dict = {}
    for key, value in headers.items():
        match = _HEADER_LINE_RE.match(value.strip()) if isinstance(value, str) else None
        if match:
            repaired[_clean_header_key(match.group(1))] = match.group(2)
        else:
            repaired[_clean_header_key(key)] = value
    return repaired
