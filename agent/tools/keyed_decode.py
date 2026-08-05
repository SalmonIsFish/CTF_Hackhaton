"""Keyed byte-cipher decode, for challenges (e.g. picoCTF's "Bookmarklet" family) whose
JavaScript XORs/adds/subtracts a repeating text key against a ciphertext string one byte at a
time -- a common shape identify_and_decode's base64/hex/rot13 auto-detection doesn't cover.

fetch_and_decode_cipher exists specifically to close a real, observed failure mode: asked to
decode this by hand, a model tried to copy a ~30-char ciphertext string containing high-byte
(0x80-0xFF) characters out of a fetch_url result and retype it into its own reasoning, silently
mangled several characters doing so, gave up on the arithmetic partway through, and fabricated a
plausible-looking flag instead of admitting it couldn't finish -- confirmed live against
picoCTF's "Bookmarklet" challenge (see evals/practice_runs.md; the real flag was
picoCTF{p@g3_turn3r_cebccdfe}, nothing like what the model stated). Extracting the ciphertext via
a server-side regex against the real HTTP response, in the same call that decodes it, means the
exact ciphertext bytes never have to pass through the model's own text generation at all.
"""
import re
from typing import Optional
from urllib.parse import urlparse

import requests
from langchain_core.tools import tool

from agent.tools._response_text import decode_response_body

FETCH_TIMEOUT_SECONDS = 8.0
MAX_CIPHERTEXT_CHARS = 4096

_MODES = {"subtract", "add", "xor"}


def _apply_cipher(ciphertext: str, key: str, mode: str) -> str:
    out_chars = []
    for i, ch in enumerate(ciphertext):
        k = ord(key[i % len(key)])
        c = ord(ch)
        if mode == "subtract":
            out_chars.append(chr((c - k + 256) % 256))
        elif mode == "add":
            out_chars.append(chr((c + k) % 256))
        else:  # xor
            out_chars.append(chr((c ^ k) % 256))
    return "".join(out_chars)


@tool
def keyed_byte_decode(text: str, key: str, mode: str = "subtract") -> str:
    """Decode a string that was enciphered one byte at a time against a repeating text key --
    the shape used by picoCTF's "Bookmarklet"-style challenges, e.g. JavaScript computing
    String.fromCharCode((cipher.charCodeAt(i) - key.charCodeAt(i % key.length) + 256) % 256).
    mode: "subtract" (cipher = plain + key, so decode subtracts -- the common case, matches the
    example above), "add" (cipher = plain - key, so decode adds), or "xor" (cipher = plain XOR
    key). Applies the operation per-character using each character's raw code point (0-255 for
    the typical case), wrapping mod 256, cycling the key. Prefer fetch_and_decode_cipher over
    manually copying a ciphertext string out of another tool's result into this one -- retyping
    a string containing high-byte (non-ASCII) characters is error-prone and has caused a real
    corrupted decode before; this tool is for cases where you already have trusted, exact
    ciphertext (e.g. from a local file, not retyped from memory)."""
    mode = mode.lower()
    if mode not in _MODES:
        return f"Unsupported mode '{mode}'; use subtract, add, or xor."
    if len(text) > MAX_CIPHERTEXT_CHARS:
        return f"Ciphertext too long (max {MAX_CIPHERTEXT_CHARS} chars)."
    if not key:
        return "key must not be empty."
    return _apply_cipher(text, key, mode)


@tool
def fetch_and_decode_cipher(
    url: str, key: str, pattern: str, mode: str = "subtract", group: int = 1,
) -> str:
    """Fetch url, extract a ciphertext substring from the response via the regex `pattern`
    (using capture group `group`, default 1), and decode it with the same per-character keyed
    cipher as keyed_byte_decode -- all in one call, so the exact ciphertext bytes (often
    containing non-ASCII characters) never have to pass through your own reasoning or a
    follow-up tool call, where retyping them has caused a real corrupted decode before. Example
    pattern for a JS bookmarklet like `var encryptedFlag = "...";`:
    r'encryptedFlag\\s*=\\s*"([^"]*)"'. Never raises -- connection errors, an unmatched pattern,
    or a bad mode all come back as a descriptive string instead. The fetched content this reads
    from is live/untrusted, same as fetch_url — the decoded output is wrapped in
    <untrusted_data> tags for the same reason."""
    mode = mode.lower()
    if mode not in _MODES:
        return f"Unsupported mode '{mode}'; use subtract, add, or xor."
    if not key:
        return "key must not be empty."
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        return f"Invalid pattern: {exc}"

    try:
        response = requests.get(url, timeout=FETCH_TIMEOUT_SECONDS)
    except requests.RequestException as exc:
        return f"Request to {url} failed: {exc}"

    match = compiled.search(decode_response_body(response))
    if not match:
        return f"Pattern {pattern!r} did not match anything in the response from {url}."
    try:
        ciphertext: Optional[str] = match.group(group)
    except IndexError:
        return f"Pattern has no capture group {group}."
    if ciphertext is None:
        return f"Capture group {group} did not participate in the match."
    if len(ciphertext) > MAX_CIPHERTEXT_CHARS:
        return f"Matched ciphertext too long (max {MAX_CIPHERTEXT_CHARS} chars)."

    decoded = _apply_cipher(ciphertext, key, mode)
    host = urlparse(url).hostname or url
    payload = f"Matched ciphertext ({len(ciphertext)} chars): {ciphertext!r}\nDecoded: {decoded}"
    return f'<untrusted_data source="fetch_and_decode_cipher:{host}">\n{payload}\n</untrusted_data>'
