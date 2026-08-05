"""Read a local file's raw contents -- the generic complement to extract_metadata (images/PDFs
only): covers any other file type a challenge hands you directly (ciphertext .txt/.enc blobs,
archives, raw binaries) that needs to reach the model's own reasoning or a decode tool, without
requiring the model to already know whether the file is text or binary.
"""
import base64
import os
import re
from typing import Optional

from langchain_core.tools import tool

from agent.tools._local_file_check import check_local_file

MAX_TEXT_CHARS = 8192
MAX_BASE64_SOURCE_BYTES = 65536
HEX_PREVIEW_BYTES = 64
SEARCH_MAX_MATCHES = 5


@tool
def read_local_file(file_path: str, search_pattern: Optional[str] = None) -> str:
    """Read a local file's contents -- for any downloaded challenge file that isn't an image or
    PDF (extract_metadata handles those). file_path is a local path the agent already has access
    to (e.g. a challenge file you downloaded to disk and mentioned in your prompt, such as
    "C:\\Users\\you\\Downloads\\secret.enc"), not a URL -- fetch_url first if the file needs
    downloading from a live target instead.

    If the file decodes as UTF-8 text, returns the text directly (capped at 8192 chars). If
    truncated, pass search_pattern (a regex) to search the FULL file and get back only the
    matching snippet(s), instead of guessing or completing what's past the cutoff from memory.

    If the file is binary (not valid UTF-8 -- true for most encrypted/.enc blobs and other
    non-text formats), returns the file size, a short hex preview, and the content base64-encoded
    (capped at 64 KB of raw bytes) -- pass that base64 string to identify_and_decode or another
    decode tool rather than retyping bytes by hand, the same reasoning fetch_and_decode_cipher
    extracts ciphertext for instead of making you copy it.

    Never raises -- a missing file or read error comes back as a descriptive string instead.
    If given a directory instead of a file, lists the directory's contents rather than just
    saying "no such file" -- the directory is real, it just needs narrowing to a specific file."""
    check_error = check_local_file(file_path)
    if check_error:
        return check_error

    try:
        size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            raw = f.read()
    except OSError as exc:
        return f"Could not read {file_path}: {exc}"

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = None

    if text is not None:
        if search_pattern:
            try:
                compiled = re.compile(search_pattern)
            except re.error as exc:
                return f"Invalid search_pattern: {exc}"
            matches = compiled.findall(text)[:SEARCH_MAX_MATCHES]
            if not matches:
                return f"No match for pattern {search_pattern!r} in {size} bytes."
            return "\n".join(m if isinstance(m, str) else str(m) for m in matches)
        truncated = text[:MAX_TEXT_CHARS]
        suffix = ""
        if len(text) > MAX_TEXT_CHARS:
            suffix = (
                f"\n...[truncated, {len(text) - MAX_TEXT_CHARS} more chars -- pass "
                "search_pattern to search the full file instead of guessing what's past this cutoff]"
            )
        return f"file: {file_path}\nsize: {size} bytes\ntype: text\n\n{truncated}{suffix}"

    preview_hex = raw[:HEX_PREVIEW_BYTES].hex()
    b64_source = raw[:MAX_BASE64_SOURCE_BYTES]
    b64 = base64.b64encode(b64_source).decode("ascii")
    suffix = ""
    if len(raw) > MAX_BASE64_SOURCE_BYTES:
        suffix = f"\n...[truncated, {len(raw) - MAX_BASE64_SOURCE_BYTES} more raw bytes not included below]"
    return (
        f"file: {file_path}\nsize: {size} bytes\ntype: binary\n"
        f"first {HEX_PREVIEW_BYTES} bytes (hex): {preview_hex}\n\n"
        f"base64 (first {len(b64_source)} bytes):\n{b64}{suffix}"
    )
