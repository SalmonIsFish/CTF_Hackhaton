import base64
import binascii
import codecs
import re
from typing import Optional

from langchain_core.tools import tool

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def _try_hex(text: str) -> Optional[str]:
    cleaned = text.strip()
    if not cleaned or len(cleaned) % 2 != 0 or not _HEX_RE.match(cleaned):
        return None
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _try_base64(text: str) -> Optional[str]:
    cleaned = text.strip()
    if not cleaned or len(cleaned) % 4 != 0 or not _BASE64_RE.match(cleaned):
        return None
    try:
        raw = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _try_rot13(text: str) -> Optional[str]:
    decoded = codecs.decode(text, "rot13")
    return decoded if decoded != text else None


@tool
def identify_and_decode(text: str) -> str:
    """Attempt to detect and decode text encoded as base64, hex, or rot13.
    Returns each successful decoding labeled by encoding, or a message if none matched.
    Note: rot13 has no distinguishing structure, so any alphabetic input yields a rot13
    candidate regardless of whether it was actually rot13-encoded."""
    results = {}

    hex_result = _try_hex(text)
    if hex_result is not None:
        results["hex"] = hex_result

    b64_result = _try_base64(text)
    if b64_result is not None:
        results["base64"] = b64_result

    rot13_result = _try_rot13(text)
    if rot13_result is not None:
        results["rot13"] = rot13_result

    if not results:
        return "No base64, hex, or rot13 encoding detected."

    return "\n".join(f"{name}: {decoded}" for name, decoded in results.items())
