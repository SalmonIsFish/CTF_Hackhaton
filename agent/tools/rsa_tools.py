"""Recover an encoded key hidden in a file and use it to decrypt an RSA-encrypted ciphertext
file -- both steps operate on local file paths end to end, so a long key/ciphertext never has to
be retyped by hand between tool calls (the same reasoning fetch_and_decode_cipher and
fetch_and_join_fragments already apply to live-target content).

Exists to close a real, confirmed capability gap, not just a missing convenience: given a local
"a private key was leaked, recover it and decrypt the message" RSA challenge (a hex-encoded PEM
key hidden in a JPEG's Comment metadata field, then used to decrypt an RSA-encrypted file), a
model with no way to actually perform the decryption has exactly two options -- admit it can't
finish, or fabricate a plausible-looking answer. Confirmed live: with no RSA-decrypt tool
available, a model never called ANY tool at all (not even extract_metadata, which already
existed) and instead narrated a correct-sounding recipe as prose, then stated a flag with a
made-up suffix -- RSA decryption genuinely cannot be computed by an LLM reasoning through it
token by token (real modular exponentiation on hundreds-of-bit numbers), so recognizing the
correct *technique* was never the gap; having a way to actually *execute* it was.
"""
import os
from typing import Optional

from langchain_core.tools import tool

from agent.tools._local_file_check import check_local_file

MAX_SOURCE_BYTES = 65536


def _decode_bytes(raw: bytes, encoding: str) -> bytes:
    cleaned = raw.decode("ascii", errors="ignore").strip()
    if encoding == "hex":
        import re

        cleaned = re.sub(r"\s+", "", cleaned)
        return bytes.fromhex(cleaned)
    if encoding == "base64":
        import base64

        return base64.b64decode(cleaned, validate=False)
    raise ValueError(f"Unsupported encoding {encoding!r}")


@tool
def extract_hidden_key(
    source_path: str, output_key_path: str, encoding: str = "hex", field: Optional[str] = None,
) -> str:
    """Recover a key (or any other encoded blob) hidden inside a local file, decode it, and
    write the decoded bytes to output_key_path -- e.g. a hex-encoded PEM private key hidden in an
    image's metadata, decoded and saved as a usable key file in one call. Never returns the
    decoded content directly (only a short preview) -- pass output_key_path to rsa_decrypt_file
    (or another tool) instead of retyping a long key by hand, which is unreliable.

    field (optional): the specific metadata field to pull the encoded blob from (e.g. "comment",
    matching a key from extract_metadata's own report) -- use this when source_path is an image
    or PDF and the encoded blob is inside its metadata, not the file's main content. Omit field
    when source_path IS the encoded blob itself (e.g. a plain .txt file containing nothing but
    the hex/base64 string).

    encoding is "hex" or "base64" -- whichever the challenge actually uses; try the other if the
    first produces garbage. Never raises -- a missing file, unknown field, or invalid encoding
    comes back as a descriptive string instead. If given a directory instead of a file, lists
    the directory's contents rather than just saying "no such file"."""
    check_error = check_local_file(source_path)
    if check_error:
        return check_error
    if encoding not in ("hex", "base64"):
        return f"Unsupported encoding {encoding!r}; use hex or base64."

    if field:
        try:
            from PIL import Image

            with Image.open(source_path) as image:
                info = dict(image.info)
                exif = {}
                try:
                    for tag_id, value in image.getexif().items():
                        from PIL import ExifTags

                        exif[str(ExifTags.TAGS.get(tag_id, tag_id))] = value
                except Exception:
                    pass
        except Exception as exc:
            return f"Could not open {source_path} as an image to read field {field!r}: {exc}"

        value = info.get(field) or exif.get(field)
        if value is None:
            available = sorted(set(info) | set(exif))
            return (
                f"Field {field!r} not found in {source_path}'s metadata. Available fields: "
                f"{', '.join(available) if available else '(none)'}"
            )
        raw = value if isinstance(value, bytes) else str(value).encode("utf-8", errors="ignore")
    else:
        try:
            with open(source_path, "rb") as f:
                raw = f.read(MAX_SOURCE_BYTES)
        except OSError as exc:
            return f"Could not read {source_path}: {exc}"

    try:
        decoded = _decode_bytes(raw, encoding)
    except (ValueError, Exception) as exc:  # noqa: BLE001 - broad: many distinct decode error types
        return f"Could not {encoding}-decode the content from {source_path}: {exc}"

    try:
        with open(output_key_path, "wb") as f:
            f.write(decoded)
    except OSError as exc:
        return f"Decoded {len(decoded)} bytes but could not write to {output_key_path}: {exc}"

    preview = decoded[:40].decode("utf-8", errors="replace")
    return f"Wrote {len(decoded)} decoded bytes to {output_key_path}. Preview: {preview!r}"


@tool
def rsa_decrypt_file(key_path: str, ciphertext_path: str, padding_mode: str = "auto") -> str:
    """Decrypt ciphertext_path (a local binary file, the RSA-encrypted message) using the local
    PEM-format private key at key_path (e.g. one written by extract_hidden_key). padding_mode:
    "auto" (default) tries every common padding scheme (pkcs1v15, oaep-sha256, oaep-sha1) and
    reports which one(s) actually decrypt successfully -- padding is a small, deterministic
    parameter space, not something worth guessing at one at a time. Pass a specific mode
    ("pkcs1v15", "oaep-sha256", "oaep-sha1") to check just one. Decrypted plaintext is returned
    UTF-8 decoded when possible, otherwise as hex. Never raises -- a missing/invalid key or
    ciphertext file, or a decryption failure under every tried padding mode, comes back as a
    descriptive string instead. If given a directory instead of a file for either path, lists
    that directory's contents rather than just saying "no such file"."""
    for path in (key_path, ciphertext_path):
        check_error = check_local_file(path)
        if check_error:
            return check_error

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    try:
        with open(key_path, "rb") as f:
            key = load_pem_private_key(f.read(), password=None)
    except Exception as exc:
        return f"Could not load {key_path} as a PEM private key: {exc}"

    try:
        with open(ciphertext_path, "rb") as f:
            ciphertext = f.read()
    except OSError as exc:
        return f"Could not read {ciphertext_path}: {exc}"

    modes = {
        "pkcs1v15": rsa_padding.PKCS1v15(),
        "oaep-sha256": rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
        "oaep-sha1": rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None
        ),
    }

    if padding_mode != "auto":
        pad = modes.get(padding_mode)
        if pad is None:
            return f"Unsupported padding_mode {padding_mode!r}; use auto, pkcs1v15, oaep-sha256, or oaep-sha1."
        try:
            plaintext = key.decrypt(ciphertext, pad)
        except Exception as exc:
            return f"Decryption failed with padding_mode={padding_mode!r}: {exc}"
        return _format_plaintext(plaintext)

    results = []
    for name, pad in modes.items():
        try:
            plaintext = key.decrypt(ciphertext, pad)
            results.append(f"{name}: SUCCESS -- {_format_plaintext(plaintext)}")
        except Exception as exc:
            results.append(f"{name}: failed ({exc})")
    return "\n".join(results)


def _format_plaintext(plaintext: bytes) -> str:
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError:
        return f"(binary, hex) {plaintext.hex()}"
