"""Arbitrary-precision modular exponentiation -- closes a real capability gap for
Diffie-Hellman/discrete-log-shaped CTF crypto challenges. Computing shared = pow(base, exponent,
modulus) for real challenge-sized numbers (hundreds of digits) requires genuine big-integer
arithmetic, not something an LLM can compute correctly by reasoning through it token by token.

Confirmed live: given a real "recover the leaked exponent, compute the DH shared secret,
XOR-decrypt the flag" challenge, a model correctly identified every step of the right algorithm
-- it even wrote out real, correct-looking Python in its final answer narrating the computation
-- but never actually executed it, and the flag it stated as if that code had run was completely
wrong (a different, fabricated suffix). Recognizing the right technique was never the gap;
performing the actual arithmetic was -- the same lesson agent/tools/rsa_tools.py already learned
for RSA decryption, here for the raw modular-exponentiation step underneath a DH exchange.
"""
from typing import Optional

from langchain_core.tools import tool


def _parse_int(value: str, name: str) -> Optional[int]:
    try:
        return int(value.strip())
    except (ValueError, AttributeError):
        return None


@tool
def modpow(base: str, exponent: str, modulus: str) -> str:
    """Compute (base ** exponent) % modulus for arbitrarily large integers. All three arguments
    are decimal integer strings, as they typically appear in a challenge's own captured data file
    (e.g. a line reading "A = 98544537...", "b = 25317480...", "p = 25491895..."). Never compute
    this kind of modular exponentiation by hand in your own reasoning -- it requires genuine
    big-integer arithmetic on numbers with hundreds of digits, not something that can be done
    correctly by reasoning through it token by token, only by actually running the computation
    (which is exactly what this tool does). Never raises -- a non-numeric argument or a zero
    modulus comes back as a descriptive string instead."""
    base_int = _parse_int(base, "base")
    exponent_int = _parse_int(exponent, "exponent")
    modulus_int = _parse_int(modulus, "modulus")
    if base_int is None or exponent_int is None or modulus_int is None:
        return "base, exponent, and modulus must all be decimal integers."
    if modulus_int == 0:
        return "modulus must not be zero."
    return str(pow(base_int, exponent_int, modulus_int))


@tool
def dh_shared_secret_decrypt(public_key: str, exponent: str, modulus: str, ciphertext_hex: str) -> str:
    """Decrypt a Diffie-Hellman-style "shared secret" challenge in one call: computes
    shared = pow(public_key, exponent, modulus), derives a single-byte key = shared % 256, and
    XORs every byte of ciphertext_hex (a hex-encoded ciphertext) with that key -- the common
    picoCTF "shared secret" challenge shape (a public value A = g**a mod p, a leaked/known
    private exponent b, shared = A**b mod p, flag = ciphertext XOR (shared % 256) per byte).
    public_key/exponent/modulus are decimal integer strings, as they typically appear in a
    challenge's own captured data file. Never compute this by hand in your own reasoning --
    modular exponentiation on numbers with hundreds of digits requires genuine big-integer
    arithmetic, not something that can be done correctly by reasoning through it token by token.
    Returns the decrypted plaintext (UTF-8 decoded if possible, otherwise hex) along with the
    computed shared secret and derived key byte, for verification. Never raises -- invalid
    input comes back as a descriptive string instead."""
    public_key_int = _parse_int(public_key, "public_key")
    exponent_int = _parse_int(exponent, "exponent")
    modulus_int = _parse_int(modulus, "modulus")
    if public_key_int is None or exponent_int is None or modulus_int is None:
        return "public_key, exponent, and modulus must all be decimal integers."
    if modulus_int == 0:
        return "modulus must not be zero."
    try:
        ciphertext = bytes.fromhex(ciphertext_hex.strip())
    except ValueError as exc:
        return f"ciphertext_hex is not valid hex: {exc}"

    shared = pow(public_key_int, exponent_int, modulus_int)
    key_byte = shared % 256
    plaintext = bytes(b ^ key_byte for b in ciphertext)

    try:
        decoded = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        decoded = f"(binary, hex) {plaintext.hex()}"

    return f"shared secret = {shared}\nkey byte (shared % 256) = {key_byte}\n\nDecrypted: {decoded}"
