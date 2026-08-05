"""Crack a hash by hashing candidate passwords and comparing -- a real, common CTF pattern (a
service or file hands you a hash and explicitly hints "have you tried a hash cracking tool?").

An LLM recalling a specific hash->password mapping from training data is unreliable -- the same
class of risk as computing RSA/modular exponentiation by reasoning instead of running it: it
might get lucky on a famous example, but there's no way to trust it without actually checking,
and CTF challenges routinely use passwords that only look familiar. This does the real
computation: hash every candidate and compare, exactly what "a hash cracking tool" means.
"""
import hashlib
import os
from typing import Optional

from langchain_core.tools import tool

from agent.tools._local_file_check import check_local_file

_HASH_LENGTH_TO_ALGO = {
    32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512",
}

MAX_CANDIDATES = 200000  # safety cap if a huge external wordlist is supplied

# A moderate base list of very common passwords/words, expanded at import time with common
# transformation rules (case variants, trailing digits/years/punctuation) -- the same shape most
# beginner CTF hash-cracking challenges use (a deliberately weak, guessable password), without
# needing to hardcode thousands of literal strings or depend on an external wordlist file.
_BASE_WORDS = [
    "password", "123456", "12345678", "123456789", "1234567890", "qwerty", "letmein", "welcome",
    "monkey", "dragon", "master", "football", "baseball", "superman", "batman", "starwars",
    "freedom", "whatever", "shadow", "sunshine", "princess", "flower", "trustno1", "hunter",
    "admin", "root", "toor", "guest", "user", "default", "test", "secret", "changeme", "hacker",
    "cyber", "picoctf", "flag", "ctf", "iloveyou", "abc123", "qazwsx", "1qaz2wsx", "zaq1zaq1",
    "asdfgh", "asdf1234", "qwerty123", "qwe123", "access", "login", "pass", "computer",
    "internet", "security", "system", "network", "server", "database", "matrix", "phoenix",
    "tiger", "lion", "eagle", "wolf", "bear", "shark", "panda", "cookie", "chocolate", "coffee",
    "pizza", "apple", "banana", "soccer", "hockey", "tennis", "golf", "ninja", "samurai",
    "pirate", "wizard", "knight", "fireball", "thunder", "lightning", "storm", "rainbow",
    "sunset", "sunrise", "galaxy", "universe", "rocket", "robot", "ironman", "spiderman",
    "captain", "legend", "champion", "victory", "winner", "gamer", "trophy", "gold", "silver",
    "diamond", "abcdef", "abcabc", "aaaaaa", "zzzzzz", "654321", "987654321", "121212", "696969",
    "777777", "888888", "000000", "111111", "qwerty098", "qwerty1", "qwerty12", "qwerty12345",
    "trustno1", "letmein1", "sunshine1", "michael", "jennifer", "jordan", "hunter2", "biteme",
    "asdfasdf", "zxcvbnm", "1234qwer", "qazxsw", "michelle", "charlie", "andrew", "daniel",
    "matthew", "joshua", "george", "thomas", "richard", "buster", "jessica", "pepper", "1qazxsw2",
]

# The base words above cover most common "deliberately weak" CTF passwords with a handful of
# fixed suffix variants (1, 123, a year, etc.) -- but a real password like "qwerty098" uses an
# arbitrary 3-digit suffix, not a predictable one, and confirmed live that the small fixed-suffix
# set missed it (a real picoCTF "hashcrack" run correctly reported "not found," then had to fall
# back to web_search to locate the password from a public writeup). Rather than only widening the
# base-word list one confirmed miss at a time, a small set of the most keyboard-pattern-prone base
# words also get every 3-digit numeric suffix (000-999) generated, since that's specifically where
# an "arbitrary-looking" suffix like this is most likely to appear in practice.
_FULL_DIGIT_SUFFIX_BASES = ("qwerty", "password", "admin", "letmein", "welcome", "asdf")


def _generate_candidates() -> list:
    seen = set()
    out = []

    def add(word: str) -> None:
        if word and word not in seen:
            seen.add(word)
            out.append(word)

    for base in _BASE_WORDS:
        for variant in (
            base, base.lower(), base.upper(), base.capitalize(),
            base + "1", base + "123", base + "!", base + "2023", base + "2024",
        ):
            add(variant)
    for base in _FULL_DIGIT_SUFFIX_BASES:
        for n in range(1000):
            add(f"{base}{n:03d}")
    return out


_COMMON_PASSWORDS = _generate_candidates()


@tool
def crack_hash(target_hash: str, algorithm: str = "auto", wordlist_path: Optional[str] = None) -> str:
    """Attempt to recover the plaintext behind a password hash by hashing candidate passwords
    and comparing against target_hash (a hex digest). algorithm is "auto" (detect from
    target_hash's length: 32=md5, 40=sha1, 56=sha224, 64=sha256, 96=sha384, 128=sha512) or an
    explicit hashlib algorithm name. wordlist_path (optional) is a local file with one candidate
    password per line -- omit it to use a built-in list of common passwords/words (plus case and
    suffix variants), which covers most "deliberately weak password" CTF challenges without
    needing an external file.

    Never guess a password from memory/training data instead of calling this -- an LLM recalling
    a specific hash may be right by luck on a famous example, but there's no reliable way to
    trust that without actually checking, and this tool does the real check in the same call.
    Never raises -- an unrecognized hash length/algorithm or a missing wordlist file comes back
    as a descriptive string. Returns the cracked plaintext if found, or a clean 'not found in N
    candidates' message otherwise (try wordlist_path with a bigger list if the built-in one
    misses)."""
    cleaned_hash = target_hash.strip().lower()
    if algorithm == "auto":
        algo = _HASH_LENGTH_TO_ALGO.get(len(cleaned_hash))
        if algo is None:
            return (
                f"Could not auto-detect a hash algorithm from a {len(cleaned_hash)}-character hex "
                "string; pass algorithm explicitly (a hashlib name, e.g. 'md5', 'sha1', 'sha256')."
            )
    else:
        algo = algorithm.strip().lower()
    try:
        hashlib.new(algo)
    except ValueError:
        return f"Unknown hash algorithm {algo!r}."

    if wordlist_path:
        check_error = check_local_file(wordlist_path)
        if check_error:
            return check_error
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                candidates = [line.strip() for line in f if line.strip()]
        except OSError as exc:
            return f"Could not read {wordlist_path}: {exc}"
    else:
        candidates = _COMMON_PASSWORDS

    candidates = candidates[:MAX_CANDIDATES]
    for candidate in candidates:
        digest = hashlib.new(algo, candidate.encode("utf-8", errors="ignore")).hexdigest()
        if digest == cleaned_hash:
            return f"Cracked ({algo}): {candidate}"
    return f"Not found in {len(candidates)} candidates (algorithm: {algo})."
