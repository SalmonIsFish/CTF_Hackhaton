"""Textbook RSA decryption from bare integers -- closes the gap that agent/tools/rsa_tools.py
does not cover.

rsa_tools.py is PEM/file-based: it wants a key file and a ciphertext file on disk. A very common
CTF shape has no files at all -- a netcat service or a captured text file just prints N, e, and
the ciphertext as decimal integers, and the whole challenge is "the modulus is factorable, go".
Before this tool the agent had modpow() (the LAST step of an RSA decrypt) but nothing for the
steps before it: no factoring, no modular inverse to get d, no integer->bytes conversion. So even
with all three integers in context its only options were to stall or to fabricate -- the exact
failure mode already recorded three times in evals/practice_runs.md (StegoRSA, Shared Secrets,
and this tool's own trigger, "Even RSA Can Be Broken").

Confirmed live: picoCTF's "Even RSA Can Be Broken" hands out an EVEN modulus (so one factor is
literally 2) over netcat, regenerated per connection. A hand-written script solved it in one
shot; the agent's own run burned its whole step budget and produced nothing, purely for want of
this computation. See evals/practice_runs.md -> "Even RSA Can Be Broken".
"""
import math
import time
from typing import List, Optional, Tuple

from langchain_core.tools import tool

# Total wall-clock budget for the factoring attempts, mirroring the "every tool is bounded" rule
# the rest of this repo's tools follow (fetch_url's 8s timeout, radare2_analyze's 20s). Factoring
# is the one genuinely unbounded step here -- a hard modulus must fail fast and say so, not hang
# the whole graph run.
FACTOR_BUDGET_SECONDS = 20.0

# Trial division bound. Cheap, and catches the "one factor is tiny" family (including the even
# modulus that triggered this tool) before any of the heavier strategies run.
TRIAL_DIVISION_LIMIT = 1_000_000

# Fermat is only worth running for CLOSE primes; a few hundred thousand iterations covers the
# "p and q generated from adjacent candidates" family. It also gets a hard slice of the total
# budget rather than the whole remainder: on FAR-apart primes Fermat can never succeed, and
# letting it grind to its iteration cap starves Pollard's rho of the time it needs to find the
# medium-sized factor that is actually there (a real, observed failure while testing this tool).
FERMAT_MAX_ITERATIONS = 200_000
FERMAT_BUDGET_FRACTION = 0.35

_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


def _parse_int(value: str) -> Optional[int]:
    """Accept decimal ('12345') or hex ('0xabc' / 'abc' when clearly hex-tagged), plus incidental
    whitespace, underscores, and the trailing 'L' some writeups still carry from Python 2."""
    if value is None:
        return None
    text = str(value).strip().replace("_", "").replace(" ", "").rstrip("Ll")
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text)
    except ValueError:
        return None


def is_probable_prime(n: int) -> bool:
    """Deterministic Miller-Rabin over the first 12 primes. That witness set is a proven
    deterministic test below 3.3 * 10^24 and an extremely strong probable-prime test above it --
    for deciding "is this cofactor prime so I can use (p-1) directly" that is more than enough,
    and it is what makes the phi computation below honest rather than assumed."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in _SMALL_PRIMES:
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _integer_nth_root(n: int, k: int) -> Tuple[int, bool]:
    """Exact integer k-th root via Newton's method, plus whether it was exact. math.isqrt-style
    precision -- float pow() silently loses accuracy on challenge-sized integers, which is exactly
    the class of bug this whole module exists to avoid."""
    if n < 0:
        return 0, False
    if n in (0, 1) or k == 1:
        return n, True
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // pow(x, k - 1)) // k
        if y >= x:
            break
        x = y
    return x, pow(x, k) == n


def _trial_division(n: int, limit: int, deadline: float) -> Optional[int]:
    """Takes the deadline like every other strategy here, so FACTOR_BUDGET_SECONDS bounds the
    whole call honestly. Without this, a slow machine could spend most of the budget grinding
    through the fixed 500k divisions before the budget was ever consulted."""
    if n % 2 == 0:
        return 2
    f = 3
    checked = 0
    while f <= limit and f * f <= n:
        if n % f == 0:
            return f
        f += 2
        checked += 1
        if checked % 8192 == 0 and time.monotonic() > deadline:
            return None
    return None


def _fermat(n: int, deadline: float) -> Optional[int]:
    """Factor n = a^2 - b^2 = (a-b)(a+b). Only converges quickly when p and q are close, which is
    precisely the "close primes" challenge family it is here for."""
    if n % 2 == 0:
        return 2
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for i in range(FERMAT_MAX_ITERATIONS):
        if i % 2048 == 0 and time.monotonic() > deadline:
            return None
        b2 = a * a - n
        if b2 >= 0:
            b = math.isqrt(b2)
            if b * b == b2:
                factor = a - b
                if 1 < factor < n:
                    return factor
        a += 1
    return None


def _pollard_rho(n: int, deadline: float) -> Optional[int]:
    """Brent's variant of Pollard's rho -- the general-purpose catch-all once the structured
    attacks above have missed. Finds small-to-medium factors; a genuinely hard semiprime will
    simply exhaust the budget and be reported as unfactored rather than silently guessed at."""
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3
    c = 1
    while c < 64:
        y, m = 2, 128
        g = q = 1
        r = 1
        x = ys = y
        while g == 1:
            if time.monotonic() > deadline:
                return None
            x = y
            for _ in range(r):
                y = (y * y + c) % n
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(x - y) % n
                g = math.gcd(q, n)
                k += m
            r *= 2
        if g == n:
            g = 1
            while g == 1:
                if time.monotonic() > deadline:
                    return None
                ys = (ys * ys + c) % n
                g = math.gcd(abs(x - ys), n)
        if 1 < g < n:
            return g
        c += 2
    return None


def _factorize(n: int, deadline: float) -> Tuple[Optional[List[int]], str]:
    """Full prime factorization of n, or (None, reason). Returns the factors WITH multiplicity, so
    phi is computed correctly for the p == q case too (a real challenge shape: phi = p*(p-1), not
    (p-1)^2 -- getting that wrong yields a d that silently decrypts to garbage rather than an
    error, which is the worst possible failure mode here)."""
    factors: List[int] = []
    pending = [n]
    strategy = "trial division"
    while pending:
        if time.monotonic() > deadline:
            return None, "factoring budget exhausted"
        m = pending.pop()
        if m == 1:
            continue
        if is_probable_prime(m):
            factors.append(m)
            continue

        root, exact = _integer_nth_root(m, 2)
        if exact:
            pending.extend([root, root])
            strategy = "perfect square (p == q)"
            continue

        f = _trial_division(m, TRIAL_DIVISION_LIMIT, deadline)
        if f is None:
            remaining = deadline - time.monotonic()
            fermat_deadline = min(deadline, time.monotonic() + remaining * FERMAT_BUDGET_FRACTION)
            f = _fermat(m, fermat_deadline)
            if f is not None:
                strategy = "Fermat (close primes)"
        if f is None:
            f = _pollard_rho(m, deadline)
            if f is not None:
                strategy = "Pollard's rho"
        if f is None:
            return None, "no strategy factored the modulus within the time budget"
        pending.extend([f, m // f])
    return factors, strategy


def _phi_from_factors(factors: List[int]) -> int:
    counts: dict = {}
    for p in factors:
        counts[p] = counts.get(p, 0) + 1
    phi = 1
    for p, k in counts.items():
        phi *= (p - 1) * pow(p, k - 1)
    return phi


def _int_to_bytes(m: int) -> bytes:
    return m.to_bytes((m.bit_length() + 7) // 8, "big") if m else b"\x00"


def _strip_pkcs1_v15(raw: bytes) -> Optional[bytes]:
    """Undo PKCS#1 v1.5 padding (0x00 0x02 <>= 8 non-zero bytes> 0x00 <message>). The leading 0x00
    is normally already gone, because converting the plaintext integer to bytes drops it -- so
    accept the block with or without it."""
    body = raw[1:] if raw[:1] == b"\x00" else raw
    if body[:1] != b"\x02":
        return None
    sep = body.find(b"\x00", 1)
    if sep < 9:
        return None
    return body[sep + 1:]


def _render_plaintext(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        printable = bytes(b for b in raw if 32 <= b < 127)
        suffix = f"\n  printable bytes only: {printable.decode('ascii')}" if printable else ""
        return f"(not valid UTF-8; hex) {raw.hex()}{suffix}"


@tool
def rsa_decrypt_ints(n: str, e: str, c: str, n2: str = "") -> str:
    """Decrypt a textbook/unpadded RSA ciphertext given ONLY the public values as decimal (or
    0x-prefixed hex) integer strings: the modulus n, the public exponent e, and the ciphertext c.
    This is the tool for the very common CTF shape where a netcat service or a captured text file
    just prints three big numbers -- lines like "N: 2671619433...", "e: 65537",
    "cyphertext: 2373402662..." -- and there is no key file anywhere (use rsa_decrypt_file
    instead when you DO have a PEM key file and a ciphertext file on disk).

    It automatically tries, in order, every cheap way a CTF modulus is made breakable, and reports
    which one worked: an EVEN modulus or any other small factor (trial division), a repeated prime
    (n = p*p), close primes (Fermat), a general small-to-medium factor (Pollard's rho), and -- if
    the ciphertext never wrapped the modulus because e is tiny -- a direct exact integer e-th root
    of c, no factoring needed at all. Pass n2 as well when the challenge hands out TWO moduli
    generated by the same buggy key generator: any shared prime factor is recovered instantly by
    gcd(n, n2), which breaks both keys.

    Never attempt this computation in your own reasoning and never write out a code block in your
    final answer "showing" the arithmetic -- that code is never executed. Factoring, the modular
    inverse d = e^-1 mod phi, and pow(c, d, n) on numbers with hundreds of digits require genuine
    big-integer arithmetic, which is exactly what this tool actually performs. A flag is only real
    if it appears in this tool's returned output verbatim.

    Note that these services usually regenerate n and c on every connection, so always use the
    values from the SAME request you are decrypting, never ones from an earlier attempt. Returns
    the recovered plaintext plus the factors and phi used, so the result can be checked. Never
    raises -- a non-numeric argument, an unfactorable modulus, or an e sharing a factor with phi
    all come back as a descriptive string instead."""
    n_int = _parse_int(n)
    e_int = _parse_int(e)
    c_int = _parse_int(c)
    if n_int is None or e_int is None or c_int is None:
        return "n, e, and c must all be integers (decimal, or hex with a 0x prefix)."
    if n_int < 2:
        return f"n must be at least 2 (got {n_int})."
    if e_int < 1:
        return f"e must be a positive integer (got {e_int})."
    if c_int < 0:
        return f"c must not be negative (got {c_int})."
    if c_int >= n_int:
        return (
            f"c ({c_int.bit_length()} bits) is not smaller than n ({n_int.bit_length()} bits), so "
            "these values do not belong to the same RSA instance. These services usually "
            "regenerate n and c per connection -- re-read both from one single request."
        )

    deadline = time.monotonic() + FACTOR_BUDGET_SECONDS
    notes: List[str] = []

    # Cheapest possible win, and it needs no factoring at all: with a tiny e and a short message,
    # m**e may never have exceeded n, so c is a perfect e-th power over the integers.
    if 1 < e_int <= 1024:
        root, exact = _integer_nth_root(c_int, e_int)
        if exact:
            raw = _int_to_bytes(root)
            unpadded = _strip_pkcs1_v15(raw)
            body = f"Decrypted: {_render_plaintext(unpadded if unpadded else raw)}"
            return (
                f"Recovered WITHOUT factoring: c is an exact {e_int}-th power over the integers, "
                f"so the message never wrapped the modulus (small-e / no-padding).\n"
                f"m = {root}\n\n{body}"
            )

    # A shared prime across two moduli from the same buggy generator breaks both instantly.
    if n2.strip():
        n2_int = _parse_int(n2)
        if n2_int is None:
            return "n2 was provided but is not an integer (decimal, or hex with a 0x prefix)."
        shared = math.gcd(n_int, n2_int)
        if 1 < shared < n_int:
            p = shared
            q = n_int // p
            factors = [p, q]
            strategy = "shared prime factor with n2 (gcd)"
            notes.append(f"gcd(n, n2) = {p}")
        else:
            notes.append("n2 shares no non-trivial factor with n; fell back to factoring n alone.")
            factors, strategy = _factorize(n_int, deadline)
    else:
        factors, strategy = _factorize(n_int, deadline)

    if factors is None:
        reason = strategy
        return (
            f"Could not factor n ({n_int.bit_length()} bits): {reason}. Tried trial division to "
            f"{TRIAL_DIVISION_LIMIT}, perfect square, Fermat (close primes), and Pollard's rho. "
            "This modulus is not broken by any of those, so the intended attack is something else "
            "-- look for a second modulus sharing a factor (pass n2), a low public exponent, a "
            "reused/related message, or a leaked private value, and check search_skills for the "
            "crypto pack's RSA attack notes. Do NOT guess a flag."
        )

    factors.sort()
    phi = _phi_from_factors(factors)
    if math.gcd(e_int, phi) != 1:
        return (
            f"Factored n successfully via {strategy} -- factors: {factors} -- but e ({e_int}) "
            f"shares a common factor with phi ({math.gcd(e_int, phi)}), so no modular inverse d "
            "exists and the plain decryption does not apply. This usually means the challenge "
            "wants a different technique on top of the factorization, e.g. taking e-th roots per "
            "prime and recombining. Do NOT guess a flag."
        )

    d = pow(e_int, -1, phi)
    m = pow(c_int, d, n_int)
    raw = _int_to_bytes(m)
    unpadded = _strip_pkcs1_v15(raw)

    lines = [f"Factored n via {strategy}."]
    lines.extend(notes)
    if len(factors) == 2:
        lines.append(f"p = {factors[0]}")
        lines.append(f"q = {factors[1]}")
    else:
        lines.append(f"prime factors (with multiplicity) = {factors}")
    lines.append(f"phi = {phi}")
    lines.append(f"d = {d}")
    lines.append("")
    if unpadded is not None:
        lines.append(f"Decrypted (PKCS#1 v1.5 padding stripped): {_render_plaintext(unpadded)}")
        lines.append(f"Decrypted (raw block, unstripped): {_render_plaintext(raw)}")
    else:
        lines.append(f"Decrypted: {_render_plaintext(raw)}")
    return "\n".join(lines)
