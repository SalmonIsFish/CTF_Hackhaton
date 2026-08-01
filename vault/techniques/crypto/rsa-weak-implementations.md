# RSA weak implementations (low exponent, shared modulus, Wiener attack)

**Category**: Crypto
**Prevalence**: High — RSA appears in many CTFs, and implementation flaws are common
**Signal**: You have an RSA public key (n, e) and a ciphertext, but the implementation has a
flaw: e is very small, n is shared across multiple keys, or d (the private exponent) is small.

## The technique: Low exponent (e=3 or e=65537 with small m)

If e is very small (commonly 3) and the plaintext m is small:

```
c = m^3 mod n
```

If `m^3 < n` (i.e., `m^3` doesn't wrap around due to mod), then:
```
c = m^3 (no modular reduction)
m = cbrt(c)  # cube root, not modular
```

An attacker just computes the cube root of the ciphertext — no key needed.

**Check this first**: if you have multiple ciphertexts and only one or two decrypt easily, the
plaintext was probably small.

## The technique: Shared modulus (n reused, different e values)

If the same n is used with two different public exponents e1 and e2:

```
c1 = m^e1 mod n
c2 = m^e2 mod n
```

And if `gcd(e1, e2) = 1` (which is usually true for random e values), then using the **extended
Euclidean algorithm**, you can find integers a, b such that:

```
a*e1 + b*e2 = 1
```

Then:
```
m = (c1^a * c2^b) mod n
```

You can recover the plaintext without knowing the private key.

## The technique: Wiener attack (d too small)

If d (the private exponent) is smaller than roughly `n^0.25`, then d is recoverable from (e, n)
alone via continued fractions. Once d is known, you can decrypt any ciphertext.

**Tool**: `owiener` (Python package) or manual continued fractions implementation.

## The technique: Common factor in n (p or q shared)

If two RSA moduli n1 and n2 share a common factor (e.g., they both used a bad PRNG to generate
primes), then:

```
gcd(n1, n2) = p (or q, one of the prime factors)
```

Once you have p, you can factor n and recover the private key:
```
q = n / p
φ(n) = (p-1)(q-1)
d = e^-1 mod φ(n)  # recover private exponent
```

## Competition approach

1. **Identify the RSA setup**: Collect public keys (n, e), ciphertexts (c), and any hints (e.g.,
   "e is small", "multiple keys share modulus").
2. **Test for low exponent**: Try taking cube roots or fifth roots of ciphertext.
3. **Check for shared modulus**: If you have two (n, e1, c1) and (n, e2, c2) pairs, use the
   shared-modulus technique.
4. **Test Wiener**: If e is large and n is large, use `owiener` to check if d is small.
5. **Factor n**: If you suspect a weak prime (shared factor), compute gcd with other n values
   or use general factorization tools (`factordb.com`, `sympy.factorint()`).

## Real gotcha

**Modern RSA (e=65537, random large d) is NOT weak.** These attacks only work when the
implementation deviates from the standard. In a CTF, if a challenge hands you RSA, assume it's
broken in one of the above ways — standard RSA is computationally infeasible to break.

## Tools

- **owiener** (Python): `pip install owiener`; then `owiener.attack(e, n)`
- **RsaCtfTool** (GitHub, ctf-tools): automated RSA attack suite (tests all of the above + more)
- **sympy**: `factorint(n)` for factorization attempts
- **factordb.com**: online database of factored integers (often n has already been factored by
  researchers)

## Source

Common across CTF crypto challenges (picoCTF, HTB challenges, etc.). These are the first things
to check when you see RSA in a challenge.

## Related

- [[weak-randomness-prng-prediction]] — if RSA primes were generated with a weak RNG, you might
  recover them deterministically, allowing full factorization
- [[hash-collision-birthday-attack]] — RSA signatures use hash functions; if the hash is broken
  (MD5/SHA1), signatures can be forged
