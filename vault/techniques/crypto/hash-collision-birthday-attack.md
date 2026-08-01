# Hash collisions & birthday attack / MD5/SHA1 weaknesses

**Category**: Crypto
**Prevalence**: Moderate — less common than RSA, but still appears
**Signal**: A challenge involves finding two inputs that hash to the same value, or breaking a
hash function. Or the challenge uses MD5/SHA1 (cryptographically broken) for security purposes.

## The technique: Birthday paradox (generic collision)

By the birthday paradox, if you hash ~2^(n/2) random messages (where n is the hash bit length),
you're likely to find a collision.

For MD5 (128 bits):
```
~2^64 hashes needed (computationally expensive but feasible)
```

For SHA-256 (256 bits):
```
~2^128 hashes needed (infeasible with current hardware)
```

**In CTF context**: Usually a challenge won't ask you to brute-force 2^64 hashes. If it does,
it's either:
1. A trick (the collision is intentionally given or findable via a different method)
2. You can use precomputed collision tables (these exist for MD5)

## The technique: MD5 is broken (practical collisions)

In 2004, researchers discovered a practical **MD5 collision attack** — two different inputs that
hash to the same value can be found in seconds.

**Implication**: If a challenge uses MD5 for security (password hashing, digital signatures,
message authentication), it's intentionally broken for the purpose of the challenge.

Example: Two files with different content but the same MD5:
```
$ md5sum file1.bin file2.bin
d41d8cd98f00b204e9800998ecf8427e  file1.bin
d41d8cd98f00b204e9800998ecf8427e  file2.bin
```

An attacker can craft a payload that triggers either path depending on which hash the app
compares.

## The technique: SHA1 is weakened (not fully broken, but exploitable)

SHA1 is not as broken as MD5, but collision attacks have been demonstrated (SHAttered attack,
2017). Practical collisions are expensive but no longer theoretical.

## The technique: Length extension attack (specific to MD5/SHA1/SHA256)

If a hash is used for message authentication without a proper MAC:
```
hash = MD5(secret + message)
```

An attacker can forge a new message with the correct hash:
```
new_hash = MD5(secret + message + attacker_appended_data)
```

Even without knowing the secret, you can compute `new_hash` by:
1. Observing the original hash
2. Computing the state of the hash function after the message
3. Appending your data and continuing the hash computation

**Tool**: `hlextend` (Python package) for length extension attacks.

## Competition approach

1. **Identify the hash function**: Check source code or challenge description.
2. **If MD5 is used for security**:
   - Assume collisions exist or can be found easily
   - Look for precomputed collision tables online (many exist)
   - Or use `hashclash` (tool for finding MD5 collisions)
3. **If SHA1 is used**:
   - Check if it's for non-security purposes (fingerprinting, checksums) — usually OK
   - If used for authentication, assume weaknesses exist
4. **If length extension is possible**:
   - Use `hlextend` to forge a message with a valid hash
   - This often bypasses signature verification or message authentication

## Real gotcha

**Modern hashes** (SHA-256, SHA-3, bcrypt) are NOT broken in the above ways. If a challenge
uses a modern hash, the vulnerability is elsewhere (e.g., the algorithm using the hash is
flawed, not the hash itself).

## Tools

- **hashclash**: Finds MD5 collisions (slow but works)
- **hlextend**: Length extension attacks on MD5/SHA1/SHA256
- **Online MD5/SHA1 databases**: `md5.gromweb.com`, `crackstation.net` (precomputed
  hashes/rainbows for dictionary words)

## Source

Common in CTF crypto challenges, especially when challenges intentionally use broken algorithms
to teach about their weaknesses.

## Related

- [[weak-randomness-prng-prediction]] — weak RNGs can make brute-force collision search feasible
- [[rsa-weak-implementations]] — hash functions are often used in RSA signatures (weaker hash
  = weaker signature)
