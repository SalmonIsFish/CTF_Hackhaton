# Advanced Cryptography & Number Theory Techniques

**Level**: Advanced (20+ years cryptanalysis and CTF experience)
**Focus**: Implementation weaknesses, mathematical attacks, and real-world bypass techniques

## Symmetric Encryption Attacks

### AES (Advanced Encryption Standard)

#### ECB Mode Weaknesses
- **Pattern leakage**: ECB encrypts identical plaintext blocks to identical ciphertext → visual patterns leak information
- **Block oracle**: Encrypt known plaintext, compare blocks to discover message structure
- **CTF exploitation**: Often used on flags; if flag is short enough to fit in one block, can brute-force via block comparison
- **Attack**: Send payloads like `AAAA...`, `AAAB...`, `AAAC...` and identify which block matches target ciphertext

#### CBC Mode Attacks
- **IV reuse**: Same IV with different plaintexts reveals XOR relationship between plaintexts
- **Padding oracle**: Exploit error messages on bad padding to decrypt bit-by-bit
  - Send ciphertext with last byte modified
  - If decryption fails due to padding error vs. other errors, deduce plaintext byte
  - Iteratively reveal entire plaintext without key
- **Bit flipping**: Modifying ciphertext block N affects plaintext block N+1 (controlled corruption)

#### GCM Mode Attacks
- **Nonce reuse**: Same nonce with same key allows authentication tag forgery and plaintext recovery
- **Weak authentication**: If tag truncated or weakly verified, forgery becomes practical

#### Key Derivation Weaknesses
- **Weak KDF**: PBKDF2 with few iterations (< 100,000), MD5/SHA1 instead of SHA256
- **Hard-coded salt**: Same salt across all users/systems
- **Predictable password**: Common passwords (CTF context: often "password", "flag", "admin", "123456")
- **Attack**: Dictionary attack with rockyou.txt, CrackStation wordlist, or context-specific wordlist

### Stream Ciphers (RC4, ChaCha20)

#### RC4 Weaknesses
- **Biased keystream**: First bytes of keystream heavily biased; discard them (standard practice)
- **Key scheduling bias**: Related keys may produce correlated keystreams
- **Reusing IVs improperly**: If IV concatenated with key without proper mixing, recoverable
- **Attack**: Collect many ciphertexts with same key, analyze biased bytes for plaintext recovery

#### Weak Random Number Generators
- **Predictable PRNG**: Time-seeded random, low entropy, or weak algorithms
- **Attack**: Predict next bytes by observing current output (CTF: often seeded with timestamp)
- **Tools**: `z3`, constraint solvers to reverse PRNG state

### Known Plaintext Attacks

- **Partial plaintext**: If you know part of the plaintext (header, magic bytes, known format), recover key
- **Ciphertext-only on weak ciphers**: Frequency analysis on substitution ciphers (Caesar, Vigenère)
- **Repeating XOR**: If plaintext repeats XOR-ed with key, Kasiski examination + Friedman index reveal key length

## RSA & Public Key Attacks

### Weak Exponent Attacks

#### Small Public Exponent (e=3)
- **Cube root recovery**: If message m is small, c = m³ mod N can be small enough that m = ³√c directly
- **Attack**: Collect multiple ciphertexts (different recipients), Chinese Remainder Theorem may recover plaintext
- **Padding bypass**: PKCS#1 v1.5 padding with e=3 vulnerable to Hastad's broadcast attack

#### Common Modulus Attack
- **Setup**: Two messages encrypted with same N but different (e₁, e₂)
- **Attack**: If gcd(e₁, e₂) = 1, use extended Euclidean algorithm to recover plaintext
- **Formula**: m = (c₁^a * c₂^b) mod N where ae₁ + be₂ = 1

### Weak Modulus Generation

#### Small Prime Factors
- **Trial division**: If N = p*q where p or q is small (< 2^32), factorize instantly via trial division
- **Fermat factorization**: If p and q are close, N = a² - b² factorizes quickly
- **Pollard's p-1**: If p-1 has only small prime factors, efficient factorization

#### Shared Prime Factor
- **GCD attack**: If two RSA moduli N₁, N₂ share a prime factor, gcd(N₁, N₂) = p immediately factors both
- **CTF patterns**: Multiple users with weak key generation may share factors

#### Related Moduli
- **Wiener's attack**: If d < N^0.25, recover private exponent from public modulus via continued fractions
- **Small decryption exponent**: d too small makes RSA weak despite large N

### Padding Oracle Attacks (RSA-OAEP, PKCS#1)

- **Decryption oracle**: If you can ask server to decrypt ciphertexts and detect valid padding:
  - Gradually refine ciphertext via binary search
  - Asymptotically recover plaintext bit-by-bit
- **Error messages matter**: "Padding invalid" vs. "Signature invalid" vs. timeout reveals structure
- **Complexity**: O(log₂ N) queries needed, practical on small moduli

### Coppersmith's Attack

- **Partial key recovery**: If d (private exponent) is known to be small or have known high/low bits, recover fully
- **Polynomial root finding**: Reduce RSA to finding roots of polynomial, solvable via lattice basis reduction
- **Known MSBs of plaintext**: If m starts with known bytes, use Coppersmith to recover full plaintext
- **Tool**: Sage math or standalone coppersmith implementations

### Chosen Ciphertext Attacks (CCA)

- **Malleability**: For textbook RSA (no padding), c' = c * r^e mod N decrypts to m*r
  - Request decryption of c, multiply result by r to get m*r, then divide: m = (m*r) / r
- **Homomorphic property**: RSA is multiplicatively homomorphic; use this to construct chosen ciphertexts

## Elliptic Curve Cryptography (ECC) Attacks

### Weak Curves

- **Singular curves**: Curves with singularities (cusps, nodes) have reduced security
- **Anomalous curves**: Order of base point equals field size; Semaev's attack recovers private key instantly
- **Curves with small embedding degree**: Pairing-based attacks (MOV attack) reduce to DLP in smaller field

### Low-Order Points

- **Subgroup confinement**: If curve has small cofactor, points might lie in low-order subgroups
- **Attack**: Compute private key modulo small order, recover via CRT from multiple subgroups
- **Invalid curve points**: Some implementations don't validate point is on curve; attacker can use low-order points

### ECDLP (Elliptic Curve Discrete Log Problem)

- **Small subgroup**: If base point has small order, brute-force via meet-in-the-middle
- **Pohlig-Hellman**: Factor group order, solve DLP modulo each factor, reconstruct via CRT
- **Baby-step giant-step**: O(√n) algorithm for DLP on small curves
- **Pollard's rho**: Probabilistic DLP algorithm, practical for 64-80 bit groups

### Timing Attacks on ECC

- **Scalar multiplication timing**: Time taken to compute k*G leaks bits of k
- **Side-channel**: Distinguish 0-bit from 1-bit via cache timing, power consumption, or electromagnetic leakage

## Hash Function Attacks

### Collision Attacks

#### MD5
- **Broken**: Practical collision attacks exist (Wang et al., 2004)
- **CTF usage**: If comparing MD5 hashes, two different inputs can hash identically
- **Attack**: Use HashClash or fastcoll to generate colliding files

#### SHA-1
- **Weakened**: Collision attacks improved (Google's SHAttered, 2017); practical but slow (2^63 operations)
- **CTF context**: Usually impractical unless collision is pre-computed

#### SHA-256/SHA-3
- **No practical attacks** (as of 2026), but truncation weakens security

### Length Extension Attacks

- **Vulnerable hashes**: MD5, SHA-1, SHA-2 (SHA-256, SHA-512) using simple concatenation
- **Setup**: You know H(secret || message) and message length, but not secret
- **Attack**: Extend message to H(secret || message || attacker_data) without knowing secret
- **Formula**: Continue hash state as if you had the secret key; only message length must be known or brute-forced
- **CTF exploitation**: If flag is hashed, extend to perform arbitrary action authenticated by original hash

### Preimage Attacks

- **Weak iterative hashing**: H(H(H(...H(data)...))) n times; first preimage may be faster than full hash strength
- **Salted hashing**: If salt is weak or predictable, rainbow tables become practical
- **Password hash**: bcrypt/scrypt/Argon2 resist this; plain MD5/SHA-1 are vulnerable

## Discrete Logarithm Problem (DLP) Attacks

### Diffie-Hellman Weaknesses

#### Small Prime Group
- **Trial division**: If p-1 has only small factors, Pohlig-Hellman instantly recovers shared secret
- **Safe primes**: p = 2q+1 where q is prime; resists Pohlig-Hellman
- **CTF context**: Often weak parameters chosen deliberately; check factorization of p-1

#### Shared Generator Across Sessions
- **Replay attack**: If same (p, g) used repeatedly, intercept and replay old values
- **Man-in-the-middle**: Substitute own values without detection if endpoint doesn't validate consistency

#### Small Subgroup Confinement
- **Subgroup ordering**: If base point g has small order, DLP is brute-forcible modulo that order
- **Attack**: Recover key modulo multiple small primes via CRT

### Pohlig-Hellman Algorithm

- **Complexity**: O(√p) only for largest prime factor of p-1
- **Process**:
  1. Factor p-1 into prime powers
  2. For each prime power q^k, solve DLP modulo q^k via baby-step-giant-step
  3. Combine solutions via CRT to recover log modulo p-1
- **Mitigation**: Use safe primes (p = 2q+1) so only factors are 2 and large prime q

## Number Theory & Mathematical Attacks

### Fermat's Factorization

- **Applicable when**: p and q are close (difference < N^0.25 or so)
- **Method**: Find a, b such that N = a² - b² = (a-b)(a+b)
- **Process**: Start a = ⌈√N⌉, increment until a² - N is a perfect square
- **Complexity**: O(p-q) in worst case; fast when primes are close

### Pollard's p-1 Factorization

- **Applicable when**: p-1 (or q-1) has only small prime factors
- **Method**: Compute gcd(2^(k!)-1, N) where k! is factorial
- **Process**: Precompute products of powers of small primes; eventually p-1 divides k!, revealing p via GCD
- **Speed**: Fast if smallest prime factor of p-1 is small

### Quadratic Residue & Tonelli-Shanks

- **Problem**: Given n, find x such that x² ≡ a (mod p)
- **Tonelli-Shanks**: Efficient algorithm for modular square root
- **CTF context**: Often used in ECC, prime-modulus equations

## Lattice Attacks (LLL, CVP)

### LLL Algorithm

- **Basis reduction**: Finds "short" vectors in lattice
- **Application to cryptography**:
  - Recover close vectors (CVP: Closest Vector Problem)
  - Solve Coppersmith's attack (subset sum hardness)
  - Break NTRU-like schemes

### Subset Sum Problem

- **Setup**: Given set of numbers, find subset that sums to target
- **Knapsack cryptosystems**: Early proposal, broken via LLL
- **CTF context**: If presented as "find which items total to X", can be solved via lattice reduction

### Hidden Number Problem (HNP)

- **Setup**: Know most significant bits of k*x mod p for multiple k values
- **Attack**: Construct lattice, use LLL to recover x
- **Applications**: ECDSA weak RNG, DSA nonce recovery

## PRNG & Entropy Attacks

### Mersenne Twister Prediction

- **Weakness**: MT19937 has 624-int state; with 624 outputs, fully recoverable
- **Attack**: Collect 624 consecutive outputs, "untemper" each to recover internal state, predict next values
- **Python random**: Uses MT19937; if you see 624 sequential outputs, completely broken
- **Tool**: MT19937 predictor scripts available; implement untemper function

### Weak Seeding

- **Time-based**: `random.seed(time.time())` has only ~2^32 possibilities (seconds since epoch)
- **Low entropy**: Seed from predictable source (PID, timestamp, etc.)
- **Attack**: Brute-force seed space; once recovered, predict all outputs

### Linear Congruential Generator (LCG)

- **Formula**: x_{n+1} = (a*x_n + c) mod m
- **Weakness**: Predictable if you know a, c, m and see enough outputs
- **Recover state**: Solve linear system if consecutive outputs visible
- **Broken by**: Marsaglia's spectral test (correlations in consecutive outputs)

## Encoding & Serialization Attacks

### Base64 Variants

- **Standard Base64**: A-Za-z0-9+/
- **URL-safe Base64**: A-Za-z0-9-_
- **Base32, Base16**: Other encodings, sometimes mixed
- **Padding**: = (equal sign) padding can be manipulated
- **Attack**: Decode, check for serialized objects, extract secrets

### Pickle/Serialization RCE

- **Python pickle**: Unsafe deserialization → arbitrary code execution
- **Java serialization**: ObjectInputStream can trigger RCE via gadget chains
- **PHP unserialize**: Dangerous without restrictions; POP chains enable RCE
- **CTF context**: If encrypted blob is pickled data, decrypt then exploit deserialization

## Real-World Exploitation Patterns

### Combine Multiple Weaknesses

1. **Small e + Padding oracle**: Decrypt via both cube root + oracle bit-by-bit
2. **Weak PRNG + DLP**: Predict ECDSA nonce, recover private key
3. **Multiple RSA moduli + Common factor**: Factor one user's key, use to break others
4. **CRT + Side-channel**: Leak bits of d modulo p via timing, recover via Coppersmith

### Fault Injection Context

- **Corrupted ciphertexts**: If single-bit flip causes differential error, recover key
- **Reduced rounds**: Fewer encryption rounds → weaker resistance to attacks
- **State corruption**: Modify PRNG state mid-encryption → predictable output

### Meet-in-the-Middle & Dictionary Attacks

- **Combine searches**: Search from both ends toward middle
- **Time-space tradeoff**: Store precomputed values, match against target
- **Wordlist attacks**: For weak passphrases, try all common words/permutations

## CTF-Specific Winning Patterns

1. **Factor first**: Try trial division, Fermat, Pollard before assuming secure
2. **Check p-1 & q-1**: If factors are small, Pohlig-Hellman wins
3. **Multiple ciphertexts**: Common modulus attack, Chinese Remainder Theorem often apply
4. **Truncated/repeated keys**: Key reuse across different algorithms/modes is common in CTF
5. **Known plaintext**: Partial plaintext known (magic bytes, format) → recover key
6. **Side-channels matter**: Timing, bit length, error messages leak information
7. **PRNG prediction**: Predict next random value if seen enough outputs
8. **Lattice attacks work**: LLL + CVP solve many "impossible" problems in CTF
9. **Implementation > Theory**: Real crypto is broken by side-channels & bad random, not math
10. **Tools available**: Don't reinvent; use sagemath, z3, hashcat, John, fcrackzip

## Key Resources & Tools

- **SageMath**: Coppersmith attacks, lattice reduction, number theory
- **z3-solver**: Constraint solving for PRNG recovery, equation systems
- **hashcat / John the Ripper**: Hash & password cracking
- **fcrackzip**: Zip file password recovery (brute-force)
- **Sympy**: Python symbolic math, factorization, discrete log (small numbers)
- **gmpy2**: Fast big integer operations, primality testing
- **pymsieve**: Polynomial selection for GNFS factorization
