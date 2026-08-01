# Credential reuse & enumeration chain

**Category**: Web, methodology
**Prevalence**: High — a persistent pattern in real-world systems and CTFs
**Signal**: You've found credentials in one place (config file, database, IDOR leak, source code
comment) — but the user who owns them might have reused that password elsewhere. Test the same
credentials across all discovered services/users.

## The technique

Real-world workflow:

1. **Find credentials anywhere**: plaintext in a config file, leaked in `git log`, dumped via
   SQLi, found via IDOR, spotted in a comment in source code, default password, hard-coded API
   key.
2. **Identify users across services**: If you found a password for `admin@company.com`, scan for
   other services that might have accounts for that user: SSH, FTP, WordPress admin panel,
   database admin console, another web app on the same server, etc.
3. **Attempt reuse**: Try the same password on all of them. Often works because:
   - System admins reuse passwords across systems.
   - Developers embed credentials in code, then share that codebase.
   - Default accounts are never changed.
4. **Hash cracking (bonus step)**: If you find password hashes (bcrypt, Argon2, MD5), crack
   them with `hashcat` or `john`. Weak/old algorithms (MD5, SHA1) are crackable; modern ones
   (bcrypt with high rounds) are harder but not impossible if the password is weak.

## Enumeration angle

Before you have valid credentials, enumerate what users exist:

- **Username enumeration**: test registration, password reset, login with variations (`admin`,
  `test`, `administrator`, `root`, `demo`). Different responses (error message, response time)
  reveal which usernames exist.
- **Service discovery**: scan for common paths (`/admin`, `/login`, `/api/users`, `/.git`,
  `/.env`, `/backup`, `/upload`, `/download`). Document all services running on the target.
- **Directory brute-force**: use `ffuf` or similar to enumerate hidden endpoints, then note
  which ones require auth vs. are open.

Once you know the services and users, credential testing becomes targeted rather than random.

## Competition approach

1. **Early passive recon**: Check for `.git`, `/backup`, `/README.md`, `/robots.txt` for hints
   about services and default usernames.
2. **Active IDOR / info leakage**: Use IDOR or SQLi to enumerate users and their attributes
   (email patterns, usernames).
3. **Credential hunting**: Review source code snippets, config files, error messages, comments
   for any embedded secrets.
4. **Brute credential reuse**: Test each discovered credential against every discovered service.
5. **Hash cracking**: If you find weak hashes, crack them immediately (online tool or local
   `hashcat`).

## Real gotcha

Time spent cracking a bcrypt-12 hash (a month on a GPU) is often wasted effort in a CTF. If a
hash doesn't crack quickly, move on. Bcrypt/Argon2 with high work factors are intentionally
expensive — that's the point.

## Source

Recurring across 0xdf's HTB writeups — credential discovery and reuse form a consistent
exploitation chain for privilege escalation and lateral movement across multiple systems.

## Related

- [[idor-insecure-direct-object-reference]] — IDOR is a primary source of leaked credentials
- [[sql-injection-advanced]] (if created) — SQLi often reveals user tables with hashes
