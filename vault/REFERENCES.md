# External References & Resources

A curated list of high-quality CTF learning and writeup sources, collected and validated during
development. All links verified as of 2026-08-01. This is the "CTF Brain"'s external backbone —
when internal vault notes cite a technique or challenge, these are the authoritative sources to
read for deeper context.

## General CTF Knowledge & Formats

- **CTF Wiki** — https://ctf-wiki.org/en/introduction/mode/
  - Comprehensive technical reference covering all major CTF categories: Misc, Crypto, Web,
    Assembly, Reverse engineering, Pwn, AI security, Android, ICS, Blockchain.
  - Explains competition formats: Jeopardy (online, problem-solving) vs. Belluminar (team-based)
    vs. Attack & Defense (offline, real-time).
  - Good for understanding "what is a CTF" and broad-strokes technique reference.

## HackTheBox Challenge Writeups

- **0xdf Hacks Stuff** — https://0xdf.gitlab.io/
  - One of the most respected HTB writeup archives in the community. Covers Web, Windows/Active
    Directory, Linux, Crypto, Reverse engineering, Cloud security, and specialized challenges.
  - Author has clear professional pen-testing + competitive CTF experience.
  - High depth on multi-step exploitation chains and advanced techniques.
  - Best source for "how do I approach this class of challenge" beyond our own vault.

- **7rocky's HTB Challenges** — https://7rocky.github.io/en/ctf/htb-challenges/
  - Solid HTB writeup blog, known community reputation.
  - Good quick reference for individual challenge solutions.

## AI Agents for CTF

- **"Cracking CTFs and Finding Zero-Days with AI Agents"** by harishhacker3010
  - https://medium.com/@harishhacker3010/cracking-ctfs-and-finding-zero-days-with-ai-agents-41a1083ba088
  - Real, practical experience report from building an AI agent (`SWE-Agent`) to solve CTF
    challenges autonomously.
  - Key findings: tool availability > raw model capability; time-boxed execution kills
    long-running exploits; complex multi-step reverse engineering overwhelms context.
  - Solved ~10 HTB easy challenges + 15 PicoCTF challenges (reversing, crypto, web, forensics).
  - Identified real CVEs including Apache Pulsar Zip Slip vulnerability.
  - Validates our own independent findings (that tools matter more than model choice, that
    scope matters, that time constraints are real).

## Specific Challenge Writeups Used This Session

- **HackTheBox "Space Explorer" Writeup** by Ravi Aravindhan
  - https://medium.com/@raviaravindhan.official/htb-space-explorer-writeup-07fb8945aa6a
  - Source writeup for the JSON key-casing differential exploit (Go vs Python parsing).
  - Cross-validated our own independent solve — writeup and our exploitation matched exactly.

## Integration with the agent & team

- Vault technique notes (under `vault/techniques/`) reference these URLs in their source-challenge
  sections — if you're reading a vault note and want to deep-dive, these are the places to follow.
- `search_vault` finds technique notes by substring; these URLs are the "go read this" links
  when the agent needs to learn a new category of exploit.
- **For competition day**: `web-testing-methodology.md` is your baseline checklist for every web
  challenge. Start there, then reference individual technique notes as needed.
- Internal best practice: when adding a new technique note to the vault, add a corresponding
  entry here if you're relying on an external writeup/reference.

## Vault content added this session

All technique notes are filed under `vault/techniques/web/` (further categorization by
subcategory, e.g. `auth-bypass/`, `injection/`, if this grows):

**From real external targets solved**:
- `json-parser-key-casing-differential.md` — Go vs Python JSON parsing (HackTheBox "Space Explorer")
- `cookie-trust-auth-bypass.md` — unsigned identity cookies (HackTheBox "Desires")
- `predictable-session-id-timestamp-hash.md` — sha256(timestamp) session IDs (HackTheBox "Desires")
- `zip-slip-symlink-bypass.md` — archive extraction symlink traversal (HackTheBox "Desires")
- `secnotes-analysis-dead-end.md` — confirmed dead-end analysis (TryHackMe "SecNotes")

**From external reference reading** (0xdf, ctf-wiki, writeup blogs):
- `server-side-template-injection-ssti.md` — Jinja2/XSLT injection to RCE
- `idor-insecure-direct-object-reference.md` — ID-based access control bypass
- `credential-reuse-enumeration-pattern.md` — finding and reusing leaked credentials across services
- `deserialization-rce.md` — Java/PHP/Python unsafe deserialization
- `command-injection-shell-escape.md` — shell metacharacter injection in post-processing
- `sql-injection-creative-bypasses.md` — SQLi with creative filter bypasses

**Methodology**:
- `web-testing-methodology.md` — prioritized checklist for testing any web challenge (start here)
