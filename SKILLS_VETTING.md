# Third-Party Skill Vetting Log

Tracks skills.sh-sourced skills reviewed against the checklist in `CLAUDE.md` §5,
so this isn't re-litigated by a future session. Add an entry here before installing
anything new from skills.sh or ClawHub.

## Installed: `ljagiello/ctf-skills` (2026-07-30)

**What it is:** 11 skill packs (75 markdown files) covering CTF technique references —
web, pwn, crypto, reverse, forensics, osint, malware, misc, ai-ml, plus a
`solve-challenge` orchestrator and `ctf-writeup` generator. MIT license, 2.9k stars,
340 forks, 88 commits, actively maintained. Not on officialskills.sh (community-published).

**Installed via:** `npx skills add ljagiello/ctf-skills` — full repo, all 11 categories
(explicit choice over scoping to Web+Crypto+Forensics, since competition categories
aren't organizer-confirmed yet).

**What actually landed on disk:** only `.agents/skills/**/*.md` (skill content, no
scripts/binaries), `skills-lock.json` (hash-pinned source record), and
`.claude/settings.local.json` — the latter was diffed against its prior state and
**no new tool permissions were granted** by the install; it only carries the
pre-existing seekstone MCP enablement.

**Checklist review (rejected candidates, for context):**
- `yaklang/hack-skills` — **rejected outright.** Ships its real content as a
  password-protected ZIP on a CDN, with the README stating the password is public
  specifically to bypass automated scanner heuristics. That's the exact
  "obfuscation to evade scanners" red flag from the checklist.
- `Eyadkelleh/awesome-skills-security` — deprioritized, not deeply reviewed. Bundles
  an MCP server + REST API + ~20 extraction tools, a much larger surface than needed,
  and less specifically matched to CTF categories than ctf-skills.

**Checklist review (`ljagiello/ctf-skills` itself):**
- Read raw `README.md`, `scripts/install_ctf_tools.sh`, `ctf-crypto/SKILL.md`, and
  `SECURITY.md` directly from GitHub before installing — no obfuscated code, no
  base64 blobs, no credential/env-var exfiltration; install script only pulls from
  standard package managers (pip/apt/brew/gem/`go install`).
- `allowed-tools` frontmatter (`Bash Read Write Edit Glob Grep Task WebFetch
  WebSearch`) is broad but matches the stated purpose — these skills actively run
  tools and research techniques, they're not a read-only reference.
- `SECURITY.md` has a sane, appropriately scoped responsible-disclosure policy.

**⚠️ Post-install scanner flags — read before relying on this in a live round:**
The `skills add` CLI itself runs three automated scanners (Gen, Socket, Snyk) and
reported:

| Category | Gen | Socket | Snyk |
|---|---|---|---|
| ctf-ai-ml | Safe | 1 alert | Critical |
| ctf-crypto | Safe | 1 alert | Critical |
| ctf-forensics | Safe | 1 alert | Med |
| ctf-malware | Med | 0 alerts | Critical |
| ctf-misc | Safe | 1 alert | Critical |
| **ctf-osint** | **Critical** | 0 alerts | Med |
| ctf-pwn | Safe | 3 alerts | Critical |
| ctf-reverse | Safe | 1 alert | Med |
| **ctf-web** | **Critical** | 1 alert | Critical |
| ctf-writeup | Safe | 0 alerts | High |
| solve-challenge | Safe | 1 alert | High |

I manually grepped all 75 installed files afterward for the checklist's actual red
flags (base64 blobs, curl/wget to unfamiliar domains, credential exfiltration,
obfuscation) and found none — every hit traces back to legitimate CTF documentation:
real recon/RE tool sites (libc.rip, gtfobins.github.io, shodan.io, whatsmyname.app),
placeholder domains (`target.com`, `attacker.tld`), the AWS metadata IP
(`169.254.169.254`) as a standard SSRF teaching example, and code snippets
*demonstrating* vulnerable patterns rather than code that exfiltrates real secrets.

**Working conclusion:** the Critical labels are almost certainly false positives from
signature/keyword-based scanners that can't distinguish "documentation of an
SQLi/RCE/kernel-exploit technique" from "a payload doing it" — which is this repo's
entire stated purpose. Decision (made with the user, 2026-07-30): keep all 11
categories installed, on the strength of the manual file-by-file audit outweighing
the automated labels. If anyone has time before the event, a closer line-by-line
read of `ctf-web/` and `ctf-osint/` specifically (the two flagged by multiple
scanners) would be worthwhile, but isn't blocking.

**Still deliberately not run:** `scripts/install_ctf_tools.sh all` — this installs a
real toolchain (pwntools, angr, radare2, hashcat, sagemath, Frida, etc.) via
sudo/apt/brew/pip/go. Do this ahead of the event, not live during it, and note
CLAUDE.md still lists "network/internet access during competition" as an unanswered
organizer question — that affects whether this step is even viable on the day.
