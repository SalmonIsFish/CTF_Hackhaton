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

## Installed: `arttapon1/defensive-soc-skills` (2026-07-30)

**What it is:** 3 skill packs, defensive/blue-team oriented (the offense-only
`ctf-forensics`/`ctf-malware` above don't cover this): `ir-report-builder` (logs →
normalized timeline → NIST SP 800-61 / SANS PICERL incident response report + exec
summary), `siem-detection-engineer` (writes vendor-neutral Sigma detection rules,
converts to Splunk SPL / Sentinel KQL / Elastic EQL, maps to MITRE ATT&CK), and
`soar-playbook-builder` (threat-intel enrichment + automated firewall/WAF/EDR
response playbook generation). MIT license. **Not on officialskills.sh** (community,
individual author) — and unlike `ctf-skills`, has essentially no community track
record: **7 GitHub stars, 7 commits, one author.** That's the honest risk accepted
here: this vetting rests entirely on a direct code read, not on outside validation.

**Installed via:** `npx skills add arttapon1/defensive-soc-skills --all`.

**Checklist review — read all 4 scripts and all 3 `SKILL.md` files directly from
GitHub before installing, not just the README:**
- `log_timeline.py` (ir-report-builder): normalizes syslog/CEF/JSON/CSV/CloudTrail
  logs into one timeline; hashes every input file (SHA-256) for chain-of-custody;
  never writes to input files.
- `sigma_to_queries.py` (siem-detection-engineer): stdlib-only text transform,
  Sigma YAML → SPL/KQL/EQL. No network calls at all.
- `enrich_ioc.py` (soar-playbook-builder): queries VirusTotal / AbuseIPDB / OTX /
  Group-IB for indicator reputation. Read-only (never blocks anything). API keys
  come only from env vars (`VT_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`,
  `GROUPIB_API_KEY`); each key is sent only to its own named vendor endpoint, never
  logged, never cross-sent. Sources with no key set are skipped gracefully.
- `respond_block.py` (soar-playbook-builder) — the one script that can touch real
  infrastructure (Cloudflare/PAN-OS/FortiGate/CrowdStrike block/unblock APIs).
  Reviewed carefully as the highest-risk file in the pack: **dry-run by default**,
  requires an explicit `--commit` flag *and* real (non-placeholder) credentials
  before sending anything, hard-refuses to ever block RFC1918/loopback/link-local
  ranges regardless of flags, redacts the `Authorization` header in all printed
  output, and every `block` action has a matching `--action unblock` rollback path.
  This is meaningfully more safety-conscious than the bar the checklist asks for.
- `allowed-tools` frontmatter (`Read, Grep, Glob, Bash, Write`) on all 3 — same
  scope as the existing ctf-skills packs, no broader ask than what the workflow
  (read logs, run the reference scripts, write reports/rules) actually needs.
- No obfuscation, no base64 blobs, no credential-file reads, no unfamiliar domains
  (only named, real vendor APIs: VirusTotal, AbuseIPDB, AlienVault OTX, Cloudflare,
  Palo Alto, Fortinet, CrowdStrike).

**Post-install cleanup:** the `skills` CLI's "install to all agent formats" step
also copied a reformatted duplicate of all 3 skills into `agent/skills/` — inside
this repo's actual Python package directory, not the project's `.agents/skills/`
convention. Removed; only `.agents/skills/{ir-report-builder,siem-detection-engineer,
soar-playbook-builder}` should exist. Worth double-checking after any future
`npx skills add` in case the CLI does this again — `agent/` apparently gets swept up
by its generic agent-directory detection.

**Working conclusion:** content-level review is clean and genuinely careful
engineering — installed. The star/commit count is real reputational risk that a
thorough manual read doesn't fully offset; acceptable for a hackathon project where
nothing in this pack executes automatically (an agent has to deliberately invoke
these scripts), not something I'd wave through for production SOC automation
without more outside review first.

## Installed: `shadcn/ui` skill `shadcn`, `vercel-labs/agent-skills` skill `web-design-guidelines` (2026-08-05)

**What they are:** not CTF-technique packs like everything above — these are
**Claude-Code-authoring aids** for the dashboard UI redesign (component library
knowledge + an accessibility/UX audit checklist), not something the runtime CTF
agent's `search_skills` tool needs to see. Both are **vendor-published**
(officialskills.sh-tier accountability, the top preference in this checklist):
`shadcn` is published by the shadcn/ui org itself, `web-design-guidelines` by
`vercel-labs` (Vercel's own org).

**Installed via:**
`npx skills add shadcn/ui --skill shadcn --agent claude-code` and
`npx skills add vercel-labs/agent-skills --skill web-design-guidelines --agent claude-code`.

**Where they landed — a real deviation from every prior install above, noted for
whoever reads this next:** both went into `.claude/skills/`, not this repo's usual
`.agents/skills/` convention. That's expected here, not a bug to fix: `.agents/skills/`
is specifically what `agent/tools/search_skills.py` reads to ground the *runtime CTF
agent's* answers (per `CLAUDE.md` §4's "two different consumers of the same folder"
distinction) — these two skills are for me while building the dashboard, the same
role `.mcp.json`'s seekstone vault access already plays, so `.claude/skills/` (Claude
Code's own skill directory) is the correct target, and nothing needs moving.

**Checklist review:**
- `shadcn`'s `SKILL.md`: pure Markdown guidance (component patterns, CLI usage,
  styling rules) plus a handful of linked `rules/*.md` reference files — no scripts,
  no obfuscation, no base64. `allowed-tools` frontmatter is scoped tightly to
  `Bash(npx shadcn@latest *)` / `pnpm dlx shadcn@latest *` / `bunx --bun shadcn@latest
  *` only — not unrestricted Bash — which matches the checklist's ask, since the
  skill's entire job is running that one CLI. The CLI does hit shadcn's component
  registry over the network to fetch component source; that's the stated
  functionality (installing UI components), not a red flag.
- `web-design-guidelines`'s `SKILL.md`: even smaller surface — no `allowed-tools`
  restriction declared, but the described behavior is read-only (reads the target
  files, fetches one known `raw.githubusercontent.com/vercel-labs/...` URL for the
  current guideline rules, outputs findings as text). No credential access, no writes.
- Both post-install scanner results: Gen=Safe, Socket=0 alerts, **Snyk=Med Risk** on
  both. Per this file's own precedent with `ctf-skills` (Critical labels on
  `ctf-web`/`ctf-osint` turned out to be false positives from keyword-based scanning
  that can't tell documentation from payloads), a "Med Risk" purely from declaring
  `allowed-tools: Bash(...)` at all — with the actual command scoped to one
  well-known CLI — reads the same way. Not independently re-verified beyond reading
  the files directly.

**Working conclusion:** both installed. Lower risk profile than any prior install in
this log — no user-facing scripts execute, and both publishers have real
organizational accountability (shadcn/ui, Vercel), unlike the community/single-author
packs above.
