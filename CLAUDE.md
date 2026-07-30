# CTF_HACKHATON — Agent Harness Instructions
> Drop this in your repo root. Claude Code loads it automatically every session.
> Fill in the `[ ]` placeholders once your team locks the idea.

## Mission
[One sentence: what does the agent do, for whom, and what's the demo-day "wow" moment?]

## Agent Formula
`Agent = LLM + Tools + Loop + Context`, running the ReAct cycle: **Thought → Action → Observation → repeat.**
Every sub-agent and tool you add should map back to one of those four parts — if it doesn't, cut it before demo day.

---

## Current Status — Session Handoff (last updated: solo build session, agent core complete)

**Read this first if you're a fresh Claude Code session picking this up.** Everything below is verified with real runs, not assumed.

### What's built and working
- `agent/model_router.py` — `get_model(provider)` for anthropic/google/groq, lazy-loaded via LangChain's `init_chat_model`, keys from `.env`
- `agent/graph.py` — LangGraph loop: **triage → think → act → observe → trim_context**, `MAX_STEPS = 15`, exits early when a tool result matches the flag pattern or the model returns no tool call. The `triage` node is the harness's "Sub-Agents" element (§3 #4) — a lightweight, separate model call that classifies the incoming prompt into one of `web/crypto/pwn/reverse/forensics/malware/osint/misc/ai-ml/blue-team/general` (`CATEGORY_SKILL_DIRS` in `agent/graph.py`), then `think`'s `SystemMessage` is built per-category (`build_system_prompt()`), nudging the model to ground its reasoning in that category's skill pack via `search_skills` before falling back to general knowledge. Verified working end to end (see test case 5 below): triage correctly routed a web-flavored prompt to `web` and an RSA prompt to `crypto`, each time producing an answer actually grounded in the right skill pack's content.
- `trim_context()` node in `agent/graph.py` — the harness's "State & Context Management" element (§3 #2). Runs once per loop iteration (after `observe`, before looping back to `think`); once more than `MAX_CONTEXT_MESSAGES` (16) think/act messages have accumulated, it drops the oldest ones via `RemoveMessage` (the `add_messages` reducer's delete-by-id mechanism), always keeping the first `HumanMessage` (the actual challenge prompt) untouched. Verified directly with a synthetic-state unit test in `evals/test_tools_smoke.py` (no API calls needed) rather than trying to force a real 15-step run just to trigger it.
- `message_text()` helper in `agent/graph.py` — Gemini sometimes returns `message.content` as a plain string and sometimes as a list of content blocks (thought-signature metadata attached); found this by chasing a real `AttributeError`/silent-`category`-fallback pair while building the triage node. Any code reading a message's final text (test assertions, the triage classifier) must go through this helper, not `.content` directly.
- **Grounding priority is explicit, not left to chance**: `build_system_prompt()` tells the model to check `search_vault` (the team's own notes) *before* `search_skills` (the broader third-party library) — added after case 4 flaked once with only `search_skills` called (both tools legitimately cover "check response headers", so without an explicit order the model's choice between them isn't deterministic).
- Tools: `echo` (dummy, defined inline in `agent/graph.py`, not its own file), plus in `agent/tools/`: `find_flag_pattern` (regex for `flag{...}`/`CTF{...}`), `identify_and_decode` (base64/hex/rot13 — rot13 always "succeeds" on alphabetic input, documented in its own docstring/description), `search_vault` (substring search across `vault/*.md`, returns filename + line + context), `search_skills` (same substring-search shape, but across `.agents/skills/**/*.md` — this is what actually connects the 14 vetted skill packs to the competition-day agent; before this, they only helped Claude Code while building, per the distinction called out in §4)
- `.mcp.json` — wired to **seekstone** (filesystem-based, no Obsidian app or plugin needed). Note: the original plan referenced `mcpvault`, which turned out to be placeholder text, not a real npm package — corrected to seekstone. **Security-reviewed this session — clean.** Community-published (16 stars, 1 fork — not on officialskills.sh-style vendor accountability) but genuinely well-engineered: CI, CodeQL, OpenSSF Scorecard, Dependabot all actually running, and — unlike most third-party vetting — the safety claims are backed by real tests, not just docs. Read the source of all 8 write-capable tools (`create_note`, `delete_note`, `move_note`, `append_note`, `patch_note`, `patch_frontmatter`, `replace_in_note`, `periodic_note`): every one independently checks the resolved path stays under `vaultRoot` before touching disk. `no-network.test.ts` mocks Node's raw `net.connect`/`http.request`/`https.request` to throw, then runs every tool including full indexing — proves zero outbound calls, not just "we don't call fetch that we know of." Dependencies are minimal and reputable (`@modelcontextprotocol/sdk`, `chokidar`, `fast-glob`, `minisearch`, `yaml`, `zod`). One caveat worth knowing, not fixing: `.mcp.json` sets `SEEKSTONE_VAULT=./vault`, a relative path, while seekstone's own `--help` documents this var as absolute — `index.ts` uses it as-is with no `path.resolve()`, so this only resolves correctly because Claude Code launches the process with CWD = repo root. Works fine in practice; a hardcoded absolute path would just break portability across teammates' machines instead, so this is a documented tradeoff, not a bug to chase.
- `.agents/skills/` — **14 third-party skill packs** total, all vetted in `SKILLS_VETTING.md` (full log) with `skills-lock.json` (hash-pinned source manifest):
  - 11 offensive CTF-technique packs from `ljagiello/ctf-skills` (`npx skills add`). Automated scanners flagged `ctf-web` and `ctf-osint` "Critical," but both a manual file grep at install time and a follow-up spot-check found no obfuscation, credential exfiltration, or base64 payload blobs — every `/etc/passwd`-style hit is standard LFI/traversal documentation. Team decision: keep all 11 installed.
  - 3 defensive/blue-team packs from `arttapon1/defensive-soc-skills` (`ir-report-builder`, `siem-detection-engineer`, `soar-playbook-builder`) — added to cover SOC/IR/detection-engineering knowledge the offense-only packs don't have. Content-level review (all 4 scripts + all 3 SKILL.md read directly) came back clean, but this repo has essentially no community track record (7 stars, 7 commits, one author) — accepted for a hackathon project, flagged as a real caveat.
- `evals/test_tools_smoke.py` — standalone tests for all four real tools (`find_flag_pattern`, `identify_and_decode`, `search_vault`, `search_skills`) plus a direct unit test of `trim_context`'s trimming logic, passing
- `agent/graph.py`'s `__main__` block — 5 end-to-end test cases, **all passing** on `gemini-3.5-flash-lite`:
  1. Plain echo (baseline loop works)
  2. Echo a flag → confirms early-exit works, doesn't run to MAX_STEPS
  3. Double-encoded flag (base64 of hex) → confirms **multi-step tool chaining** across loop iterations, not just single calls
  4. Vault lookup question → confirms the model calls `search_vault` (not just answering from training data) and grounds its answer in `vault/Web_Placeholder.md`
  5. RSA-attack question → confirms **sub-agent triage routes to `category: crypto`**, the model calls `search_skills`, and the answer is grounded in a real technique from `ctf-crypto`'s RSA attack notes (Wiener/Coppersmith/common modulus/low exponent)
- `demo/` — harness element #9 (Deploy/Demo Readiness). `python -m demo.run_demo` is the one-command entrypoint: fails fast with a clear message if `GOOGLE_API_KEY` isn't set (instead of a confusing API error mid-run), solves the seeded `response_headers.txt` challenge (a captured HTTP response with a base64-of-hex flag in a custom header — deliberately solvable with only the tools that already exist, no live target or network dependency), and exits `1` if no flag was found so a regression shows up as a failing command before demo day. `expected_transcript.txt` is a captured successful run, checked in as a **text fallback** if live tools flake on stage — **still need an actual rehearsed screen recording before the event**, this transcript is a placeholder until that's done, not a replacement for it.

### Model choice — hard-won today, don't relitigate without new evidence
- **Default is `gemini-3.5-flash-lite`** (Google), not `gemini-flash-latest`/`gemini-3.6-flash` — that one only has a 20-requests/day free quota and gets exhausted fast. `gemini-3.5-flash-lite` has 500/day and passed all 5 cases including chaining and sub-agent triage.
- `gemini-2.5-flash` — **retired**, 404s on this key regardless of quota. Don't retry it.
- `gemini-2.0-flash` — zero free-tier entitlement on this key. Don't bother.
- Groq `gpt-oss-120b` — reliable tool-call *syntax*, but **fails multi-step chaining** (case 3): calls `echo` redundantly instead of re-decoding, states the flag as prose instead of through a tool. Not suitable as primary.
- Groq `llama-3.3-70b-versatile` — reproducibly emits malformed tool-call syntax, rejected by Groq as `400 tool_use_failed`. This is a known, documented issue with Llama models + tool-calling generally, not specific to this project. Don't use for anything requiring tool calls.
- Full comparison table lives in `evals/practice_runs.md`.

### Known harmless noise (don't waste time on these)
- `UserWarning: Core Pydantic V1 functionality isn't compatible with Python 3.14` — cosmetic, from LangChain's compat shim, not a real failure.
- Windows console may show `�` for em-dashes — cosmetic terminal encoding, not file corruption (confirmed the underlying files are clean UTF-8).

### Not yet done
- ~~Closer read of `ctf-web`/`ctf-osint` skill packs~~ — done this session, confirmed vetting log's conclusion (no red flags found)
- Rashid hasn't started — categories not yet locked (Web + Crypto + Forensics is the working assumption from earlier planning, not confirmed)
- Hasif hasn't started — but there's now a real, tested agent to point the dashboard at instead of a stub
- **No API bridge between the Python agent and a JS frontend yet.** `agent/graph.py` is LangGraph/Python; Hasif's planned dashboard is Next.js — a Next.js API route can't just `import` Python code. Needs a small FastAPI (or similar) server wrapping `build_graph()`/`app.invoke(...)` so `app/api/agent/route.ts` has a real HTTP endpoint to call instead of the stub. This is naturally "agent core / final integration" work (mine), not Hasif's — not built yet as of this handoff. Suggested contract: `POST /solve {prompt: str} -> {category, steps, flag, tool_calls}` (or a streamed version of the same, if Hasif's live-trace UI wants incremental updates rather than a single final response).
- **Current design is a semi-autonomous copilot, not an autonomous scanner.** The agent has no tool that reaches out to a target on its own (no live `nc`/socket tool; `fetch_page`, once Rashid builds it, still requires a human to hand it a URL). An operator pastes/feeds challenge artifacts in; the agent reasons over what it's given. This matches the still-unanswered "autonomy requirements" organizer question below — worth chasing an answer, since it determines how much more "reach out and touch the target" tooling (if any) is worth building before the event.
- Farhan's real vault content not yet in `vault/` (only the placeholder `README.md` and test-fixture `Web_Placeholder.md` exist)
- Multi-API-key rotation/fallback (pooling teammates' keys with automatic failover) — discussed as competition-day insurance, not built yet, low priority given 500 RPD headroom already found on the current default
- ~~`ANTHROPIC_API_KEY` absent from `.env`~~ — confirmed intentional: the team deliberately runs on the `google` provider only, since it has the highest free-tier request quota of the three (see §2). The `anthropic` entry in `model_router.py` is not expected to be usable without adding a key.
- ~~`scripts/install_ctf_tools.sh all` (the real CTF toolchain: pwntools, radare2, hashcat, angr, Frida, sagemath, etc.)~~ — done this session, on WSL Ubuntu. `bash install_ctf_tools.sh --verify` reports **56/58 found**. The two "missing" are known and not worth chasing further:
  - `py:ropper` — permanent, unfixable on Python 3.14. Its dependency `filebytes` calls `ast.Str`, a Python API removed in 3.12+; that package is unmaintained upstream. `ROPgadget` (installed, does the same job) is the substitute.
  - `ffuf` — not actually broken, just not on `$PATH` yet. The Go install put the binary at `~/go/bin/ffuf`; add `export PATH="$PATH:$(go env GOPATH)/bin"` to `~/.bashrc`.
  Real upstream bugs hit and fixed along the way, worth knowing if re-running this on a fresh machine:
  - Python 3.14 is too new for several packages to have prebuilt wheels yet (`unicorn`, `angr`'s x86_64 wheel, `yara-python`, etc. for the exact pinned versions), forcing source builds that need `build-essential cmake python3.14-dev libssl-dev zlib1g-dev libjpeg-dev libfreetype6-dev rustc cargo` (angr's own package has a Rust build step) — install all of these up front next time.
  - `unicorn==2.1.2`'s own CMake build has a real bug: `qemu/osdep.h` gates `sys/mman.h` behind `#ifdef CONFIG_POSIX`, which the CMake path never defines (confirmed by direct source build) — this is why `mprotect`/`PROT_*` errors showed up. Not worth patching directly: `angr`/`qiling`'s looser dependency constraints pull in `unicorn==2.1.4` instead, which ships a working `abi3` wheel (no compile needed).
  - `pwntools==4.15.0` explicitly excludes `unicorn!=2.1.3,!=2.1.4` in its own metadata, so a plain `pip install pwntools` tries to build the broken 2.1.2 from source. Fix: `pip install --no-deps pwntools==4.15.0`, then install its other real dependencies (paramiko, mako, pyelftools, ropgadget, pyserial, requests, pygments, pysocks, python-dateutil, packaging, psutil, intervaltree, sortedcontainers, six, rpyc, colored_traceback, unix-ar, zstandard) manually. pip will warn about the unicorn version mismatch — harmless; core pwntools features (`ELF`, packing, process/remote I/O) don't touch unicorn at all.
  - `angr==9.2.193` failed to *import* (not install) due to `pycparser` 3.0 (a new, breaking major release) removing the ability to set `CLexer.filename`, which `angr`'s bundled `pyvex` relies on. Fix: `pip install pycparser==2.23` (last 2.x release).
  - `fpylll==0.6.4` was missing an undeclared dependency, `cysignals` — `pip install cysignals` fixes it.
  - All of the above venv work happens inside `~/.ctf-tools/venv` (created by the script itself, since this Ubuntu's Python 3.14 is "externally managed" per PEP 668) — never `pip install` outside it.
- Awaiting organizer reply on: network/internet access during competition, presentation vs. flag-only scoring, confirmed categories, autonomy requirements, environment/VM provisioning, team-role rules, submission format

---

## 1. Team Roles (built for mixed access — 3 free-tier, 1 no laptop)

The bottleneck in most hackathons isn't the idea, it's serializing work through one paid tool. Decouple roles so nobody blocks on Claude Pro:

| Person | Access | Owns | Why this split |
|---|---|---|---|
| You | Claude Code CLI | Agent core: LangGraph/Pydantic AI state graph, harness, Obsidian MCP wiring, final integration | Only role that strictly needs Claude Code |
| Hasif | Free-tier model + laptop | Frontend: Vercel AI SDK streaming UI | Frontend work barely touches the agent's model choice |
| Rashid | Free-tier model + laptop | Prompts, sub-agent design, eval harness, test cases | Can iterate entirely against a free API, no Claude needed |
| Farhan | No laptop | Obsidian vault (mobile app), pitch narrative, demo script, judge Q&A prep, live QA of the deployed demo from their phone | Obsidian has first-class iOS/Android apps — this role needs zero dev environment |

Detailed, step-by-step task briefs for Hasif, Rashid, and Farhan are in `TEAM_TASKS.md`.

Git workflow: small feature branches (`frontend/*`, `agent/*`, `prompts/*`), PR into `main` every 60–90 min, integrate early and often — don't save integration for the last hour.

## 2. Free-Tier Model Routing (updated with verified findings — see Current Status above)
Since only you have Claude Code, keep the agent's *model provider* swappable so teammates can build/test against something they can actually call for free. The specific model choices below aren't the original plan — they're what actually survived real testing:

```python
# model_router.py — as of tonight's build
from langchain.chat_models import init_chat_model
from dotenv import load_dotenv
load_dotenv()

_PROVIDERS = {
    "anthropic": lambda: init_chat_model("claude-sonnet-4-6", model_provider="anthropic"),
    "google":    lambda: init_chat_model("gemini-3.5-flash-lite", model_provider="google_genai"),  # NOT gemini-flash-latest — see below
    "groq":      lambda: init_chat_model("llama-3.3-70b-versatile", model_provider="groq"),  # has known tool-call bugs — see below
}

def get_model(provider: str = "google"):
    if provider not in _PROVIDERS:
        raise ValueError(f"Unknown provider '{provider}'. Choose from: {list(_PROVIDERS)}")
    return _PROVIDERS[provider]()
```

**Why `gemini-3.5-flash-lite` and not the more obvious `gemini-2.5-flash` or `gemini-flash-latest`:** rate limits on Google AI Studio are per-model, not per-account, and they vary wildly — `gemini-flash-latest` (resolves to `gemini-3.6-flash`) is capped at 20 requests/day on a free key, which is not enough for a full competition day. `gemini-2.5-flash` is retired entirely on newer keys. `gemini-3.5-flash-lite` has 500/day and, importantly, passed the hardest test (multi-step tool chaining) that a faster/cheaper Groq model failed. Check current rate limits yourself before the competition — these change and shouldn't be trusted from memory (yours or Claude's): Google AI Studio's own dashboard shows live, per-model numbers for whatever key you're using.

**Why not just use Groq as primary despite the free-tier headroom being larger:** raw request quota doesn't matter if the model can't reliably format tool calls. Verified today: Llama models on Groq have a known, reproducible issue emitting malformed tool-call syntax that gets rejected outright. A newer OpenAI-lineage model on Groq (`gpt-oss-120b`) fixed that specific problem but was worse at *multi-step* reasoning (chaining two tool calls in sequence) — which matters more for CTF challenges than raw syntax correctness. Don't assume this is fixed without re-testing; open-model tool-calling reliability is genuinely inconsistent across providers and versions.

You keep Claude Code for orchestration/dev work; the shipped agent runs on whichever provider actually passed the eval suite — check `evals/practice_runs.md` before changing the default.

## 3. Agent Harness Checklist
Your brief named 5 elements under "9 Harness Elements" — here's the full 9 so nothing's missed at integration time:

1. **Control Loop** — bounded `while`/graph loop, explicit max-steps and exit conditions
2. **State & Context Management** — trim/summarize context between turns; don't let it grow unbounded
3. **Modular Skills & Tools** — typed params + Pydantic/Zod validation, one clear docstring per tool
4. **Sub-Agents** — Explore → Plan → Code → Test (or your domain's equivalent), sequential or parallel
5. **Safety & Observability** — lifecycle hooks, guardrails, least-privilege tool permissions, human-in-the-loop on destructive actions
6. **Model/Provider Routing & Fallback** — see §2; if Groq/Gemini free tier rate-limits mid-demo, fall back gracefully
7. **Memory & Persistence** — short-term (per-run) vs long-term (cross-session). This is where Obsidian comes in (§4).
8. **Evaluation Harness** — even 5–10 hand-written test cases beat none; run them before every merge to `main`
9. **Deploy/Demo Readiness** — one-command startup, seeded demo data, a fallback recording in case live tools flake on stage

## 4. Obsidian Integration
Obsidian works well here as your agent's **long-term memory / knowledge base**, and it's the natural home for Teammate C's mobile-only contributions (notes, pitch draft, task list — all sync automatically into the vault the agent reads from).

**Update: already set up, using `seekstone`.** The original two options below are kept for context, but `mcpvault` (previously listed) turned out to be placeholder text, not a real package — it 404s on npm. The repo now uses **seekstone** (github.com/shaqmughal/seekstone), a real filesystem-direct server, confirmed connected via `claude mcp list`.

✅ **Security-reviewed — clean, see the "What's built and working" bullet above for the full writeup.** It's community-published (not an official/vendor package) with read+write access to `vault/`, but the source backs up its safety claims with actual tests (a dedicated test blocks Node's network primitives and proves the server never phones home) rather than just documentation, and every write-capable tool independently validates paths stay inside the vault. One documented, low-severity caveat: our `.mcp.json` uses a relative `SEEKSTONE_VAULT` path, which only resolves correctly because of Claude Code's launch CWD — works fine in practice, noted for awareness.

Two MCP server options, for reference:

| Option | Needs Obsidian running? | Setup time | Good for |
|---|---|---|---|
| `mcp-obsidian` (REST API plugin-based) | Yes | ~10 min (install community plugin + API key) | Most documented, widest adoption |
| Filesystem-based server (e.g. `seekstone`) | No — reads the vault folder directly | ~5 min | Faster hackathon setup, no plugin dependency — **this is what's in use** |

`.mcp.json` (project-level, so the whole team's Claude Code sessions pick it up) — this is the actual file, corrected from an earlier stale example that showed the vault path as a positional CLI arg rather than the `SEEKSTONE_VAULT` env var seekstone actually reads:
```json
{
  "mcpServers": {
    "obsidian": {
      "command": "npx",
      "args": ["-y", "seekstone"],
      "env": {
        "SEEKSTONE_VAULT": "./vault"
      }
    }
  }
}
```
**Important distinction, easy to conflate:** this `.mcp.json` wires the vault into **Claude Code** (so it can read vault notes while helping you build) — it does **not** automatically wire the vault into the actual competition-day agent. That's handled separately by the `search_vault` tool in `agent/tools/`, a plain Python function that reads `vault/*.md` directly. Two different consumers of the same folder; don't assume one gives you the other.

New MCP servers found in `.mcp.json` require one-time interactive approval (`claude mcp list` will show "Pending approval" until you run `claude` in a real interactive terminal and approve it — doesn't work through piped/non-interactive sessions). Already approved for "this and future servers in this project" as of this handoff, so this shouldn't prompt again on this machine.

## 5. Vetting Third-Party Skills (skills.sh)
Worth knowing before your team installs anything: independent audits in 2026 (Snyk's ToxicSkills study, the ClawHavoc campaign) found real malicious skills distributed through skills.sh and ClawHub — credential exfiltration, backdoors, prompt injection — and researchers later showed the platform's automated malware scanner can be bypassed with basic obfuscation. So **no one can hand you a verified "safe" list**, including me — treat every third-party skill like an unreviewed code dependency.

Before installing any skill from skills.sh:
- [ ] Prefer **officialskills.sh** (vendor-published: Anthropic, Cloudflare, Microsoft, Stripe, etc.) over random community entries — known publisher = real accountability.
- [ ] Open the GitHub repo and actually read `SKILL.md` and any bundled scripts before running `npx skills add` — skills are Markdown + scripts, fully human-readable.
- [ ] Grep for red flags: calls to `curl`/`wget`/`fetch` against unfamiliar domains, base64-looking blobs, reads of env vars or credential files, unusually long lines or excessive blank/newline padding (a documented scanner-evasion trick).
- [ ] Check the `allowed-tools` frontmatter — a skill that only needs to read files shouldn't be requesting unrestricted `Bash`.
- [ ] Avoid ClawHub entirely for this event — it's the platform named in the 2026 ClawHavoc campaign.
- [ ] When in doubt, just write your own `SKILL.md` — for a 5-person hackathon team, a hand-written skill takes 10 minutes and carries zero supply-chain risk.

## 6. Repo Structure (as actually built, not just planned)
```
CTF_Hackhaton/
├── CLAUDE.md              ← this file
├── TEAM_TASKS.md          ← detailed per-person task briefs
├── .env / .env.example    ← API keys (ANTHROPIC_API_KEY, GOOGLE_API_KEY, GROQ_API_KEY) — .env is gitignored
├── .gitignore
├── requirements.txt
├── .mcp.json              ← seekstone (Obsidian vault access for Claude Code)
├── SKILLS_VETTING.md      ← vetting log for third-party skills.sh installs
├── skills-lock.json       ← hash-pinned source manifest for installed skills
├── .agents/
│   └── skills/            ← 14 third-party skill packs: 11 offensive (ljagiello/ctf-skills)
│                             + 3 defensive/blue-team (arttapon1/defensive-soc-skills)
├── agent/
│   ├── model_router.py    ← done, verified
│   ├── graph.py           ← done, verified — triage → think → act → observe → trim_context loop,
│   │                         5 passing test cases in __main__ (echo tool defined inline here)
│   └── tools/
│       ├── find_flag_pattern.py     ← done, verified
│       ├── identify_and_decode.py   ← done, verified
│       ├── search_vault.py          ← done, verified
│       └── search_skills.py         ← done, verified — connects .agents/skills/ to the runtime agent
├── demo/                  ← harness element #9 (Deploy/Demo Readiness)
│   ├── run_demo.py            ← one-command entrypoint: `python -m demo.run_demo`
│   ├── response_headers.txt   ← seeded demo challenge, solvable offline with existing tools
│   ├── expected_transcript.txt ← captured successful run, text fallback until a real recording exists
│   └── README.md
├── frontend/              ← not started (Hasif's part)
├── evals/
│   ├── test_tools_smoke.py   ← standalone tool tests + trim_context unit test, passing
│   └── practice_runs.md      ← model comparison findings + picoCTF results go here
└── vault/
    ├── README.md              ← placeholder, explains folder purpose
    └── Web_Placeholder.md     ← test fixture only — replace/expand with Farhan's real notes
```

## 7. Rough Timeline
- **Hour 0–1:** Lock the idea, fill in this file's placeholders, split branches
- **Hour 1–N-4:** Parallel build — agent core / frontend / prompts+evals / vault+pitch, merge every 60–90 min
- **N-4 to N-2:** Integration pass — everything talks to everything, run the eval set
- **N-2 to N-1:** Demo script rehearsal (Teammate C leads), record a fallback video
- **Last hour:** Buffer only — no new features
