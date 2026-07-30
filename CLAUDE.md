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
- `agent/graph.py` — LangGraph ReAct loop (think → act → observe), `MAX_STEPS = 15`, exits early when a tool result matches the flag pattern or the model returns no tool call. Includes a `SystemMessage` instructing the model to actively use tools — especially `search_vault` — rather than answering from its own general knowledge.
- Tools: `echo` (dummy, defined inline in `agent/graph.py`, not its own file), plus in `agent/tools/`: `find_flag_pattern` (regex for `flag{...}`/`CTF{...}`), `identify_and_decode` (base64/hex/rot13 — rot13 always "succeeds" on alphabetic input, documented in its own docstring/description), `search_vault` (substring search across `vault/*.md`, returns filename + line + context)
- `.mcp.json` — wired to **seekstone** (filesystem-based, no Obsidian app or plugin needed). Note: the original plan referenced `mcpvault`, which turned out to be placeholder text, not a real npm package — corrected to seekstone. **Not yet security-reviewed** — community-published, has read+write vault access. Worth a look at github.com/shaqmughal/seekstone before leaning on it for anything sensitive.
- `.agents/skills/` — 11 third-party CTF technique-reference skill packs installed from `ljagiello/ctf-skills` (`npx skills add`), plus `SKILLS_VETTING.md` (full vetting log) and `skills-lock.json` (hash-pinned source manifest). Automated scanners flagged `ctf-web` and `ctf-osint` "Critical," but both a manual file grep at install time and a follow-up spot-check (this session) found no obfuscation, credential exfiltration, or base64 payload blobs — every `/etc/passwd`-style hit is standard LFI/traversal documentation. Team decision: keep all 11 installed. See `SKILLS_VETTING.md` for full detail.
- `evals/test_tools_smoke.py` — standalone tests for all three real tools, passing
- `agent/graph.py`'s `__main__` block — 4 end-to-end test cases, **all passing** as of tonight on `gemini-3.5-flash-lite`:
  1. Plain echo (baseline loop works)
  2. Echo a flag → confirms early-exit works, doesn't run to MAX_STEPS
  3. Double-encoded flag (base64 of hex) → confirms **multi-step tool chaining** across loop iterations, not just single calls
  4. Vault lookup question → confirms the model calls `search_vault` (not just answering from training data) and grounds its answer in `vault/Web_Placeholder.md`

### Model choice — hard-won today, don't relitigate without new evidence
- **Default is `gemini-3.5-flash-lite`** (Google), not `gemini-flash-latest`/`gemini-3.6-flash` — that one only has a 20-requests/day free quota and gets exhausted fast. `gemini-3.5-flash-lite` has 500/day and passed all 4 cases including chaining.
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
- Farhan's real vault content not yet in `vault/` (only the placeholder `README.md` and test-fixture `Web_Placeholder.md` exist)
- Multi-API-key rotation/fallback (pooling teammates' keys with automatic failover) — discussed as competition-day insurance, not built yet, low priority given 500 RPD headroom already found on the current default
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

⚠️ **Not yet security-reviewed.** It's community-published (not an official/vendor package) and has read+write access to `vault/`. Per §5's vetting checklist, worth a quick look at its source before the team leans on it for anything sensitive — this was flagged but not yet done as of this handoff.

Two MCP server options, for reference:

| Option | Needs Obsidian running? | Setup time | Good for |
|---|---|---|---|
| `mcp-obsidian` (REST API plugin-based) | Yes | ~10 min (install community plugin + API key) | Most documented, widest adoption |
| Filesystem-based server (e.g. `seekstone`) | No — reads the vault folder directly | ~5 min | Faster hackathon setup, no plugin dependency — **this is what's in use** |

`.mcp.json` (project-level, so the whole team's Claude Code sessions pick it up):
```json
{
  "mcpServers": {
    "obsidian": {
      "command": "npx",
      "args": ["-y", "seekstone", "./vault"]
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
│   └── skills/            ← 11 CTF technique-reference skill packs (ljagiello/ctf-skills)
├── agent/
│   ├── model_router.py    ← done, verified
│   ├── graph.py           ← done, verified — ReAct loop + system prompt, 4 passing test cases in __main__
│   │                         (echo tool is defined inline here, not as its own file)
│   └── tools/
│       ├── find_flag_pattern.py     ← done, verified
│       ├── identify_and_decode.py   ← done, verified
│       └── search_vault.py          ← done, verified
├── frontend/              ← not started (Hasif's part)
├── evals/
│   ├── test_tools_smoke.py   ← standalone tool tests, passing
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
