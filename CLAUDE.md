# CTF HACKHATON — Agent Harness Instructions
> Drop this in your repo root. Claude Code loads it automatically every session.
> Fill in the `[ ]` placeholders once your team locks the idea.

## Mission
[One sentence: what does the agent do, for whom, and what's the demo-day "wow" moment?]

## Agent Formula
`Agent = LLM + Tools + Loop + Context`, running the ReAct cycle: **Thought → Action → Observation → repeat.**
Every sub-agent and tool you add should map back to one of those four parts — if it doesn't, cut it before demo day.

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

## 2. Free-Tier Model Routing
Since only you have Claude Code, keep the agent's *model provider* swappable so teammates can build/test against something they can actually call for free:

- **Google AI Studio** — free Gemini API key, generous quota, good default for teammates B/A to prototype tool-calling against.
- **Groq Cloud** — free, extremely fast inference on open models (Llama, etc.) — good for latency-sensitive demo loops.
- **OpenRouter** — free-tier models as a fallback if you hit rate limits mid-hackathon.
- Route through LangChain's chat model abstraction so switching provider is a one-line change, not a rewrite:

```python
# model_router.py
from langchain.chat_models import init_chat_model

def get_model(provider: str = "google"):
    return {
        "anthropic": lambda: init_chat_model("claude-sonnet-4-6", model_provider="anthropic"),
        "google":    lambda: init_chat_model("gemini-2.5-flash", model_provider="google_genai"),
        "groq":      lambda: init_chat_model("llama-3.3-70b-versatile", model_provider="groq"),
    }[provider]()
```

You keep Claude Code for orchestration/dev work; the shipped agent can run on whichever provider is cheapest/fastest for the demo.

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

Two MCP server options, pick based on time budget:

| Option | Needs Obsidian running? | Setup time | Good for |
|---|---|---|---|
| `mcp-obsidian` (REST API plugin-based) | Yes | ~10 min (install community plugin + API key) | Most documented, widest adoption |
| Filesystem-based server (e.g. `obsidian-mcp`, `mcpvault`) | No — reads the vault folder directly | ~5 min | Faster hackathon setup, no plugin dependency |

For a hackathon, the filesystem option is usually less friction — no plugin/API-key dance, works even if Obsidian isn't open on anyone's machine.

`.mcp.json` (project-level, so the whole team's Claude Code sessions pick it up):
```json
{
  "mcpServers": {
    "obsidian": {
      "command": "npx",
      "args": ["-y", "mcpvault", "/path/to/shared/vault"]
    }
  }
}
```
Wire it into LangGraph via `langchain-mcp-adapters` so your Python agent can call vault tools the same way it calls any other tool.

## 5. Vetting Third-Party Skills (skills.sh)
Worth knowing before your team installs anything: independent audits in 2026 (Snyk's ToxicSkills study, the ClawHavoc campaign) found real malicious skills distributed through skills.sh and ClawHub — credential exfiltration, backdoors, prompt injection — and researchers later showed the platform's automated malware scanner can be bypassed with basic obfuscation. So **no one can hand you a verified "safe" list**, including me — treat every third-party skill like an unreviewed code dependency.

Before installing any skill from skills.sh:
- [ ] Prefer **officialskills.sh** (vendor-published: Anthropic, Cloudflare, Microsoft, Stripe, etc.) over random community entries — known publisher = real accountability.
- [ ] Open the GitHub repo and actually read `SKILL.md` and any bundled scripts before running `npx skills add` — skills are Markdown + scripts, fully human-readable.
- [ ] Grep for red flags: calls to `curl`/`wget`/`fetch` against unfamiliar domains, base64-looking blobs, reads of env vars or credential files, unusually long lines or excessive blank/newline padding (a documented scanner-evasion trick).
- [ ] Check the `allowed-tools` frontmatter — a skill that only needs to read files shouldn't be requesting unrestricted `Bash`.
- [ ] Avoid ClawHub entirely for this event — it's the platform named in the 2026 ClawHavoc campaign.
- [ ] When in doubt, just write your own `SKILL.md` — for a 5-person hackathon team, a hand-written skill takes 10 minutes and carries zero supply-chain risk.

## 6. Repo Structure
```
project/
├── CLAUDE.md              ← this file
├── .mcp.json              ← Obsidian + other MCP servers
├── agent/                 ← LangGraph / Pydantic AI backend
│   ├── graph.py
│   ├── model_router.py
│   └── tools/
├── frontend/               ← Vercel AI SDK app
├── evals/                  ← test cases (harness element 8)
└── vault/                  ← shared Obsidian vault (or symlink to it)
```

## 7. Rough Timeline
- **Hour 0–1:** Lock the idea, fill in this file's placeholders, split branches
- **Hour 1–N-4:** Parallel build — agent core / frontend / prompts+evals / vault+pitch, merge every 60–90 min
- **N-4 to N-2:** Integration pass — everything talks to everything, run the eval set
- **N-2 to N-1:** Demo script rehearsal (Teammate C leads), record a fallback video
- **Last hour:** Buffer only — no new features
