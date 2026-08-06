# CTF Hackathon Agent

An autonomous CTF-solving agent (`LLM + Tools + Loop + Context`) built on LangGraph, paired with
a Next.js dashboard for driving and watching it work. Given a challenge prompt (and optionally a
live `host:port`), it triages the category, reasons over a bounded tool-use loop, grounds itself
in a local vault + 14 vetted CTF technique packs before falling back to general knowledge, and
returns a flag (or its best answer) with a full tool-call trace.

## Architecture at a glance

| Path | What it is |
|---|---|
| `agent/graph.py` | The LangGraph core: `triage → think → act → observe → trim_context` loop |
| `agent/model_router.py` | Swappable model provider (Anthropic/Google/Groq), multi-key rotation |
| `agent/api.py` | FastAPI bridge (`/solve`, `/solve/stream`, `/solve/resume`) used by the dashboard |
| `agent/tools/` | `fetch_url`, `tcp_session`, `port_scan`, `dir_enum`, `upload_file`, `search_vault`, `search_skills`, `identify_and_decode`, `find_flag_pattern`, `web_search`, ... |
| `dashboard/` | Next.js + Vercel AI SDK chat UI that talks to `agent/api.py` |
| `vault/` | The agent's long-term memory (Markdown notes), read by the `search_vault` tool and by Claude Code via the `seekstone` MCP server |
| `.agents/skills/` | 14 vetted third-party CTF technique packs (`ctf-web`, `ctf-crypto`, `ctf-pwn`, ... — see `SKILLS_VETTING.md`), read by `search_skills` |
| `demo/` | One-command, offline, seeded demo runs |
| `evals/` | Smoke-test scripts and practice-run logs |

For the full build history, model-choice rationale, and known issues, see `CLAUDE.md`. For the
current TODO list, see `NEXT_STEPS.md`. Per-teammate task briefs are in `TEAM_TASKS.md`.

## Results

Flag captures are tracked as a running index in `evals/solved_challenges.md` (full narrative
write-ups, including bugs found and fixed along the way, live in `evals/practice_runs.md`). As of
this writeup: **28 real flags captured** across picoCTF, HackTheBox, and this event's own
organizer-set challenges, including three from the live competition itself:

| Challenge | Category | Flag |
|---|---|---|
| Saturn Exchange | web — business-logic race condition (TOCTOU) | `UCSI26{4sync_settlement_r4c3_110cbe1e}` |
| StaffDesk | web — GraphQL IDOR → admin takeover | `UCSI26{gr4phql_1d0r_2_admin_t4k30v3r}` |
| Sandworm VM | pwn — custom VM, unchecked-offset OOB read/write | `UCSI26{sandworm_vm_oob_escape_025a2ef7}` |

Autonomy varies by write-up and is reported honestly rather than rounded up — many picoCTF/HTB
flags were captured by the agent loop end-to-end with no human intervention (see
`evals/solved_challenges.md` for the step counts), while the three competition flags above were
solved by a human/Claude Code directly against the live scored infrastructure, with real gaps this
exposed in the agent (no concurrent-request tool, no GraphQL-introspection nudge, no custom-ISA
reversing workflow) called out as open items in `evals/solved_challenges.md` and `NEXT_STEPS.md`
rather than glossed over.

## Prerequisites

- Python 3.14
- Node.js (for the dashboard)
- A [Google AI Studio](https://aistudio.google.com/) API key at minimum — the default provider
  is `gemini-3.5-flash-lite` (see `CLAUDE.md` for why this specific model). Anthropic/Groq keys
  are optional, only needed if you switch providers in `agent/model_router.py`.

## Setup

```bash
# Python deps (use a venv)
pip install -r requirements.txt

# API keys
cp .env.example .env
# then edit .env and set at least GOOGLE_API_KEY

# Dashboard deps
cd dashboard && npm install && cd ..
```

## Running it

**Agent API (backend):**
```bash
uvicorn agent.api:app --reload --port 8000
```

**Dashboard (frontend):** in a second terminal
```bash
cd dashboard
npm run dev
```
Open `http://localhost:3000`. The dashboard proxies chat messages to the agent API at
`http://localhost:8000` by default — override with `AGENT_API_URL` in `dashboard/.env.local` if
the API runs elsewhere.

**Seeded demos** (no live target, no dashboard needed):
```bash
python -m demo.run_demo            # static-file challenge, base case
python -m demo.run_demo_network    # exercises the live-network tools against a throwaway local server
python -m demo.run_demo_hitl       # same as above, with human-in-the-loop approval gating
```

**Smoke tests:**
```bash
python -m evals.test_tools_smoke
python -m evals.test_model_router_smoke
```

**Containerized (Isolate Execution):**
```bash
docker compose up
```
Runs the agent API only (`agent/api.py`), non-root, read-only root filesystem — see `Dockerfile`
and `docker-compose.yml`. Run the dashboard separately against it.

## Docs map

- `CLAUDE.md` — technical reference: what's built, why, and how (start here for deep context)
- `NEXT_STEPS.md` — the TODO list, in priority order
- `TEAM_TASKS.md` — per-person task briefs
- `SKILLS_VETTING.md` / `skills-lock.json` — vetting log for third-party skill packs
- `evals/practice_runs.md` — model comparison results and real-target practice-run write-ups
