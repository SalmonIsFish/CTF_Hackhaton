# Hackathon Submission — Team Gamabunta

Quick-reference answers to each submission requirement. Full architecture/design writeup is in
[`WRITEUP.md`](./WRITEUP.md); the deep technical build log is in [`CLAUDE.md`](./CLAUDE.md).

## Team Name

**Gamabunta**

## GitHub Repository

**https://github.com/SalmonIsFish/CTF_Hackhaton** — public, hosted under the registered team
leader's account.

## Documentation / Writeup

See [`WRITEUP.md`](./WRITEUP.md) — covers agent harness architecture, implementation approach,
design decisions, results, and team roles.

## Technology Stack

| Layer | Choice |
|---|---|
| Orchestration | [LangGraph](https://github.com/langchain-ai/langgraph) (state graph: triage → think → act → observe → trim_context), [LangChain](https://github.com/langchain-ai/langchain) (`init_chat_model`, tool binding) |
| LLM providers | Google Gemini (`gemini-3.5-flash-lite`, default — primary driver), Groq (`llama-3.3-70b-versatile` / `gpt-oss-120b`, evaluated fallback), Anthropic (`claude-sonnet-4-6`, available via the same router) |
| Backend | Python 3.14, [FastAPI](https://fastapi.tiangolo.com/) (`agent/api.py` — `/solve`, `/solve/stream`, `/solve/resume`), `uvicorn` |
| Frontend | Next.js, [Vercel AI SDK](https://sdk.vercel.ai/) (`useChat`, `DefaultChatTransport`), React |
| Long-term memory | Obsidian-format Markdown vault (`vault/`), read via a custom `search_vault` tool and via Claude Code's [seekstone](https://github.com/shaqmughal/seekstone) MCP server |
| Skills library | 14 vetted third-party CTF technique packs (`.agents/skills/`) — 11 offensive from `ljagiello/ctf-skills`, 3 defensive/SOC from `arttapon1/defensive-soc-skills` |
| Live-target tooling | Pure-Python `requests`-based HTTP (`fetch_url`, `upload_file`), raw-socket TCP sessions (`tcp_session`), a `socket`-based port sweep (`port_scan`) — no subprocess/shell surface |
| Binary analysis | `radare2` / `rabin2` / `ROPgadget`, bridged from Windows into a WSL Ubuntu toolchain via a fixed-argv `subprocess` call (the one deliberate subprocess/shell exception, argv-only, no shell string building) |
| Remote access | `paramiko` (SSH/SFTP) — `ssh_analyze_binary`, `ssh_run` |
| Safety / HITL | LangGraph `interrupt()` + `MemorySaver` checkpointer for human-in-the-loop approval gating on live-network tool calls |
| Telemetry | LangSmith tracing (opt-in via `LANGCHAIN_TRACING_V2`), local JSONL run log (`evals/run_log.jsonl`) |
| Isolation | Docker (`python:3.14-slim`, non-root user, read-only root filesystem + `/tmp` tmpfs, mem/cpu caps), `docker-compose.yml` |
| Testing | Custom smoke-test suite (`evals/test_tools_smoke.py`, `evals/test_model_router_smoke.py`), offline practice-target servers (`evals/practice_targets.py`) simulating real CTF-shaped services |
| Crypto/math tooling | Hand-built `rsa_int_tools` (textbook RSA from bare integers: factoring via trial division, Fermat, Pollard's rho, small-e root, cross-modulus GCD), `math_tools` (modular exponentiation, Diffie–Hellman), `rsa_tools` (PEM/file-based RSA), `crack_hash` (MD5/SHA1/SHA256 wordlist cracking) |

## Notes for Judges

- The agent is deliberately **not** fully autonomous by design — live-target actions can be gated
  behind an explicit human approve/deny step, matching the organizer's own "Enforce Permissions"
  guidance rather than running unattended against scored infrastructure.
- Results (29 real flags captured, including 4 from this event's own live challenges) are indexed
  in [`evals/solved_challenges.md`](./evals/solved_challenges.md) with full narrative write-ups in
  [`evals/practice_runs.md`](./evals/practice_runs.md) — autonomy level is reported honestly per
  challenge, not rounded up.
