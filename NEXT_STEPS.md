# Next Steps

> This is the TODO list — what to actually do next, in priority order. `CLAUDE.md` is the
> technical reference (what's built, why, how it works); keep that for "how does X work,"
> keep this one for "what's left." Update this file as things get done or new gaps show up —
> don't let it drift the way `CLAUDE.md`'s old inline "Not yet done" section did.

Four phases below, in the order they actually unblock each other: validate the new
network tools before trusting them, then close the loop with organizers, then unstick the
two teammates who haven't started. A "Lower priority" and an "Explicitly out of scope"
list follow for anything not on the critical path.

## Phase 0 — Organizer slide compliance (done)

The organizer stopped answering questions ("ask trainers during the workshop, but the
workshop is already done") and the recording had nothing useful — the only concrete
guidance left was a "Next Steps: Implementation" slide (Pick Framework & Tools / Isolate
Execution / Enforce Permissions / Full Telemetry). All three items that used to be
"explicitly out of scope" below are now built and verified:

- [x] **Enforce Permissions (HITL)** — LangGraph `interrupt()` + `MemorySaver`
  checkpointer gate `fetch_url`/`tcp_open`/`port_scan` in `act()`
  (`agent/graph.py`) behind an operator approve/deny decision when
  `require_approval` is set on `AgentState`. Defaults to falsy everywhere existing, so
  every automated eval/demo is unaffected. CLI side: `run_interactive()` in
  `agent/graph.py`, driven live by `demo/run_demo_hitl.py`. HTTP side: `agent/api.py`'s
  `/solve` and `/solve/stream` return `{"status": "pending_approval", "thread_id", "interrupt"}`
  instead of finishing, and `POST /solve/resume` continues that thread with `"approve"` or
  `"deny"`. **Verified**: both the approve and deny paths were exercised directly against a
  live local target (approve reaches the flag, deny returns "Denied by operator" and never
  leaks it), through both the CLI mechanism and the API's sync + resume endpoints; the
  existing 5-case suite, both demos, and `evals/practice_runs_network.py` were re-run
  afterward with no regression. Known caveat, documented in `agent/graph.py`: if a single
  model turn makes more than one gated tool call, resuming the second interrupt replays the
  node from the top, so an already-approved earlier call in the same batch would re-fire.
  Not engineered around — the model makes one tool call per turn in every case observed so
  far.
- [x] **Full Telemetry** — turned out to be near-zero-cost: `langsmith` and
  `langgraph-checkpoint` were already installed as transitive deps. `.env.example` has a
  commented-out `LANGCHAIN_TRACING_V2`/`LANGCHAIN_API_KEY`/`LANGCHAIN_PROJECT` block (with
  an explicit note that turning it on sends challenge prompts and live tool output to
  LangSmith, a third-party service — a real trade-off, not defaulted on). `run_config()` in
  `agent/graph.py` tags every `graph.invoke`/`graph.stream` call for LangSmith when it's
  configured. Independent of any LangSmith account: `log_run()` (`agent/graph.py`) appends
  one JSON line per completed run (prompt, category, steps, flag, full tool trace, reusing
  the existing `extract_tool_trace()`) to `evals/run_log.jsonl` (gitignored), called from
  `run_case()`, `run_interactive()`, `/solve`, `/solve/resume`, and `/solve/stream`.
  **Verified**: confirmed inert with `LANGCHAIN_TRACING_V2` unset (identical behavior across
  the full existing test/demo suite); confirmed `run_log.jsonl` gets a correctly-populated
  line from `/solve`, `/solve/resume`, and `/solve/stream` (the streaming path needed an
  explicit fix — the initial `HumanMessage` is part of the input, not a node-emitted delta,
  so `messages_by_id` had to be pre-seeded with it or the logged prompt came back `null`).
- [x] **Isolate Execution (Docker)** — `Dockerfile` (repo root) containerizes
  `agent/api.py` on `python:3.14-slim` (matches the local dev interpreter), non-root user,
  copies only what the running agent actually reads (`agent/`, `vault/`,
  `.agents/skills/`). `docker-compose.yml` adds `mem_limit`/`cpus` caps, `read_only: true`
  with a `/tmp` tmpfs, and a dedicated bridge network (not host networking).
  **Verified**: `docker build` succeeds; `docker run`/`docker compose up` both serve
  `/health` correctly; `docker exec ... whoami` confirms non-root; a write outside `/tmp`
  fails with "Read-only file system" while a write inside `/tmp` succeeds; a real solve
  (`echo` flag) and a real live-network solve (`fetch_url` against a host-side server via
  `host.docker.internal`) both succeeded through the containerized API.
  **Honest scope limit, not silently oversold**: this gives process/filesystem isolation
  and resource caps, not per-challenge dynamic network egress restriction — the tools are
  pure Python with no shell surface, so there was never a subprocess for Docker's threat
  model to contain, and the host allowlist stays enforced the existing way, in Python, via
  `extract_allowed_hosts()`/`act()`.

**Cross-cutting change from this phase**: `build_graph()` now compiles with a
`MemorySaver` checkpointer unconditionally, so every `graph.invoke`/`graph.stream` call
anywhere in the codebase needs a `thread_id` in its config — use the new `run_config()`
helper (`agent/graph.py`) rather than constructing `{"recursion_limit": ...}` by hand; every
existing call site (`demo/`, `evals/`, `agent/api.py`) was updated to use it.

## Phase 1 — Validate the network tools against real targets (must)

**Update: the mechanical validation is done.** A screenshot of the organizer's own reference
harness (mid-conversation) showed a bare-IP challenge (no port given) being scanned for open
ports, service names, and version banners — confirming port discovery is genuinely needed,
not just "port comes with the IP." `agent/tools/port_scan.py` (pure Python, no nmap/subprocess
— see Architecture note below) was added to close that gap. All three realistic local
scenarios below now pass end-to-end via `python -m evals.practice_runs_network`; full results
in `evals/practice_runs.md`.

- [x] Confirm `tcp_session` handles a real login-prompt-then-command service, not just an
  echo server. **PASS** — reached the flag via a real `tcp_open`→`tcp_send`→`tcp_send`
  sequence against a local login-gated service.
- [x] Confirm `fetch_url` behaves sanely on a real challenge's redirects/cookies. **PASS** —
  follows a 302+`Set-Cookie` chain to the final response in one call.
- [x] Port/service discovery — **PASS** — `port_scan` correctly reports an open port's banner
  vs. closed/filtered adjacent ports.
- [x] Stress-test `extract_allowed_hosts` (in `agent/graph.py`) against real challenge
  phrasing. **PASS** — no regex gap found across `Target: host:port`, `nc host port`,
  `host:port`, `http(s)://host:port`, and parenthetical-port forms; see
  `evals/test_tools_smoke.py`.
- [x] Log every result in `evals/practice_runs.md`. **Done.**
- [x] Real (non-localhost) internet target — **PASS** — `python -m evals.real_target_check`
  against `scanme.nmap.org` (nmap's own public scanning-practice box). Port-state detection
  was solid both runs; SSH's version banner was never captured even after widening
  `port_scan`'s timeouts (now the shipped default) — a real, honest limitation: banner
  capture is best-effort against a real host, unlike the instant response a local test
  server gives. Full write-up in `evals/practice_runs.md`.
- [x] Pull real *network-based CTF challenges* and run each through the full agent loop.
  **Done, via TryHackMe + HackTheBox free tiers** (no organizer/picoCTF target exists yet, so
  these stood in — same "actual scored/CTF-shaped service" risk this item was tracking).
  Full write-up in `evals/practice_runs.md`. Two real external targets, no flag on either,
  but both genuinely informative:
  - **TryHackMe Room 404** — reached via OpenVPN (had to switch from UDP, which stalled on a
    TLS handshake timeout, to TCP 443 — worth remembering if this happens again on any
    OpenVPN-based platform). Agent explored sensibly but the free-tier lab machine's 1-hour
    hard limit killed it mid-run before it found the hidden endpoint. Surfaced a real gap:
    no directory/wordlist enumeration tool — `fetch_url` only tries paths the model itself
    thinks to guess.
  - **HackTheBox "Space Explorer"** — reached directly over the public internet (HTB exposes
    standalone challenge spawns on a public IP, no VPN hop needed for this one). Two runs:
    blind (no flag, found the right endpoint/action names unprompted by reading page JS) and
    with the challenge's own source code pasted into the prompt (got much closer — correctly
    identified "conflicting JSON keys" as the right attack category — but missed the specific
    Go-case-insensitive-vs-Python-case-sensitive key-matching trick that actually works).
    Manually confirmed the real exploit (`HTB{C0SM1C-BYP4SS}`) to validate the root cause.
    This is a reasoning-depth limit, not a tooling gap — `fetch_url` could already express the
    winning request.
  - Also the first real exercise of `require_approval`/`interrupt()` (Phase 0) against
    genuinely external targets, not just local demos — every live-target call on both
    platforms was gated and approved before firing.

Owner: you, ideally with Rashid once he's back (see Phase 3).

## Phase 2 — Close the organizer-question loop (must)

- [x] Network/internet access during competition — confirmed by the organizer's own demo
  (a challenge handed out as a bare IP).
- [ ] Presentation vs. flag-only scoring.
- [ ] Confirmed categories.
- [ ] Autonomy requirements — the demo answers "is it network-based," not "how autonomous
  does the agent need to be" (fully autonomous solve vs. operator-assisted).
- [ ] Environment/VM provisioning — fixed IP range, VPN, or literally "here's an IP" per
  challenge?
- [ ] Team-role rules.
- [ ] Submission format.

## Phase 3 — Teammate sync (must)

As of this handoff, none of the three teammates have started their piece. Hasif is now the
single biggest not-started risk on the team — the API bridge has been ready and tested for
a while, so there's nothing left blocking him.

- [ ] **Rashid** — finalize 2–3 CTF categories now that network/web is a confirmed real
  category (Web + Crypto + Forensics/Misc was the working assumption, not confirmed).
  `identify_and_decode`, `find_flag_pattern`, `fetch_url`, and
  `tcp_open`/`tcp_send`/`tcp_close` are already built — don't redo them. Still open:
  `extract_metadata` for forensics, if that category gets confirmed.
- [ ] **Rashid** — co-run the Phase 1 validation pass once categories are picked.
- [ ] **Hasif** — start the dashboard against the already-live API bridge:
  `uvicorn agent.api:app --reload --port 8000`, `POST /solve` and `POST /solve/stream` are
  both live and tested; see `TEAM_TASKS.md` for the exact contract.
- [ ] **Farhan** — write real vault content once Rashid's category list is final (only
  placeholder `README.md` and test-fixture `Web_Placeholder.md` exist in `vault/` today) —
  worth waiting so effort isn't spent on categories the team doesn't end up attempting.

## Phase 4 — Polish (nice to have, only if time remains)

- [x] ~~Pure-Python port-probe tool~~ — done, promoted to Phase 1 (see above) once the
  organizer's demo confirmed bare-IP-no-port challenges are real, not hypothetical.
- [ ] Real `nmap` via subprocess, tightly allowlisted (fixed flags only). Considered and
  deferred, not rejected outright — see Architecture note below for the reasoning
  (competition machine runs Windows, nmap isn't installed there, and installing it is its own
  unstarted task). Worth revisiting only if nmap gets installed on the actual competition
  machine before the event and there's still time to wrap/test it.
- [x] ~~Optional `target` field on `SolveRequest`~~ — done. Folds into the prompt text
  (`Target: {target}\n\n{prompt}`) rather than separate graph state, so it flows through the
  same `extract_allowed_hosts()` path a plain-text mention would.
- [x] ~~Multi-API-key rotation/fallback~~ — done. `GOOGLE_API_KEYS` (comma-separated, see
  `.env.example`) rotates to the next teammate's key on a real `429`/`RESOURCE_EXHAUSTED`
  from Gemini; falls back to the single `GOOGLE_API_KEY` if unset, so nobody's `.env` needed
  to change. Verified with stubbed models in `evals/test_model_router_smoke.py` (no real quota
  exhaustion needed to test the logic).
- [ ] An actual rehearsed screen recording of the demo — ideally showing a real network
  solve once Phase 1 lands, not just the synthetic local-server one.
  `demo/expected_transcript.txt` is a text placeholder, not a substitute.

## Explicitly out of scope for this event (updated)

Decided against the "Cybersecurity Toolset" / multi-agent-swarm style reference material
the team was given:

- Semgrep/Ghidra/Caido subprocess wrappers
- Multi-agent triage/exploit/reporting swarm
- Canary tokens
- Secondary-evaluator LLM

Reasoning: no infra time to build/test any of them properly this week, and none of them
were named on the organizer's own "Next Steps" slide the way Docker/HITL/telemetry were
(see Phase 0 above) — these four are extra reference material beyond what that slide
actually asked for. Revisit only with real spare time or evidence organizer challenges
specifically need one of them.

**Docker sandboxing and the LangSmith/Logfire-style tracing pipeline moved off this
list** — both built and verified, see Phase 0 above. The reasoning that moved them off
mirrors what moved nmap below: once there was a concrete signal (there, the organizer's
demo; here, the organizer's own slide), and once the actual cost turned out lower than
assumed (`langsmith`/`langgraph-checkpoint` were already installed transitively; Docker
Desktop was already available), "no infra time" stopped being the accurate reason to skip
them.

**Nmap moved off this list** — a screenshot of the organizer's reference harness confirmed
port discovery is a real need, and `agent/tools/port_scan.py` (pure Python) now covers it.
Real nmap itself stays a Phase 4 stretch item, not fully out of scope, gated on installing it
on the actual competition machine first.

## Architecture note worth remembering

The agent is no longer a pure "semi-autonomous copilot" — it now has three tools that reach
out to a live target on their own: `fetch_url` (`agent/tools/fetch_url.py`),
`tcp_open`/`tcp_send`/`tcp_close` (`agent/tools/tcp_session.py`, a multi-turn
`nc`/pwntools-`remote()`-style session — connect once, send/receive repeatedly, close
explicitly), and `port_scan` (`agent/tools/port_scan.py`, added after the organizer's demo
showed bare-IP-no-port challenges are real — sweeps a capped candidate port list via
`socket.connect_ex()` and passively reads any banner volunteered on connect, e.g. SSH's
unprompted version string). All three are pure Python (`requests` / stdlib `socket`) — no
subprocess, no shell, no Nmap/Docker. Real nmap was considered for `port_scan` specifically
(would add scan speed and version probes for silent protocols like HTTP) but deferred: it
isn't installed on the machine the agent actually runs on (Windows, confirmed, not the WSL
box `scripts/install_ctf_tools.sh` targets), and everything the organizer's demo actually
showed (port state, SSH banner text, "Ubuntu" read out of that banner) is reproducible
without it.

Safety model added alongside them, all in `agent/graph.py`:

- **Target allowlist** — `extract_allowed_hosts()` pulls the host/IP out of the original
  challenge prompt; `act()` refuses any `fetch_url`/`tcp_open`/`port_scan` call whose target
  isn't in that set, before the tool ever runs.
- **Per-call timeouts and response-size caps** inside both tools (never model-configurable
  past a hard ceiling).
- **TCP session backstops** (`agent/tools/tcp_session.py`): max 3 concurrent sessions, 60s
  absolute session lifetime, all sessions force-closed on every graph exit path.
- **Loop detection** — `route_after_observe` now also ends the run early (keeping partial
  results) if the last 3 tool calls were identical, on top of the existing `MAX_STEPS` cap —
  added because a live target timing out is exactly the failure mode that invites blind
  retries against real scored infrastructure.
- **Prompt-injection guard** — both tools wrap their return value in
  `<untrusted_data source="...">` tags, and `build_system_prompt()` now always includes a
  fixed instruction not to treat that content as directives, since it's the first tool
  output in this repo that's attacker-influenced rather than team-authored.
- **Operator approval (Phase 0)** — on top of the allowlist above, `act()` can pause any
  `fetch_url`/`tcp_open`/`port_scan` call via `interrupt()` and wait for an explicit
  approve/deny when `require_approval` is set — see Phase 0 above for the full writeup.
  This is a second, independent gate (a human, not just a regex match against the prompt),
  opt-in per run so automated evals/demos are unaffected by default.

New seeded demos: `python -m demo.run_demo_network` spins up a throwaway local HTTP server
and solves it via `fetch_url`, so the network-tool code path gets exercised in the
one-command demo runner without any real network dependency. `python -m demo.run_demo_hitl`
is the same setup but with `require_approval` on, driven interactively from the terminal —
the one to actually run in front of a judge for the Enforce Permissions story.
`demo/run_demo.py` (static-file demo) is unchanged and still the primary fallback.

Containerized runtime: `docker build -t ctf-agent .` / `docker compose up` runs
`agent/api.py` in an isolated, non-root, read-only container — see Phase 0 above for what
this does and doesn't cover.
