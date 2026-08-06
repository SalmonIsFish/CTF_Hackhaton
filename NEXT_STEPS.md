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
    thinks to guess. **Update: closed.** `agent/tools/dir_enum.py` (pure Python, `requests`,
    ~34-entry built-in wordlist of CTF-relevant paths, capped at 40 paths/20s per call) sweeps
    a base URL and reports non-404 hits, with a baseline canary probe that aborts the sweep
    outright if the target is a wildcard/catch-all responder (e.g. an SPA history-fallback
    route) rather than reporting a wordlist's worth of false positives. Wired into
    `agent/graph.py`'s `TOOLS`/`_NETWORK_TOOL_HOST_ARG`/host-allowlist path the same way as the
    other network tools, and smoke-tested in `evals/test_tools_smoke.py` (normal sweep,
    wildcard-abort, cap enforcement, unreachable-target error handling — all passing). Not yet
    re-validated against Room 404 or an equivalent real target; a natural next
    `evals/practice_runs.md` entry, out of scope for this change.
  - **HackTheBox "Space Explorer"** — reached directly over the public internet (HTB exposes
    standalone challenge spawns on a public IP, no VPN hop needed for this one). Two runs:
    blind (no flag, found the right endpoint/action names unprompted by reading page JS) and
    with the challenge's own source code pasted into the prompt (got much closer — correctly
    identified "conflicting JSON keys" as the right attack category — but missed the specific
    Go-case-insensitive-vs-Python-case-sensitive key-matching trick that actually works).
    Manually confirmed the real exploit (`HTB{REDACTED}`) to validate the root cause.
    This is a reasoning-depth limit, not a tooling gap — `fetch_url` could already express the
    winning request.
    **Update (2026-08-04): re-run through the real dashboard against a fresh instance — flag
    captured by the agent itself**, HITL-approved for both live calls. Caveat found and
    corrected afterward: the vault already contained a challenge-specific note covering this
    exact case (`vault/techniques/web/json-parser-key-casing-differential.md`, predating this
    session, evidently from the "CTF Brain" vault work), so this mainly validates that
    `search_vault`-first grounding + HITL + live tool use work correctly end-to-end — not that
    the agent generalized the technique to a fresh instance with zero prior documentation. Full
    write-up in `CLAUDE.md`'s 2026-08-04 session update.
  - Also the first real exercise of `require_approval`/`interrupt()` (Phase 0) against
    genuinely external targets, not just local demos — every live-target call on both
    platforms was gated and approved before firing.
  - **HackTheBox "SecNotes" (Web, Easy)** — a follow-up solo session, run to actually land a
    flag rather than another near-miss. Still no flag, but found and fixed two real,
    generically-useful agent bugs along the way: `fetch_url` had no way to set request
    headers (couldn't send `Content-Type: application/json`, so it silently couldn't POST to
    any `express.json()`-style backend — a very common stack, not SecNotes-specific), and
    `act()` had no error handling around tool invocation, so a single malformed tool call
    (model-hallucinated nested dict for the new `headers` param) crashed the entire graph run
    instead of surfacing as a recoverable `ToolMessage`. Both fixed and verified; full
    write-up in `evals/practice_runs.md`. The actual `/flag` access-control bypass on
    SecNotes itself is still unsolved — real recon (confirmed `/flag` is a genuinely gated
    route via its distinct 403, ruled out IP-spoofing headers/cookies/session/ObjectId
    prediction) came up empty. Left as a real open item, not chased further to avoid
    over-hammering a live scored target.

  - **HackTheBox "Desires" — flag captured**: `HTB{REDACTED}`. First
    fully solved live external target. A layered auth bypass (untrusted `username` cookie +
    predictable `sha256(timestamp)` session IDs + a Zip Slip symlink bypass on the archive
    upload) — confirmed the first two independently via source review, needed a public
    writeup (MachineEP, Medium) for the specific symlink technique after ~45 min of
    unsuccessful independent path-traversal testing. Also surfaced two more real agent bugs
    (a model-layer crash on Gemini's real 15-req/min free-tier limit, and the multi-key
    rotation feature never actually catching a real quota error) — both fixed, see
    `evals/practice_runs.md` for the full write-up and `agent/tools/upload_file.py` (new
    tool, multipart upload support fetch_url never had).
  - **TryHackMe "SecNotes" — reasoned to be unsolvable via HTTP alone**: full source review
    found the `/flag` route's loopback-only check has no reachable SSRF surface anywhere in
    the app's code (confirmed a real NoSQL injection bug in `/update`, but it only touches
    MongoDB documents — nothing in the app ever turns a DB result into an outbound request).
    Not a dead end from lack of effort — a genuinely airtight design, unlike Desires.

Owner: you, ideally with Rashid once he's back (see Phase 3).

## Phase 2 — Organizer questions: closed via working assumptions, not answers (must)

The organizer has stopped responding entirely — no replies to messages, and the team WhatsApp
group is admin-only for posting, so there's no channel left to ask through. Waiting further
isn't a plan. Closing this phase with clearly-labeled working assumptions instead, reasoned
from what's already been demonstrated or built, revisable the moment real information shows up
(a past-hackathon writeup, a last-minute organizer reply, or reality on the day itself).

- [x] Network/internet access during competition — confirmed by the organizer's own demo
  (a challenge handed out as a bare IP).
- [x] **Autonomy requirements — resolved by inference, not actually unknown.** The organizer's
  own "Next Steps: Implementation" slide required Enforce Permissions (HITL) on top of the
  framework choice already made — that's a strong, direct signal this is meant to be
  operator-assisted, not a fully hands-off autonomous solve. Already built for
  (`require_approval`/`interrupt()` in `agent/graph.py`, Phase 0 above) — no further action
  needed.
- [x] **Environment/VM provisioning — resolved by inference.** The organizer's demo showed a
  bare-IP challenge; this project has since validated both VPN-reached (TryHackMe) and
  direct-public-IP (HackTheBox) live targets work end-to-end with the existing tools
  (`fetch_url`/`tcp_session`/`port_scan` + `extract_allowed_hosts()`). Working assumption:
  expect `host:port`, sometimes behind a VPN — both are covered.
- [x] **Confirmed categories — treated as low-risk regardless of the answer.** 14 skill packs
  already span Web/Crypto/Pwn/Reverse/Forensics/Malware/OSINT/Misc/AI-ML — broad enough that
  not knowing the exact 2–3 categories in advance isn't a real blocker. Rashid's Phase 3 task
  to narrow this down is nice-to-have, not required.
- [x] **Presentation vs. flag-only scoring — RESOLVED: flag-only.** Confirmed by the user
  2026-08-05: the competition (2026-08-06) is scored on captured flags only — you just submit the
  flag, there is no demo/recording/presentation component. This supersedes the earlier "assume
  both" hedge. Acting on this: **optimize purely for flag capture.** The rehearsed-screen-recording
  item under Phase 4 is now moot (scratch it — see that item, updated). Prioritize agent hardening
  via practice runs on the likely categories (Web confirmed; Crypto/Forensics assumed), bug fixes,
  vault notes, and quota discipline. The configurable flag format (`FLAG_PREFIXES` env / per-request
  `flag_prefixes`, added 2026-08-05) is directly the win condition — set the real format the moment
  it's known on the day.
- [ ] **Team-role rules / submission format — accepted as genuinely unknowable, and genuinely
  low-risk.** Nothing in the current build depends on a specific submission mechanism — the
  dashboard surfaces the flag string directly (`final_state["flag"]`) for a human to submit
  however the organizer's platform requires. No code depends on this being answered in advance.

**Still open, real task**: if the user finds any writeups/details from a past edition of this
hackathon (or the same organizer's prior events), fold that into vault content (the "CTF Brain"
work, Phase 3's Farhan item below) and revisit the two `[ ]` items above if it contradicts
these assumptions.

## Phase 3 — Teammate sync (must)

**Update (2026-08-04): this section was stale.** Hasif's and Farhan's items below were marked
not-started at the original handoff; both are actually done, confirmed by real evidence found
this session (not just assumed) — corrected below rather than left to mislead the next reader.
Rashid's items remain genuinely open.

- [ ] **Rashid** — finalize 2–3 CTF categories now that network/web is a confirmed real
  category (Web + Crypto + Forensics/Misc was the working assumption, not confirmed).
  `identify_and_decode`, `find_flag_pattern`, `fetch_url`, and
  `tcp_open`/`tcp_send`/`tcp_close` are already built — don't redo them.
  `extract_metadata` (`agent/tools/extract_metadata.py`) is now also built and wired into
  `agent/graph.py`'s `TOOLS` list, for whenever Forensics/Misc gets confirmed — Pillow-only
  (already an installed dependency), reads EXIF tags and PNG tEXt/iTXt/zTXt info-dict entries
  (a common place a flag is hidden directly in an image's metadata rather than the pixels).
  Smoke-tested in `evals/test_tools_smoke.py` (a real PNG with a flag in a tEXt chunk, plus
  missing-file and not-an-image error paths — all return clean strings, never raise).
- [ ] **Rashid** — co-run the Phase 1 validation pass once categories are picked. First real
  picoCTF attempt done: "Old Session" (Web, Easy) via the actual agent loop, no flag, but a real
  bug found and fixed along the way — see `evals/practice_runs.md`'s picoCTF section. Still
  need 4-7 more challenges across Web/Crypto/Forensics logged the same way before this item is
  actually done.
- [x] ~~**Hasif** — start the dashboard against the already-live API bridge~~ — done. The
  dashboard has been wired to `agent/api.py`'s `/solve` since the 2026-08-03/04 session
  (`CLAUDE.md`), and this session added `require_approval` (HITL) end-to-end: a checkbox in
  `dashboard/app/page.tsx`, `dashboard/app/api/agent/route.ts` forwarding it and rendering
  Approve/Deny controls on a pending-approval turn. Verified live against a real external HTB
  target (see `CLAUDE.md`'s 2026-08-04 session update) — both approve and deny paths confirmed
  working through the actual UI, not just the API directly.
- [x] ~~**Farhan** — write real vault content~~ — done. `vault/` now holds 150+ real notes
  (`vault/CTF_Vault/` — Concepts/Categories/Tools — and `vault/techniques/{web,crypto,forensics}/`
  — specific, real-target-derived technique writeups, e.g. the JSON-key-casing note that let the
  agent re-solve HackTheBox "Space Explorer" unassisted this session), confirmed by direct
  listing, not just assumed from an old placeholder note. The original placeholder
  `vault/Web_Placeholder.md` is now stale test fixture, not representative of the vault's actual
  state — worth deleting next time someone's in there, not urgent on its own.

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
- [~] ~~An actual rehearsed screen recording of the demo~~ — **moot: scoring is flag-only, no
  presentation** (see Phase 2, resolved 2026-08-05). No recording is needed. `demo/` stays useful
  only as a quick offline regression check that the loop still works, not as a demo artifact.
- [x] ~~`web_search` tool (Tavily-backed)~~ — done. `agent/tools/web_search.py`, wired into
  `TOOLS` and the `search_vault → search_skills → web_search` grounding order in
  `build_system_prompt()`. Motivated by real friction solving Desires: the agent had no way to
  look up a specific technique/writeup itself, a human had to do it manually. Deliberately
  excluded from `_NETWORK_TOOL_HOST_ARG` (and so from the host-allowlist/HITL gate) since it
  queries the public internet, not the challenge's own target. Degrades gracefully to an
  "unavailable" message if `TAVILY_API_KEY` is unset — no existing eval/demo depends on it.
  Along the way, found and fixed a real Windows-only crash: `message.pretty_print()` (used by
  `run_interactive()` and this module's own `__main__` suite) raised `UnicodeEncodeError` and
  killed the whole process the moment a non-cp1252 character (e.g. `→`, now common across the
  vault's technique notes) appeared anywhere in the conversation — including from an
  uncontrolled source like a live target's own response. Fixed with a one-time
  `sys.stdout.reconfigure(encoding="utf-8")` at the top of `agent/graph.py`. Also updated case 5
  of the 5-case eval suite (`agent/graph.py`'s `__main__` block): it hardcoded `search_skills`
  as required, which broke the moment the vault's own new RSA content (from the CTF Brain work)
  legitimately answered the question via `search_vault` alone — the assertion now accepts
  either lookup tool, matching the documented "vault before skills" priority instead of forcing
  a specific one.

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

The agent is no longer a pure "semi-autonomous copilot" — it now has tools that reach
out to a live target on their own: `fetch_url` (`agent/tools/fetch_url.py`),
`tcp_open`/`tcp_send`/`tcp_close` (`agent/tools/tcp_session.py`, a multi-turn
`nc`/pwntools-`remote()`-style session — connect once, send/receive repeatedly, close
explicitly), `port_scan` (`agent/tools/port_scan.py`, added after the organizer's demo
showed bare-IP-no-port challenges are real — sweeps a capped candidate port list via
`socket.connect_ex()` and passively reads any banner volunteered on connect, e.g. SSH's
unprompted version string), and `dir_enum` (`agent/tools/dir_enum.py`, added after the
TryHackMe Room 404 run above showed `fetch_url` alone can't find a hidden endpoint it never
thinks to guess — sweeps a capped, built-in wordlist of CTF-relevant paths against a base URL,
aborting immediately if a baseline canary probe reveals the target is a wildcard/catch-all
responder). All four are pure Python (`requests` / stdlib `socket`) — no
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
