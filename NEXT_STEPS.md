# Next Steps

> This is the TODO list — what to actually do next, in priority order. `CLAUDE.md` is the
> technical reference (what's built, why, how it works); keep that for "how does X work,"
> keep this one for "what's left." Update this file as things get done or new gaps show up —
> don't let it drift the way `CLAUDE.md`'s old inline "Not yet done" section did.

Four phases below, in the order they actually unblock each other: validate the new
network tools before trusting them, then close the loop with organizers, then unstick the
two teammates who haven't started. A "Lower priority" and an "Explicitly out of scope"
list follow for anything not on the critical path.

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
- [ ] Pull 3–5 real *network-based CTF challenges* (picoCTF-style `nc`/web-IP challenges are
  the working assumption) and run each through the full agent loop. **Still open** —
  `scanme.nmap.org` above closed the "does this work against a real non-localhost host" risk;
  this is specifically "does it work against an actual scored/CTF-shaped service," which needs
  a human to hand over a real target — picoCTF instances are per-account/per-session, and no
  organizer challenge IP exists yet.

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

Decided against the "Cybersecurity Toolset" / "Isolate Execution" / multi-agent-swarm style
reference material the team was given, when the network tools were added:

- Docker sandboxing
- Semgrep/Ghidra/Caido subprocess wrappers
- Multi-agent triage/exploit/reporting swarm
- Canary tokens
- Secondary-evaluator LLM
- LangSmith/Logfire-style tracing pipeline

Reasoning: no infra time to build/test any of them properly this week; the network tools
are pure-Python with no shell surface, so Docker's threat model doesn't really apply here;
and the allowlist+timeout+loop-detection model already in `agent/graph.py` covers the
actual risk (hangs, runaway resource use, hitting the wrong host) at a fraction of the setup
cost. Revisit only with real spare time or evidence organizer challenges specifically need
it.

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

New seeded demo: `python -m demo.run_demo_network` — spins up a throwaway local HTTP server
and solves it via `fetch_url`, so the network-tool code path gets exercised in the
one-command demo runner without any real network dependency. `demo/run_demo.py`
(static-file demo) is unchanged and still the primary fallback.
