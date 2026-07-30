# Next Steps

> This is the TODO list — what to actually do next, in priority order. `CLAUDE.md` is the
> technical reference (what's built, why, how it works); keep that for "how does X work,"
> keep this one for "what's left." Update this file as things get done or new gaps show up —
> don't let it drift the way `CLAUDE.md`'s old inline "Not yet done" section did.

## Right now — highest priority

1. **Check in with Rashid, Hasif, and Farhan.** As of this handoff, none have started their
   piece. `TEAM_TASKS.md` is freshly updated to match the actual current state of the agent
   (tools, skill packs, the demo, the API bridge) — share it, confirm they've read it, answer
   questions, get a rough sense of timeline against 6 Aug 2026.
2. **Get the organizers' answers** on: network/internet access during competition,
   presentation vs. flag-only scoring, confirmed categories, autonomy requirements,
   environment/VM provisioning, team-role rules, submission format. The **autonomy** answer
   specifically matters — see "Architecture note" below.

## Rashid — Agent Tools & CTF Category Strategy

- Pick 2–3 CTF categories with the team (Web + Crypto + Forensics/Misc is the working
  assumption from earlier planning — not confirmed).
- `identify_and_decode` and `find_flag_pattern` are already built — don't redo them. Build
  whatever connection tool the chosen categories still need (`fetch_page` for web,
  `extract_metadata` for forensics).
- **Validate against real picoCTF challenges.** The 14 vetted skill packs give the agent
  technique knowledge, but nobody has confirmed yet that this actually converts into solved
  challenges — pull 5–8 beginner picoCTF challenges, run them through the actual agent loop
  (not just the tool in isolation), log results in `evals/practice_runs.md`.

## Hasif — Dashboard

- Hasn't started yet.
- The API bridge is ready — `agent/api.py` (`uvicorn agent.api:app --reload --port 8000`).
  `POST /solve` and `POST /solve/stream` are both live and tested; see `TEAM_TASKS.md` for
  the exact contract. No more waiting on "once the agent's ready."

## Farhan — Knowledge Base

- Real vault content not yet in `vault/` — only the placeholder `README.md` and test-fixture
  `Web_Placeholder.md` exist.
- Worth waiting on Rashid's category decision before writing the category notes, so the
  effort isn't spent on categories the team doesn't end up attempting.

## Lower priority / nice-to-have

- **Multi-API-key rotation/fallback** across teammates' keys — discussed as competition-day
  insurance, not built. Low priority given the 500 RPD headroom already found on the current
  default (`gemini-3.5-flash-lite`).
- **An actual rehearsed screen recording** of the demo. `demo/expected_transcript.txt` is a
  text placeholder, not a substitute — record a real one (narrated, ideally) before the event
  using `python -m demo.run_demo`.

## Architecture note worth remembering

The current design is a **semi-autonomous copilot**, not an autonomous scanner — no tool
reaches out to a live target on its own (no `nc`/socket tool; `fetch_page`, once built, still
needs a human to hand it a URL). An operator pastes/feeds challenge artifacts in; the agent
reasons over what it's given. This ties directly to the still-open "autonomy requirements"
question above — the answer determines how much more "reach out and touch the target"
tooling (if any) is worth building before the event.
