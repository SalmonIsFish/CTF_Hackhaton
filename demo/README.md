# Demo folder

One-command demo run for harness element #9 (Deploy/Demo Readiness).

## Run it

```bash
python -m demo.run_demo
```

Solves the seeded challenge in `response_headers.txt` (a captured HTTP response with a
base64-of-hex-encoded flag in a custom `X-Flag` header) end to end, printing the tool-call
trace and the result. Exit code is `0` if a flag was found, `1` otherwise — run this before
demo day, not just once while building it, so a regression shows up as a failing command
instead of a surprise on stage.

Point it at a different file to try something else:

```bash
python -m demo.run_demo path/to/other_challenge.txt
```

## Files

- `response_headers.txt` — the seeded demo artifact. Deliberately solvable with only the
  tools that already exist (`find_flag_pattern`, `identify_and_decode`) so the demo doesn't
  depend on a live target, network access, or a challenge category the team hasn't built
  tooling for yet.
- `run_demo.py` — the one-command entrypoint. Fails fast with a clear message if
  `GOOGLE_API_KEY` isn't set, instead of a confusing API error mid-run.
- `expected_transcript.txt` — a captured successful run, checked in as the **fallback if
  live tools flake on stage**. It's a text transcript, not a video — if this project gets an
  actual screen recording before the event, swap it in and reference that instead; this file
  is the placeholder until that happens.

## Still needed before the actual event

This script proves the agent *can* solve a demo challenge reliably — it doesn't replace an
actual rehearsed screen recording. Record one (a real screen capture, ideally narrated) by
running the command above and capturing it, so there's a real fallback video, not just this
text transcript, if live tools flake on stage.
