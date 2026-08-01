## Network Tool Practice Runs

Phase 1 of `NEXT_STEPS.md`: the network tools (`fetch_url`, `tcp_open`/`tcp_send`/`tcp_close`,
`port_scan`) had only been proven against a single trivial local server (one GET, one echo
exchange) before this. These are local stand-ins built to stress two specific gaps that
weren't exercised yet — a genuinely multi-turn TCP service, and an HTTP redirect+cookie
chain — run through the **full agent loop** (`python -m evals.practice_runs_network`), not
the tool in isolation. All three passed with `gemini-3.5-flash-lite`.

| Scenario | Tool(s) exercised | Result | Notes |
|---|---|---|---|
| Login-gated multi-turn TCP service (`Password:` prompt, then a second `flag` command) | `tcp_open`, `tcp_send` (x2), `tcp_close` | PASS | Reached `flag{multi_turn_tcp_works}` via a real open→send→send sequence, confirming `tcp_session` isn't limited to one-shot exchanges. The model made a couple of extra `tcp_open`/`tcp_close` calls before landing on the right sequence — didn't fail, just wasn't maximally efficient; worth a glance if step budget ever gets tight on a similar real service. |
| HTTP redirect (302 + `Set-Cookie`) → final response with the flag | `fetch_url` | PASS | Confirms `requests.request(..., allow_redirects=True)` follows a redirect+cookie chain within a single `fetch_url` call and returns the *final* response, not the 302 — matches a common real CTF "cookie wall before the flag" pattern. |
| Port sweep across one open (banner-emitting) port and two closed/adjacent ports | `port_scan` | PASS | Correctly reported the open port's banner (`SSH-2.0-OpenSSH_9.6p1`, a synthetic banner shaped like a real SSH version string) and the other two as `closed/filtered`. |
| Real internet target — `scanme.nmap.org` (nmap's own public scanning-practice box, ports 22/80/9929) | `port_scan` (full agent loop, `python -m evals.real_target_check`) | PASS (with a real finding) | Correctly reported all 3 known-open ports as open, both runs. **But**: SSH's version banner on port 22 was never captured, even after widening `CONNECT_TIMEOUT_SECONDS`/`BANNER_TIMEOUT_SECONDS` from 0.6s/0.8s to 1.0s/1.5s (now the shipped default) and re-running — unlike our local synthetic banner target, which always responds instantly. Real hosts/network paths don't guarantee an immediate banner the way a same-machine test server does. Port-state detection is solid; banner capture on a real target is best-effort, not guaranteed. Stopped after 2 runs out of respect for scanme.nmap.org's light-use policy — not chasing this further against their box. |
| **Real TryHackMe target** — Room 404 (`hh-room404-804573bf`), a hidden-endpoint-discovery web challenge, reached via OpenVPN (TCP, after UDP stalled with a TLS handshake timeout) | `fetch_url`, `port_scan`, `search_skills`; `require_approval=True` (HITL) | **No flag** — real target expired mid-run | First real run through `require_approval`/`interrupt()` against a genuinely external (VPN-reached) target, not just `scanme.nmap.org`. The agent explored sensibly (root, `/robots.txt`, `/static/flag.txt`, `/static/`, `/console`, a port sweep, `search_skills` for "flask") but never guessed the actual hidden path before the free-tier lab machine's hard time limit killed the connection mid-request (`WinError 10053`). Real, useful gap surfaced: `fetch_url` has no directory/wordlist enumeration — it only tries paths the model itself thinks to guess, one at a time. Not fixed this session; noted for Phase 4 if there's time. |
| **Real HackTheBox target** — "Space Explorer" challenge (Web, Very Easy, free tier), reached directly over the public internet (no VPN hop needed — HTB spawns standalone challenges on a public IP) | `tcp_open`, `fetch_url`; `require_approval=True` (HITL) | **No flag** (2 runs) | **Run 1 (blind, no source):** explored unprompted from nothing — found the real `/execute` endpoint and the correct JSON action names (`getcosmic`/`getSecureCode`) by fetching `/` and reading the page's own JavaScript. Its very first guess, `{"action": "getSecureCode"}`, was the right shape but got refused server-side. At the time this looked like it might need `fetch_url` custom-header support (no such param exists) — **that hypothesis turned out to be wrong** once the source was read; worth flagging so it's not treated as a confirmed gap. **Run 2 (challenge's own source code — a Go "Sender" proxy + Python "Receiver" — pasted directly into the prompt, same pattern as `demo/run_demo.py`'s captured-artifact style, no new tool needed):** correctly identified the right *category* of attack (conflicting/duplicate `action` keys in the JSON body, since the Go proxy and Python backend parse the same forwarded bytes independently) and tried several variants (`{"action":"getcosmic","action":"getSecureCode"}` both orders, a nested-object variant) — but never tried the one that actually works: exploiting Go's built-in *case-insensitive* JSON key matching against Python's *case-sensitive* dict lookup on the identical raw bytes (`{"action": "getSecureCode", "Action": "getcosmic"}` — Go's decoder resolves its single struct field via the last matching key regardless of case, so it forwards; Python reads the literal lowercase key and returns the flag). Manually verified this payload directly (`Invoke-WebRequest`) to confirm the actual root cause: `HTB{C0SM1C-BYP4SS}`. **Read as**: source code access measurably helps (went straight for the real vulnerable code path instead of guessing blind), but this specific bug needed a fairly deep, language-specific implementation fact the agent had no strong reason to know — a reasoning-depth limit, not a missing tool. |

Also stress-tested (offline, no server needed): `extract_allowed_hosts` (the host-allowlist
guard in `agent/graph.py`) against additional real-world phrasings (`"Target:
10.0.0.7:4000"`, `"Connect to service.chal.ctf:9999"`, `"The box is 172.16.5.20 (port
31337)"`) — all extracted correctly, no regex gap found, see `evals/test_tools_smoke.py`.

# Practice Runs — Model Comparison

Results from running the 4 `agent/graph.py` test cases (echo, echo+early-exit-on-flag,
multi-step decode, vault lookup) against different providers/models, with the
`SYSTEM_PROMPT` (vault-search nudge) in place.

| Model | Provider | Case 1 (echo) | Case 2 (flag early exit) | Case 3 (multi-step decode) | Case 4 (vault lookup) | Free-tier quota | Notes |
|---|---|---|---|---|---|---|---|
| `gemini-3.5-flash-lite` | Google | PASS | PASS | PASS | PASS | 500 requests/day | **Recommended default.** Only model to pass all 4 cases cleanly, including multi-step tool chaining. Now the `model_router.py` default for `"google"`. |
| `openai/gpt-oss-120b` | Groq | PASS | PASS | FAIL | PASS | — | Weak multi-step chaining: after decoding base64 to hex, calls `echo` redundantly instead of calling `identify_and_decode` again, then states the final flag as prose instead of via a tool call — so `observe()` never sees it in a `ToolMessage` and the flag is never captured. |
| `llama-3.3-70b-versatile` | Groq | — | — | — | — | — | **Unusable.** Reliably emits malformed tool-call syntax (`<function=search_vault{"query": "..."}</function>` instead of a proper JSON tool call), which Groq rejects outright with `400 tool_use_failed`. Reproduced twice, not transient. |

## Models ruled out — don't retry these

- **`gemini-2.5-flash`** — retired for this API key. Returns `404 NOT_FOUND`
  ("no longer available to new users") at generation time, even though it still
  appears in `client.models.list()`.
- **`gemini-2.0-flash`** — `limit: 0` free-tier entitlement on this key. Not a quota
  *exhaustion*, a quota of zero — this key was never entitled to any free requests
  for this model, so waiting won't help.
- **`gemini-flash-latest`** (resolves to `gemini-3.6-flash`) — works, but only has a
  20/day free-tier quota, which this key exhausted mid-testing. Superseded by
  `gemini-3.5-flash-lite` as the default.

## How to check available models / quota for a key

```bash
python -c "
from dotenv import load_dotenv
load_dotenv()
import os
from google import genai
client = genai.Client(api_key=os.environ['GOOGLE_API_KEY'])
for m in client.models.list():
    if 'generateContent' in (m.supported_actions or []):
        print(m.name, '|', m.display_name)
"
```

Quota limits only show up when you actually hit them (in the `429` error body), not
from the listing call above.
