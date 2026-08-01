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

## Real HackTheBox target — "SecNotes" (Web, Easy), live run

Picked to actually get a flag on stage rather than another near-miss, since the two Phase 1
external runs above (Room 404, Space Explorer) both surfaced real gaps but no flag. This run
found and fixed two real, generically-useful bugs in the agent itself, but still didn't
capture the flag.

**Bug 1 — `fetch_url` had no way to set request headers.** First attempt against SecNotes
(an Express + MongoDB note-taking app) sent exactly the right JSON body to `POST /create`
but got `400 "Invalid title or content"` every time — `requests.request(..., data=body)`
sends form-urlencoded by default, and this app's `express.json()` middleware only parses the
body when `Content-Type: application/json` is set explicitly, so the server never saw a body
at all. Manually confirmed with `curl -H "Content-Type: application/json"` (200 OK, note
created). Fixed: `fetch_url` now takes an optional `headers: dict[str, str]` param
(`agent/tools/fetch_url.py`). This isn't SecNotes-specific — any Express/`express.json()`
backend (an extremely common stack) was silently unreachable via POST before this.

**Bug 2 — a malformed tool call crashed the whole graph run.** After the fix above, the model
occasionally passed a malformed nested value for the new `headers` dict param (e.g.
`{"headers": {"Headers": {"contentType": "..."}}}`). LangChain's pydantic arg validation
raises before the tool body ever runs, and `act()` (`agent/graph.py`) had nothing catching
that — an uncaught `ValidationError` took down the entire `graph.invoke()` call, losing the
whole run. Fixed: `act()` now routes every tool invocation through a small `invoke_tool()`
wrapper that catches `Exception` broadly and returns the error as a normal `ToolMessage`
instead, so the model sees its own mistake and can retry with corrected args on the next turn
— the same "never raises" contract the tools already have for their own internal errors,
extended to cover the arg-validation layer above them. Verified: re-ran the same scenario
post-fix and the run completed its full step budget instead of crashing.

**Still no flag.** Full recon: `POST /create` (with headers now working) and `GET
/get/<id>` work as expected; `POST /update` echoes back whatever you send rather than
existing content, so it's a write-only IDOR surface, not a read one; `POST /create` validates
title/content must be plain strings, blocking NoSQL-operator injection there. `GET /flag`
exists and returns a distinct `403 {"Message":"Access denied"}` (every other unknown path is
a generic 404), confirming it's the real gated route — but none of the standard bypass
attempts worked: `X-Forwarded-For`/`X-Real-IP`/`CF-Connecting-IP`/etc. IP-spoofing headers,
`Host: localhost`, same-origin `Referer`/`Origin`, browser `User-Agent`, `?admin=true`, or
guessed cookies (`role=admin`, `isAdmin=true`, ...). No `/login`/`/register`/`/auth` route
exists and the app never sets a `Set-Cookie` anywhere, so there's no session system to log
into. Also tried a MongoDB ObjectId-prediction attack (both of our own created notes shared
the same 5-byte machine/PID segment and had counters 2 apart with nothing else creating a
note in between, suggesting a same-process seeded note) — ~12,000 read-only `GET /get/<id>`
guesses across a 10-minute/20-counter window around our first note's ID found nothing. The
model itself (`gemini-3.5-flash-lite`) also struggled with the new `headers` dict param,
repeatedly producing malformed variants across several turns instead of the correct flat
dict — a real tool-calling reliability gap worth knowing about for any future dict-typed
tool param, separate from the crash in Bug 2 above (which is now at least non-fatal).

Left open, not resolved this session: the actual `/flag` bypass technique. Candidates not yet
tried: a wider/different ObjectID search window, a proxy-level (not app-level) block, or a
technique that needs a hint neither manual recon nor the agent's `search_skills` calls
surfaced.

## Real HackTheBox target — "Desires" (Web), flag captured

Full source (Go/Fiber app + Node/Express SSO backend + Redis sessions) was provided for local
study, not just a blind IP — closer to a real CTF-with-source-access scenario than prior
targets. **Flag captured**: `HTB{S0m3tIm3s_Its_J4usT_A_B!G_M3ss}`, matching a public writeup
(MachineEP, Medium) consulted mid-session after independent analysis stalled — see below.

**Vulnerability chain** (`services/sessions.go`, `services/http.go`):
1. `SessionMiddleware` authenticates purely off the client-supplied `username` cookie — it
   looks up the *real* session file via Redis keyed on that cookie's value, but never checks
   it against the `session` cookie, so any username can be impersonated if a session file for
   it exists server-side. Found independently by source review; confirmed real via a 500 vs.
   403 status difference (no Redis entry vs. real-but-wrong-role entry).
2. `LoginHandler` computes `sessionID = sha256(current unix timestamp)` — no secret, so any
   failed login attempt (even with a wrong password, even for a nonexistent username) still
   calls `PrepareSession()` first and leaks a fully predictable session ID via the response's
   `Date` header.
3. No account can ever legitimately get `role: "admin"` (registration hardcodes `"user"`, no
   seed data, no SQLi — parameterized queries throughout) — so exploiting bug #1 requires
   *planting* a forged session file, not stealing a real admin's.
4. `UploadEnigma` extracts uploaded archives via `archiver.Unarchive` into `./files/<user>/`.
   Direct `../` path-traversal entries are blocked (verified with a direct, observable oracle:
   tried to overwrite the served `static/styles.css` across 6 traversal depths, no effect) —
   but a **symlink** entry (`type: SYMTYPE`, `linkname: /tmp/sessions`) is *not* revalidated
   the same way, so files written "through" the link land outside the sandboxed extraction
   folder. This specific bypass (independently found: no) came from the public writeup after
   ~45 min of unsuccessful independent path-traversal testing — worth having in
   `ctf-web`/`ctf-misc` skill notes for next time, since it's a generically-known archiver
   Zip Slip bypass class, not exploit-specific trivia.

**Full chain**: send a failed login as a chosen non-existent username at a known time (capture
the `Date` header, compute 3 candidate `sha256(timestamp ± 1s)` IDs) → build a tar with a
symlink to `/tmp/sessions` plus forged `{"role":"admin"}` JSON files at each candidate ID's
path → upload it as any authenticated user → hit `/user/admin` with `username=<chosen name>`
and each candidate `session` cookie until one 200s.

**Two real agent-tooling gaps found and fixed along the way, both generically useful beyond
this challenge:**
- `fetch_url` had no multipart/file-upload support at all — added a new `upload_file` tool
  (`agent/tools/upload_file.py`, base64-encoded content since tool args are text-only) since
  file-upload challenges are common and the old tool simply couldn't touch them.
- A **real 429 RESOURCE_EXHAUSTED from Gemini's free tier (15 requests/minute, separate from
  the documented 500/day)** crashed the whole run uncaught from `think()`'s `model.invoke()`
  call — same class of gap as the `act()` tool-call crash fixed against SecNotes this session,
  just at the model layer. Fixed: `think()` now catches the failure and ends the run cleanly
  (an `AIMessage` with no tool calls) instead of losing the whole process. While fixing this,
  found the multi-key rotation feature (`_RotatingChatModel` in `agent/model_router.py`) has
  **never actually worked against a real quota error**: it caught `google.genai.errors.APIError`
  directly, but `langchain-google-genai` wraps that in its own `ChatGoogleGenerativeAIError`
  before it reaches calling code, so the except clause never matched in practice — only in the
  unit test's mocks, which raised the unwrapped type. Fixed by walking the exception's
  `__cause__` chain; added a regression test (`evals/test_model_router_smoke.py`) using a stub
  that wraps the error the same way the real library does, so this can't silently regress again.

**Also found, not fixed**: `gemini-3.5-flash-lite` is **unreliable at reproducing a large
(~4000+ char) base64 blob verbatim** in a tool call argument — the first agent-driven upload
attempt got `archive/tar: invalid tar header` from the server, while the *identical* payload
worked immediately when the tool was invoked directly (bypassing the model's own
regeneration of the string). Practical implication for any future challenge needing a
sizeable binary payload delivered via a tool call: don't route it through the model's own
text generation if avoidable — have it reference a pre-staged artifact instead of retyping
raw bytes/base64. Not fixed this session since the right fix (a file-reference-based upload
path vs. inline content) needs a bit more design than the other items above.

**Process note**: independent source analysis (register/login/role logic, Zip Slip patch
verification, predictable-session-ID discovery) got most of the way there in under an hour,
but the specific symlink bypass technique was the one piece a public writeup supplied that
independent testing hadn't found yet. Worth normalizing checking for a writeup once a
challenge's *category* of bug is identified but the exact bypass isn't converging — this
isn't a shortcut past understanding the vulnerability, it's the same thing a human competitor
would do after being stuck.

# Practice Runs — Model Comparison

Results from running the 4 `agent/graph.py` test cases (echo, echo+early-exit-on-flag,
multi-step decode, vault lookup) against different providers/models, with the
`SYSTEM_PROMPT` (vault-search nudge) in place.

| Model | Provider | Case 1 (echo) | Case 2 (flag early exit) | Case 3 (multi-step decode) | Case 4 (vault lookup) | Free-tier quota | Notes |
|---|---|---|---|---|---|---|---|
| `gemini-3.5-flash-lite` | Google | PASS | PASS | PASS | PASS | 500 requests/day | **Recommended default.** Only model to pass all 4 cases cleanly, including multi-step tool chaining. Now the `model_router.py` default for `"google"`. |
| `openai/gpt-oss-120b` | Groq | PASS | PASS | FAIL | PASS | — | Weak multi-step chaining: after decoding base64 to hex, calls `echo` redundantly instead of calling `identify_and_decode` again, then states the final flag as prose instead of via a tool call — so `observe()` never sees it in a `ToolMessage` and the flag is never captured. |
| `llama-3.3-70b-versatile` | Groq | — | — | — | — | — | **Unusable.** Reliably emits malformed tool-call syntax (`<function=search_vault{"query": "..."}</function>` instead of a proper JSON tool call), which Groq rejects outright with `400 tool_use_failed`. Reproduced twice, not transient. |

## Real HackTheBox target — "Offlinea" (Web), in progress, not yet solved

Testing session for the newly-added `web_search` tool and the CTF Brain vault content, run
against a fresh live target. Two full agent runs plus manual follow-up probing. Not solved this
session, but real, generalizable findings came out of it — full technique write-ups now in
`vault/techniques/web/pdf-generator-ssrf-selenium.md` and
`vault/techniques/web/jwt-secret-and-dns-ssrf-hints.md`.

**App shape**: a "bartender" themed page (`url`, `name`, `secret` text inputs) that submits to
`GET /bartender.php?url=...&name=...&secret=...` and returns a PDF. Stack confirmed via a
provided `requirements.txt`: `flask`, `selenium`, `pyjwt`, `requests`, `dnspython` — a real
headless-Chrome-driven PDF generator (confirmed independently from the PDF's own metadata:
`Producer: Skia/PDF m143`, a real `Chrome/143.0.0.0` user-agent), not a lightweight PDF library.

**Two real agent-harness bugs found and fixed, both confirmed via this live run, not
synthetically**:
- `observe()`'s auto flag-detection regex (`agent/graph.py`) was `\w+\{[^{}]+\}` — far too
  loose. The first agent run false-matched garbage bytes inside the PDF response's raw
  (still-compressed) binary as a "flag" and ended the run at step 4 before real exploration
  happened. Root cause: this regex had silently drifted from the stricter, separate one in
  `agent/tools/find_flag_pattern.py` (`(?:flag|ctf)\{...\}`) — which itself had the opposite
  bug: it would have **missed** both real `HTB{...}` flags captured earlier this session, since
  it didn't recognize that prefix at all. Fixed both: tightened the auto-detector to
  `\b(?:flag|ctf|htb)\{[^{}]{1,300}\}` and made `graph.py` import that single pattern instead of
  keeping a second copy that can drift again.
- Confirmed (not fixed, a genuine model-behavior gap rather than a code bug): given a `web_search`
  tool, when a specific query search turns up no results, the model tends to retry with
  reworded phrasings rather than quickly concluding "no writeup exists, pivot to direct
  exploration." Burned 5 of a 15-step budget on `web_search` alone in the second run, all minor
  rephrasings of "is there a public writeup for Offlinea."

**Manual follow-up findings** (after the agent's own runs, pushing further by hand):
- `url=file:///flag.txt` gets an **instant** rejection: the app's response, once properly
  decoded (raw PDF text is FlateDecode-compressed + glyph-ID-encoded behind a custom font's
  ToUnicode CMap — see the new PDF-decoding technique note), reads **"Dont try to trick me!"**.
  This is the first confirmed case of actually reading real *rendered content* out of a PDF
  response rather than just skimming raw/corrupted bytes.
- Every plain `http://` URL tried (external, and several internal `127.0.0.1` ports) **hangs**
  rather than fast-failing, up to a 40-second tested timeout. Initially read as "no outbound
  network egress"; the later `dnspython` discovery reframes this as more likely "the SSRF
  guard's own DNS-resolution check is the slow/hanging step" — a more specific, more actionable
  hypothesis for next time (see the JWT/DNS hints note for the reasoning).
- **The target visibly degraded under repeated testing** — by the end of the session, even the
  plain homepage (instant all session) started timing out. Real headless-Chrome-per-request
  backends are expensive; stopped testing rather than continue hammering a live, likely
  resource-exhausted target. This is worth internalizing as a general rule, not just something
  that happened once: recognize target degradation and back off, the same discipline the
  harness's own loop-detection (`route_after_observe`) already enforces automatically inside
  the agent loop, but which manual probing outside the graph doesn't get for free.

**Not yet tried, the concrete plan for next attempt** (on a fresh instance, since this one may
still be degraded): test whether the `name` field is reflected unescaped into the rendered
page — if so, HTML injection there (e.g. `<iframe src="file:///flag.txt">`) could reach the same
powerful Selenium-driven renderer while completely bypassing whatever validation is specifically
written for the `url` parameter. Separately, investigate whether `secret` has any JWT-related
effect given `pyjwt` is a real dependency, not incidental.

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
