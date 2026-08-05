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

### Offlinea — session 3 (Opus, live Chrome browser recon, `154.57.164.72:31280`)

Re-attempted on a fresh instance using the real Chrome browser (not just the agent's
`fetch_url`), which unlocked several things prior text-only sessions couldn't see. **Still not
solved**, but the architecture is now concretely mapped, and two prior working assumptions were
corrected. Backed off before finishing because the instance degraded again (same expensive-Chrome
failure mode as before — see below).

**New, confirmed facts (beyond sessions 1–2):**
1. **Internal origin is `http://127.0.0.1:8000`.** The returned PDF's own print-to-PDF *header*
   (the URL Chrome stamps at the top of a printed page) read `127.0.0.1:8000/bartender.php`. So
   public `:31280` proxies to the app on internal `:8000`, and the server-side headless Chrome
   renders internal URLs. This is the single most useful new datapoint — it names the SSRF's
   internal target origin outright.
2. **The `url` filter is a positive ALLOWLIST, not a `file://` blocklist.** Both `file://` *and*
   `data:text/html,...` get the instant "Dont try to trick me!" render. Session 1 only knew
   `file://` was blocked; knowing `data:` is *also* rejected means the check is "must be
   http(s)://", not "must not be file". That kills the `data:`-URI rendering primitive outright.
3. **`name`/`secret` are NOT reflected on the invalid-url ("trick me") render.** Sent distinctive
   `name`/`secret` markers alongside a rejected `data:` url — the rendered PDF showed *only* "Dont
   try to trick me!", no marker. So name/secret only matter on the *valid-url* card path (which
   hangs, see below) — the reflection hypothesis can't be tested until the hang is solved first.
4. **Every `http://` url hangs (~45s+), including a CLOSED local port.** Tested `http://127.0.0.1:8000/`
   (live app) and `http://127.0.0.1:1/` (nothing listening) — both hung the request/renderer for
   45s. A closed port hanging is the key new signal: it rules out "single-thread Flask deadlock on
   SSRF-to-self" as the *sole* cause (a refused connection would fail fast), and points instead at
   the guard's **own pre-navigation step hanging on every http url** — most consistent with a
   `dnspython` forward/reverse lookup with no resolver reachable in the offline container. "Offline"
   is looking less like flavor and more like the literal mechanism: the DNS-based SSRF guard can't
   complete a lookup, so nothing downstream ever runs.

**Refined intended-solve hypothesis:** the guard resolves the url host (dnspython) to enforce a
private-IP blocklist, and that lookup hangs offline. The intended bypass is probably a url that
(a) passes the http(s) allowlist, (b) sidesteps the hanging DNS step — e.g. hostname `localhost`
(resolved via `/etc/hosts`, no network), or a specific IP-literal form the guard special-cases —
and (c) points Chrome at an internal resource serving the flag. The `secret`→JWT (`pyjwt`) angle
is still completely unexplained and may be a second required stage. **Next probe to run FIRST on a
fresh instance:** `url=http://localhost:8000/` (hosts-file resolution may not hang where IP
literals did), read the rendered PDF via the fetch-blob→iframe→screenshot trick below.

**Reusable technique unlocked this session:** to read a returned PDF *visually* instead of
hand-decoding FlateDecode/CMap streams — `fetch('/bartender.php?...')` → `res.blob()` →
`URL.createObjectURL(blob)` → inject a full-viewport `<iframe src=bloburl>` → screenshot. Chrome's
native PDF viewer renders it and its print-header even leaks the internal source URL (that's how
fact #1 was found). Much faster and more reliable than the manual PDF-text decoder in
[[pdf-generator-ssrf-selenium]]; use that decoder only as a fallback.

**Degradation, again:** after two 45s http hangs, even the plain homepage started failing to load
and cheap same-origin GETs stopped completing — identical to session 1's degradation. Confirms the
"recognize degradation and back off" rule is not optional for this target; a fresh instance per
attempt, and a strict budget of http-triggering calls (each one risks a 45s stall), is mandatory.

### Offlinea — session 4 (Opus, fresh instance `154.57.164.69:32240`)

Retested on a genuinely fresh instance to remove session-3's degradation confound. **Biggest
finding of all four sessions: the hang is PATH-specific on the internal target, not a blanket
http/DNS block.**

- `url=http://localhost:8000/` → returned **fast** (no hang). `localhost` (hosts-file, no network
  DNS) behaves differently from the IP literals that hung in session 3 — OR the app special-cases
  the internal-root URL (possibly a 302 back to `/` loop-guard; the tab landed on `/` showing the
  live homepage, so this may not have been a real PDF render — unresolved, see caveat).
- `url=http://localhost:8000/flag` → **hung 45s.** Same host, different path, opposite result.

**Why this matters:** a blanket "the SSRF guard's DNS step hangs on all http" theory (session 3's
best guess) is now **wrong** — a same-host request to `/` did not hang. The hang is specific to
`/flag`. Leading hypotheses for a path-specific hang:
1. `/flag` is auth-gated and, without the right credential, the internal render enters a
   redirect loop / blocks — which finally gives `secret`+`pyjwt` a concrete role: the intended
   path is likely *authorize the internal Chrome's request to `/flag`* via a JWT the `secret`
   field controls (forge/inject a token, or set a cookie Chrome carries to `/flag`).
2. `/flag` renders HTML that pulls a sub-resource which never loads (e.g. an external `<img>`/
   `<script>` in an offline container), so print-to-PDF waits forever.
3. Single-thread Flask deadlock on any *real* internal render, with `localhost:8000/` only
   appearing fast because it was redirected/short-circuited rather than actually rendered.

**Caveat / unresolved:** could not confirm whether `localhost:8000/` produced a real PDF or a
redirect — the follow-up fetch to inspect its exact status/content-type hung because the instance
had already degraded from the `/flag` stall. This is the first thing to nail down next time.

**Next attempt (fresh instance), in order, hard budget ~3 http calls:**
1. `fetch` (not navigate) `url=http://localhost:8000/` and read status/content-type/size ONLY
   (no heavy iframe render) — is it `application/pdf` (real render) or a `3xx` redirect?
2. Understand `secret`: submit a distinctive `secret` and inspect whether bartender.php sets a
   cookie or returns/embeds a JWT anywhere; test `alg:none` / secret-as-HS256-key on any token found.
3. Only then retry `/flag` *with* whatever auth mechanism secret provides.

### Offlinea — session 5 (Opus, fresh instance `154.57.164.72:31383`)

Answered session 4's caveat and found the loop-guard, but hit the same degradation wall.

- **`url=http://localhost:8000/...` → 302 redirect to `/` (the homepage), NOT a PDF render.**
  Confirmed for both `/` and `/images/bar.png`: after navigating to `/bartender.php?url=...`, the
  browser ends up on the live homepage at `/` (verified via `get_page_text` — the interactive form
  is present, not a PDF viewer). So the app has an explicit **loop-guard: SSRF pointed at its own
  origin (`127.0.0.1:8000`) is bounced to `/`.**
- Combined with external `http://` hanging (offline, no egress), this means the `url` parameter
  has **no usable SSRF target by design** — self is redirected, external hangs. The `url` SSRF
  angle that sessions 1–4 chased is very likely a **deliberate dead end**.
- **The homepage pulls an EXTERNAL Google Font** (`fonts.googleapis.com/css2?family=Press+Start+2P`).
  In an offline container the server-side Chrome would stall loading it — a plausible *additional*
  contributor to render hangs whenever a rendered page includes that font.
- `/flag` still hangs (vs `/` and `/images` redirecting) — unresolved why it differs from other
  localhost paths; possibly its handler blocks (self-deadlock on the pre-check `requests.get`, or
  it waits on the external font/another resource).

**Reframed conclusion — the likely intended bug is HTML injection via `name` (or `secret`) into
the rendered CARD, reaching `file:///flag` at the card's own origin, NOT url SSRF.** The blocker
is a catch-22: the full card (which would reflect `name`) only renders for a *valid* url, and no
valid url renders (self→redirect, external→hang). The untested escape: a url that passes the
http(s) allowlist but **fails fast** (e.g. `http://localhost:1/` or `http://127.0.0.1:1/`, a
refused port) so the card's embedded `url` resource errors instantly and the card renders *with
`name` reflected* — then `name=<iframe src="file:///flag.txt">` reads the flag if headless Chrome
runs with relaxed file access. Session 3 tried `127.0.0.1:1` but on an already-degraded instance
(hung); must retry on a fresh one. **This is the #1 thing to try next, on a fresh instance:**
`url=http://127.0.0.1:1/` + `name=REFLECTTEST<b>X</b>` — first just confirm whether `name` renders
into the card at all, before adding the file:// payload.

**Strategic note:** black-box iteration is extremely slow here (each instance dies after ~2–3
render calls). This is an HTB challenge with a downloadable source bundle (the user already had its
`requirements.txt`). **Getting `app.py`/the Flask source would collapse all remaining ambiguity
instantly** — the exact filter, the loop-guard/redirect logic, how `/flag` is gated, and how
`secret`+`pyjwt` are used. Strongly prefer that over more blind probing.

### Offlinea — session 6 (SOURCE OBTAINED — fully reverse-engineered)

User provided the source bundle (`HTB Challnges/web_offlinea/`). **Full intended solution now
documented in `vault/techniques/web/offlinea-full-solve.md`.** Summary: SSRF (via the
headless-Chrome `/generate` renderer) into the localhost-only Flask backend (`:5000`), past a
PHP private-IP filter + a Flask DNS-TTL≥40 check + a `check_equiv` anti-redirect guard — intended
bypass is **DNS rebinding** (multi-A-record, TTL≥40; possible no-infra shortcut via IPv4-mapped
IPv6 `[::ffff:7f00:1]` if it survives `check_equiv`). Then **Python `str.format()` injection** in
`/logs` (`{logify.__globals__[app].config[SECRET_KEY]}`) to leak the random JWT key, **forge an
HS256 `{"is_admin":true}` token**, and read the flag from `/bartender` (the flag is a `secrets` DB
row, `name='oldest_user_of_bartender'`).

**Corrections to earlier black-box theories (all wrong):** the `http://` "hangs" were NOT a DNS
guard — they were Selenium's `set_page_load_timeout(40)` firing on unreachable hosts (offline = no
HTTP egress; DNS via 8.8.8.8 works). "localhost redirects to /" was PHP's private-range block →
`header('location: /pdfs/no_way.pdf')`. There is no special `/flag` route; the flag is in SQLite,
gated by the forgeable JWT. Lesson reinforced: **get the source before theorizing** — 5 black-box
sessions produced a plausible-but-wrong model that source corrected in minutes.

## Real picoCTF target — "Old Session" (Web Exploitation, Easy), no flag — real bug found and fixed

First actual picoCTF run through the full agent loop (`agent/api.py`'s `/solve`, the same path
`dashboard/`'s "Run Agent" button hits) — the eval Rashid's `TEAM_TASKS.md` brief calls for,
previously only done against TryHackMe/HackTheBox stand-ins since no picoCTF instance had been
spun up yet. User opened a live picoCTF instance (`dolphin-cove.picoctf.net:56243`, ~7 minute
timer) and handed the exact challenge prompt + hints; the agent was run against it directly, not
solved by hand first.

| Field | Detail |
|---|---|
| Challenge | picoCTF "Old Session" — a Flask login app ("The New Twitter") whose session cookie allegedly never expires; hints point at the browser's cookie storage |
| Category | web |
| Steps | 15 (hit `MAX_STEPS`) |
| Tool calls | 9 (`dir_enum` x1, `fetch_url` x6, `search_vault` x1, `search_skills` x1) |
| Flag | **None** |

**What happened:** `dir_enum` and a couple of `fetch_url` GETs correctly found `/login` and
`/register` and confirmed a Werkzeug/Flask backend. The agent tried default creds
(`admin`/`admin`) on `/login`, then tried registering a fresh account on `/register` — reasonable
next steps. **Every one of those POSTs failed with `400 Bad Request`**, not because the attack
was wrong, but because `gemini-3.5-flash-lite` sent the `Content-Type` header key wrapped in
literal single quotes — `{"'Content-Type'": "application/x-www-form-urlencoded"}` instead of
`{"Content-Type": "..."}`. Flask never recognized the mangled key, so `request.form` came back
empty and Werkzeug auto-400'd on the missing form fields. The agent burned the rest of its step
budget retrying variations of the same broken header shape and querying `search_vault`/
`search_skills` for "flask"/"cookie" (neither surfaced the vault's own most relevant note,
`predictable-session-id-timestamp-hash.md` from the HTB "Desires" solve — a retrieval-ranking
gap worth another look, not chased further this session) before hitting `MAX_STEPS`. It never
actually reached the point of inspecting the session cookie's contents, so the intended
vulnerability itself was never tested.

**Real bug found and fixed, not just observed:** this is a *third*, distinct pattern of
`gemini-3.5-flash-lite` mangling `fetch_url`'s `headers` dict keys — CLAUDE.md already documents
underscore-for-hyphen substitution and splitting `Content-Type: application/json` at the wrong
colon, both "fixed" via a docstring warning alone. This run is direct evidence a docstring
warning doesn't reliably prevent the underlying quirk. Fixed properly this time:
`agent/tools/fetch_url.py` now strips stray surrounding quote characters from header keys
server-side (`_clean_header_key()`) before the request ever goes out, rather than trusting the
model to format them correctly. Covered by a new case in `evals/test_tools_smoke.py` (a local
server that echoes back the `Content-Type` it actually received, given the exact quoted-key
shape observed here) — passes.

**Not yet re-run against a fresh instance** — the original 7-minute timer expired during this
investigation, and hammering a second live instance back-to-back wasn't worth it once the root
cause was clear and fixable offline. Worth a retry once a new instance is spun up, now that the
header bug is fixed; if it still doesn't land, the cookie-inspection step itself needs a proper
try (the agent never got that far in this run).

### Attempt 2 — fresh instance, flag found and correctly identified by the model

Fresh instance spun up (`dolphin-cove.picoctf.net:49638`), same prompt re-run through
`/solve`. **Result: flag found (`picoCTF{s3t_s3ss10n_3xp1rat10n5_51c526ab}`)** — but the API
still reported `flag: null`, exposing a second, more serious bug (below). 12 steps, 8 tool
calls.

**The `fetch_url` header fix worked in production**, and immediately surfaced a *new*,
previously-unseen variant of the same underlying quirk in the same run — the model tried
`{"contentType": "application/x-www-form-urlencoded"}` (no hyphen at all, camelCase) first,
which still 400'd since it's not a header-key-quoting issue the fix covers, then self-corrected
to the quoted-key shape from Attempt 1 (`{"'Content-Type'": "..."}`) — which `_clean_header_key`
now sanitizes, and the request went through with a real `200 OK`. Registration and login both
succeeded from there.

**The real vulnerability, found and exploited correctly:** after logging in, the agent hit
`/sessions` and found the endpoint leaks *every* active session in the server's session store,
not just the caller's own — including one belonging to `{'_permanent': True, 'key': 'admin'}`.
It swapped its own `session` cookie for the admin one, re-requested `/`, and correctly read the
flag out of the admin-authenticated response. This is a real account-takeover technique (session
ID enumeration via an endpoint that shouldn't expose other users' identifiers at all) worth a
vault technique note alongside the existing `predictable-session-id-timestamp-hash.md` and
`cookie-trust-auth-bypass.md` from the HTB "Desires" solve, for whenever there's time to add it.

**Second real bug found: `FLAG_PATTERN` didn't recognize picoCTF's own flag format.** The model
correctly extracted `picoCTF{s3t_s3ss10n_3xp1rat10n5_51c526ab}` and even called
`find_flag_pattern` on it to confirm — which returned `"No flag pattern found."` The old pattern
(`\b(?:flag|ctf|htb)\{...\}`) needs a word boundary immediately before `ctf`, but `pico` sits
directly against `CTF` with no boundary in between, so a bare `ctf` alternative can never match
inside `picoCTF{`. Since `agent/graph.py`'s flag-exit/extraction logic imports this exact
constant, the bug wasn't just cosmetic in one tool — it silently blocked the whole harness from
ever recognizing a flag in picoCTF's own native format, the platform this eval pass exists to
validate against. **Fixed**: added `picoctf` as an explicit alternative in `FLAG_PATTERN`
(`agent/tools/find_flag_pattern.py`), covered by a new smoke-test case reproducing this exact
flag string.

**Read as**: this was a real solve — the agent found the actual vulnerability and the actual
flag unassisted — that the harness itself failed to surface, not an agent reasoning failure.
Worth a third attempt on a fresh instance now that both bugs are fixed, to confirm the API
reports the flag correctly end-to-end rather than just proving it offline via the smoke test.

## Real picoCTF target — "Cookie Monster Secret Recipe" (Web Exploitation, Easy) — flag captured, and a real fabrication bug found + fixed along the way

Run through the dashboard (`require_approval=True`, HITL on) against a live instance at
`verbal-sleep.picoctf.net`. Two attempts, back to back — the first surfaced a serious, previously
unknown agent-safety bug; the second, after the fix, produced a clean real solve.

**Attempt 1 (`:52321`) — target was already dead (closed/filtered port), and the agent fabricated a
flag instead of saying so.** Both `fetch_url` calls failed to connect. Rather than reporting the
target unreachable, the model called `web_search`, found two independent public writeups of this
same challenge, and confidently returned `picoCTF{c00k1e_m0nster_l0ves_c00kies_6E81FC1E}` as the
answer — formatted exactly like a real result, with no hedging. This flag was never read from the
actual target and was almost certainly wrong: the two writeups found showed *different* flag
suffixes (`...6E81FC1E` vs `...73110ED1`) for nominally the same challenge, proving picoCTF
randomizes the flag per deployment. Submitting this on stage would have meant confidently handing
judges a wrong answer instead of an honest "couldn't reach it."

**Root cause**: the existing `_UNTRUSTED_DATA_NOTICE` system-prompt guardrail (`agent/graph.py`)
said "never state a flag... that isn't verbatim present in a tool result from THIS run" — but a
flag string copied out of a `web_search` hit *is* technically "verbatim present in a tool result
from this run," so the wording didn't actually block it. Separately, `observe()`'s automatic
flag-pattern detector already excludes `search_vault`/`search_skills`/`web_search` results via
`_REFERENCE_ONLY_TOOLS` (added after an earlier, different incident — see the `observe()` tests in
`test_tools_smoke.py`) — but that only stops the *auto-detector*, not the model's own free-text
final answer from doing the same thing.

**Fixed**: extended `_UNTRUSTED_DATA_NOTICE` to explicitly state that a flag is only valid if it
came from a *live-target* tool this run (`fetch_url`, `dir_enum`, `tcp_open`/`tcp_send`,
`port_scan`) actually reaching the challenge's own host — `search_vault`/`search_skills`/
`web_search` are reference-only and never a valid flag source, even when they return an
exact-looking `flag{...}`/`picoCTF{...}` string — and that if every live-target call fails, the
model must say the target is unreachable rather than substitute a searched-up answer. Covered by a
new regression test in `evals/test_tools_smoke.py` (`build_system_prompt` fabrication-guardrail
check) so this can't silently regress.

**Verified the fix directly**, re-running the exact same dead target (`:52321`) post-patch: the
agent tried `fetch_url`, `dir_enum`, and `port_scan` (all confirming the port closed/filtered),
called no `web_search`, and returned `flag: None` with the honest final answer "the target is
unreachable and no valid flag can be retrieved."

**Attempt 2 (`:53457`, fresh instance) — real solve, no web_search used.** Confirmed via
`evals/run_log.jsonl`: `fetch_url` GET `/` → nothing; `dir_enum` found `/login.php`; `fetch_url` GET
`/login.php` → a login form; `fetch_url` POST `username=admin&password=admin` → server replied
"Access Denied... Me just need cookies!" and set `Set-Cookie: secret_recipe=<base64>`;
`identify_and_decode` on that cookie value decoded to `picoCTF{c00k1e_m0nster_l0ves_c00kies_78B4C390}`.
Every step traced back to a real tool result against the live target — the fabrication guardrail
had every opportunity to reach for `web_search` when the guessed login failed, and correctly didn't.

## Real picoCTF target — "Unminify" (Web Exploitation, Easy) — flag captured in a single step

Run through the dashboard (`require_approval=True`) against `titan.picoctf.net:51574`. Verified clean
via `evals/run_log.jsonl`: exactly one tool call all run, `fetch_url` on the target root — no
`web_search`, no other tool. The flag (`picoCTF{pr3tty_c0d3_51d374f0}`) is genuinely present verbatim
in the minified HTML `fetch_url` returned, sitting in a `<p class="picoCTF{...}">` attribute — the
challenge's actual intended solve (read the minified page source) rather than anything requiring
un-minification tooling, since the flag isn't obscured by the minification at all, just easy to miss
scrolling past a wall of squished markup. 1 step, 1 tool call, no ambiguity — the simplest real solve
so far, and another clean confirmation the fabrication guardrail isn't over-triggering on runs where
`web_search` was never actually needed.

## Real picoCTF target — "IntroToBurp" (Web Exploitation) — agent solved it on the second attempt, root cause was a stateless fetch_url

**Attempt 1 (failed, human had to finish it by hand)** — logged in `evals/solved_challenges.md`
and `CLAUDE.md`'s session-update log. Two separate agent runs against
`titan.picoctf.net:61209` both failed to reach the flag on their own: the first never even
reached `/dashboard` (wrong path in the human's prompt); the second reached the right path but
kept re-registering from scratch, because several `GET /` calls in the transcript carried no
`Cookie` header at all — `fetch_url` was fully stateless, so the model had to manually copy the
`Set-Cookie` value onto every single later call, and reliably forgot to on plain navigation
requests. Confirmed directly from that transcript: steps 4, 7, 10, 13, 16 (all bare `GET /`) had
no `headers` in their tool args, while the POST calls right next to them did — each cookie-less
`GET /` handed back a fresh session + CSRF token, restarting the registration flow. The real
flag (`picoCTF{#0TP_Bypvss_SuCc3$S_3e3ddc76}`) was found by a human running `curl` by hand with a
real cookie jar, outside the agent entirely.

**Root cause fixed**: `fetch_url` gained an optional `session_id` param (`agent/tools/fetch_url.py`)
— a `requests.Session`-backed cookie jar, keyed by whatever string the model passes, that
auto-persists `Set-Cookie` values across every call sharing that id (mirroring `tcp_session.py`'s
`session_id` pattern: capped concurrent sessions, absolute lifetime generous enough to survive a
paused HITL approval wait, closed on every graph exit path). This removes the failure mode
entirely rather than relying on prompting to fix it — the model no longer has to remember to
attach a `Cookie` header on calls that don't look session-relevant to it.

**Attempt 2 (`:61209`, same instance, post-fix) — agent solved it end-to-end, 6 steps, no human
intervention.** Prompted to pass one `session_id` ("introtoburp") on every `fetch_url` call in
the flow. Trace: `GET /` (session created) → `POST /` registering `testuser123` (CSRF token from
the same session's page) → `POST /dashboard` with `otp=1234` (wrong-but-present value, rejected)
→ `POST /dashboard` with `not_otp=1234` (the `otp` field entirely absent, just a differently-named
field in its place) → server responded "Welcome, testuser123 you sucessfully bypassed the OTP
request" with the flag inline. Same underlying bug as the manual solve (a missing `otp` field is
treated as a pass, not a rejection) but reached via a slightly different variant — a wrong field
name rather than a truly empty body — confirming the vulnerability is "no field named `otp`
present," not specifically "an empty POST body." Flag confirmed identical to the one found by
hand in attempt 1: `picoCTF{#0TP_Bypvss_SuCc3$S_3e3ddc76}`.

Also verified: 4 new regression tests added to `evals/test_tools_smoke.py` covering
`fetch_url`'s `session_id` behavior — cookie persistence across calls, a session_id-less call
staying fully stateless (no bleed-over), the concurrent-session cap, and lifetime expiry
dropping a stale cookie jar. Full smoke suite passes.

## Real picoCTF target — "Bookmarklet" (Web Exploitation) — agent fabricated a flag, and the dashboard displayed it uncritically; both root causes fixed, not yet re-verified end-to-end

**Not a solve — a caught fabrication, on two independent layers.** Target
`titan.picoctf.net:59998`, a page that hands the flag to the browser pre-encrypted, plus a JS
"bookmarklet" that decrypts it: `decryptedFlag[i] = (encryptedFlag.charCodeAt(i) -
key.charCodeAt(i % key.length) + 256) % 256`, key `"picoctf"`. `identify_and_decode` doesn't
cover this shape (not base64/hex/rot13), and the agent has no code-execution tool, so the model
tried to hand-simulate the byte arithmetic character-by-character in its own reasoning text. It
got the first 8 characters right (`picoCTF{`), visibly lost track partway through ("Wait, let's
carefully check the characters..." repeated several times, an abandoned Python snippet it never
actually ran), and then stated a final answer — `picoCTF{b00karn3l3ts_are_rocck_50882ef9}` —
hedged with "(or similar instance-specific flag)". **Confirmed fabricated**: re-fetched and
decoded the real page in one clean Python pass (no manual transcription) —
`picoCTF{p@g3_turn3r_cebccdfe}`, nothing like what the model stated. Along the way, manually
copy-pasting the ciphertext string through an intermediate shell/terminal step corrupted it too
(a `UnicodeEncodeError` on the very first attempt, then silently wrong output on the second) —
direct confirmation that hand-transcribing this string through any extra text layer is fragile
independent of which model or human is doing it, not a one-off model quirk.

**Root cause #1 (backend): no tool covered this cipher shape, so the model resorted to unreliable
manual arithmetic instead of a real computation.** Fixed with a new
`agent/tools/keyed_decode.py`: `keyed_byte_decode(text, key, mode)` for a repeating-key
subtract/add/xor cipher when the ciphertext is already trusted/local, and
`fetch_and_decode_cipher(url, key, pattern, mode)` — fetches the page, extracts the ciphertext
via a server-side regex, and decodes it in the same call, so the exact (often non-ASCII) bytes
never pass through the model's own text generation at all, closing the transcription-corruption
path directly rather than just telling the model to be more careful. Both wired into
`agent/graph.py` (`fetch_and_decode_cipher` is live-network: added to `_NETWORK_TOOL_HOST_ARG` so
it gets the same host-allowlist/HITL gating as `fetch_url`). `_UNTRUSTED_DATA_NOTICE` (the system
prompt's anti-hallucination guardrail) gained an explicit rule against hand-computing decodes or
retyping non-ASCII ciphertext between tool calls, and against offering a hedged "best guess" as
if it were a confirmed answer. 4 new regression tests in `evals/test_tools_smoke.py`
(`keyed_byte_decode` round-trip + bad-mode error, `fetch_and_decode_cipher` extract-and-decode +
no-match error against a local server) — full suite passes.

**Root cause #2 (frontend, more severe — undermines the guardrail work for every challenge, not
just this one): the dashboard's flag box never actually checked the backend's verification.**
`dashboard/app/page.tsx` populated the 🚩 flag box by running its own regex
(`/\b(?:flag|ctf|htb|picoctf)\{[^{}]{1,300}\}/i`) over the *entire* assistant message text,
including the model's free-text reasoning — completely independent of `agent/graph.py`'s
`observe()` node, which is the actual source of truth (`state["flag"]` is only ever set from a
real ToolMessage match, never the model's prose). On this run, `observe()` correctly never set a
flag — the transcript has no `Flag: ...` line from `route.ts` — but the dashboard's own regex
still found the model's fabricated string sitting in its final answer and displayed it as if
confirmed. Fixed: `dashboard/app/api/agent/route.ts` now writes the backend's verified
`result.flag` (when truthy) into a dedicated `data-flag` UI message part, the same pattern
already used for `data-approval`; `page.tsx` now reads *that* instead of regexing prose. Verified
with `npx tsc --noEmit` and a full `npm run build` — both clean.

**Not yet done**: re-run the actual agent against this challenge (or a fresh instance — the
flag is very likely per-instance/per-session, same as every other picoCTF target here) with both
fixes in place, to confirm `fetch_and_decode_cipher` actually gets used correctly and produces
the real flag rather than just verifying it no longer fabricates a wrong one. Log the outcome
here (success or otherwise) once that run happens.

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
