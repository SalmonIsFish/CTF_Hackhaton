# Solved Challenges — Quick Index

One row per captured flag. Full narrative (agent trace, bugs found, root cause) stays in
`practice_runs.md` or `CLAUDE.md`'s session-update log — this file is just the fast-scan index,
not a replacement for either.

| Date | Platform | Challenge | Category | Flag | Technique | Full write-up |
|---|---|---|---|---|---|---|
| 2026-08-05 | picoCTF | IntroToBurp | web (missing-field validation bypass) | `picoCTF{#0TP_Bypvss_SuCc3$S_3e3ddc76}` | Register via CSRF-protected form, then POST to `/dashboard`'s 2FA form with a completely empty body (no `otp` field at all) — server treats a missing field as success instead of rejecting it | This session — **agent's own runs failed twice** (first run never reached `/dashboard` at all due to a wrong path in the human's prompt; second run reached the right path but kept re-registering from scratch because several `GET /` calls didn't carry the session cookie forward, resetting progress each time — worth a closer look). Real flag found via direct `curl` with a proper cookie jar, run by hand outside the agent. Confirmed accepted on picoCTF |
| 2026-08-05 | picoCTF | WebDecode | web (encoded data in included file) | `picoCTF{web_succ3ssfully_d3c0ded_f6f6b78a}` | Web inspector → found an encoded string in `about.html` (a file included by the page, not the page itself) → decoded via `identify_and_decode` | This session (dashboard, 6 steps, no `web_search` used — verified grounded in a real tool result, not the flag-hallucination pattern below) |
| 2026-08-05 | picoCTF | head-dump | web (Node.js heap-dump leak) | `picoCTF{Pat!3nt_15_Th3_K3y_8df117c1}` | Swagger UI exposed an undocumented `/heapdump` endpoint leaking a full Node heap snapshot; flag was buried past `fetch_url`'s 8 KB cap | This session — **agent's own run got this wrong first** (fabricated a different, plausible-looking flag from memorized training data on a public writeup instead of admitting the response was truncated); real flag found via direct `curl`+`grep` against the live target, bypassing the cap. Root cause fixed same session: `fetch_url` gained a `search_pattern` mode (server-side regex search over up to 20 MB) plus a stronger anti-hallucination system-prompt rule — see `agent/tools/fetch_url.py`, commit `2a1e004` |
| 2026-08-05 | picoCTF | n0s4n1ty | web (file upload → RCE) | `picoCTF{wh47_c4n_u_d0_wPHP_56060bd8}` | Unsanitized PHP upload → webshell → passwordless `sudo cat /root/flag.txt` | This session (dashboard, HITL approve/deny) |
| 2026-08-05 | picoCTF | Cookie Monster Secret Recipe | web (secret stored in a cookie) | `picoCTF{c00k1e_m0nster_l0ves_c00kies_78B4C390}` | POST'd guessed creds to `/login.php`; login was refused, but the response `Set-Cookie`'d a `secret_recipe` value that base64-decoded straight to the flag | `evals/practice_runs.md` → "Cookie Monster Secret Recipe" (also the run where a dead first instance exposed a real flag-fabrication bug in the agent, fixed same session — see write-up) |
| 2026-08-05 | picoCTF | Unminify | web (flag hidden in minified HTML) | `picoCTF{pr3tty_c0d3_51d374f0}` | Flag sat verbatim in a `class` attribute inside the minified page source, found via a single `fetch_url` GET — no unminify tooling actually needed | `evals/practice_runs.md` → "Unminify" |
| 2026-08-04 | picoCTF | Old Session | web (session mgmt) | `picoCTF{s3t_s3ss10n_3xp1rat10n5_51c526ab}` | `/sessions` endpoint leaked every active session; swapped own cookie for an admin session | `evals/practice_runs.md` → "Old Session", Attempt 2 |
| 2026-08-04 | HackTheBox | Space Explorer (formerly logged as "Cosmic Explorer" — see Naming note below, now resolved) | web (JSON parsing) | `HTB{C0SM1C-BYP4SS}` | JSON parser key-casing differential: duplicate `action` keys in different cases, gateway and backend disagreed on which one wins | `vault/techniques/web/json-parser-key-casing-differential.md`; `CLAUDE.md` 2026-08-03/04 session (stuck, as "Cosmic Explorer") and 2026-08-04 session (solved, as "Space Explorer") |
| — | HackTheBox | Desires | web (Go/Fiber + Node SSO) | `HTB{S0m3tIm3s_Its_J4usT_A_B!G_M3ss}` | Session middleware trusted a client-supplied `username` cookie without checking it against the real session; timestamp-seeded session IDs made forgery easy | `evals/practice_runs.md` → "Desires" |

## Not yet solved (for reference, not a full log — see source docs for detail)

| Platform | Challenge | Status | Detail |
|---|---|---|---|
| HackTheBox | SecNotes | Stuck — confirmed airtight | `CLAUDE.md`, 2026-08-03/04 session |
| HackTheBox | Offlinea | In progress, source obtained | `evals/practice_runs.md` → "Offlinea" |

## Naming note (resolved)

"Space Explorer" and "Cosmic Explorer" are the **same HTB target**, not two separate boxes —
confirmed, not just suspected: both `CLAUDE.md` session write-ups describe the identical
`POST /execute` endpoint taking the identical `{"action": "getcosmic"}` / `{"action":
"getSecureCode"}` bodies, and the captured flag (`HTB{C0SM1C-BYP4SS}`) itself contains "COSMIC."
The 2026-08-03/04 session ("Cosmic Explorer") tried 5 hypotheses and got stuck because none of
them was the actual bug — duplicate/differently-cased JSON keys was never among them. The
2026-08-04 session ("Space Explorer") found that exact technique and captured the flag. Removed
the stale duplicate "stuck" row from the table above accordingly; this is one solved challenge; a
prior write-up name inconsistency, not two challenges.
