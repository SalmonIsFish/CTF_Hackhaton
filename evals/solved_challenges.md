# Solved Challenges — Quick Index

One row per captured flag. Full narrative (agent trace, bugs found, root cause) stays in
`practice_runs.md` or `CLAUDE.md`'s session-update log — this file is just the fast-scan index,
not a replacement for either.

| Date | Platform | Challenge | Category | Flag | Technique | Full write-up |
|---|---|---|---|---|---|---|
| 2026-08-05 | picoCTF | WebDecode | web (encoded data in included file) | `picoCTF{web_succ3ssfully_d3c0ded_f6f6b78a}` | Web inspector → found an encoded string in `about.html` (a file included by the page, not the page itself) → decoded via `identify_and_decode` | This session (dashboard, 6 steps, no `web_search` used — verified grounded in a real tool result, not the flag-hallucination pattern below) |
| 2026-08-05 | picoCTF | head-dump | web (Node.js heap-dump leak) | `picoCTF{Pat!3nt_15_Th3_K3y_8df117c1}` | Swagger UI exposed an undocumented `/heapdump` endpoint leaking a full Node heap snapshot; flag was buried past `fetch_url`'s 8 KB cap | This session — **agent's own run got this wrong first** (fabricated a different, plausible-looking flag from memorized training data on a public writeup instead of admitting the response was truncated); real flag found via direct `curl`+`grep` against the live target, bypassing the cap. Root cause fixed same session: `fetch_url` gained a `search_pattern` mode (server-side regex search over up to 20 MB) plus a stronger anti-hallucination system-prompt rule — see `agent/tools/fetch_url.py`, commit `2a1e004` |
| 2026-08-05 | picoCTF | n0s4n1ty | web (file upload → RCE) | `picoCTF{wh47_c4n_u_d0_wPHP_56060bd8}` | Unsanitized PHP upload → webshell → passwordless `sudo cat /root/flag.txt` | This session (dashboard, HITL approve/deny) |
| 2026-08-04 | picoCTF | Old Session | web (session mgmt) | `picoCTF{s3t_s3ss10n_3xp1rat10n5_51c526ab}` | `/sessions` endpoint leaked every active session; swapped own cookie for an admin session | `evals/practice_runs.md` → "Old Session", Attempt 2 |
| 2026-08-04 | HackTheBox | Space Explorer (aka "Cosmic Explorer" in earlier notes — name inconsistent, see below) | web (JSON parsing) | `HTB{C0SM1C-BYP4SS}` | JSON parser key-casing differential: duplicate `action` keys in different cases, gateway and backend disagreed on which one wins | `vault/techniques/web/json-parser-key-casing-differential.md`, `CLAUDE.md` 2026-08-04 session |
| — | HackTheBox | Desires | web (Go/Fiber + Node SSO) | `HTB{S0m3tIm3s_Its_J4usT_A_B!G_M3ss}` | Session middleware trusted a client-supplied `username` cookie without checking it against the real session; timestamp-seeded session IDs made forgery easy | `evals/practice_runs.md` → "Desires" |

## Not yet solved (for reference, not a full log — see source docs for detail)

| Platform | Challenge | Status | Detail |
|---|---|---|---|
| HackTheBox | SecNotes | Stuck — confirmed airtight | `CLAUDE.md`, 2026-08-03/04 session |
| HackTheBox | Cosmic Explorer | Stuck — ~90 steps, no positive signal | `CLAUDE.md`, 2026-08-03/04 session (**note**: may be the same target as "Space Explorer" above under a different name — worth the team confirming before assuming two separate boxes) |
| HackTheBox | Offlinea | In progress, source obtained | `evals/practice_runs.md` → "Offlinea" |

## Naming note

"Space Explorer" and "Cosmic Explorer" may refer to the same HTB target — both are web
challenges with a "cosmic" theme, and the flag itself (`C0SM1C-BYP4SS`) matches the "Cosmic"
name, not "Space". Flagged here rather than silently merged, since `CLAUDE.md` describes them as
separate outcomes (one stuck, one solved) across two different session notes. Confirm with the
team and fix this file (and `CLAUDE.md` if needed) once resolved.
