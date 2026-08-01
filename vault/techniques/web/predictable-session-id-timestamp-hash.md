# Predictable session ID via sha256(timestamp)

**Category**: Web
**Signal**: A session/token ID that's a hash of something guessable (current time, an
incrementing counter, a username alone) instead of a real random secret (e.g. `crypto/rand`,
`secrets.token_hex`).

## The technique

If session ID generation looks like:

```go
sessionID := sha256(current_unix_timestamp_as_string)
```

...there is **no secret entropy at all** — anyone who knows roughly when a session was created
can compute the exact same hash. The response's own `Date` HTTP header gives you the server's
wall-clock time to within a second, so:

1. Trigger session creation for a chosen username (even via a **failed** login attempt, if the
   session-ID-generation step runs before credential validation — see caveat below).
2. Read the `Date` header from that response, convert to a Unix timestamp.
3. Compute `sha256(str(ts-1))`, `sha256(str(ts))`, `sha256(str(ts+1))` as candidates — a ±1s
   window covers clock/processing-time slop between when the server computed the hash and when
   it sent the response.
4. Use each candidate as the session ID; one of them matches.

**Real gotcha worth remembering**: session-prep and credential-validation are often two
separate steps executed in sequence — if the prep step (which leaks the predictable ID) runs
*before* the validation step, a **failed** login for a completely non-existent username still
leaks a usable, real session ID mapping for that username. You don't need valid credentials to
trigger the leak.

## Source challenge

HackTheBox "Desires". `LoginHandler` called `PrepareSession(sessionID, username)` — which sets
a Redis mapping `username → sessionID` — *before* calling `loginUser()` (the actual password
check). A login attempt as a chosen non-existent username with any wrong password still leaked
a real, computable session ID for that username. Combined with [[cookie-trust-auth-bypass]] and
[[zip-slip-symlink-bypass]] — see `evals/practice_runs.md` for the full chain and flag.

## Related

- [[cookie-trust-auth-bypass]]
- [[zip-slip-symlink-bypass]]
