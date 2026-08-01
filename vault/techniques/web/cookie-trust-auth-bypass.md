# Cookie-trust auth bypass (unsigned/unverified identity cookie)

**Category**: Web
**Signal**: A session mechanism uses two separate cookies — one that identifies *who you are*
(e.g. `username`) and one that's supposed to prove *you're really logged in* (e.g. `session`) —
but the server-side check only uses the identity cookie to look up state, and never verifies
the session cookie actually belongs to that identity.

## The technique

If server-side session lookup logic looks like:

```
username = cookie["username"]          // attacker-controlled, unsigned
real_session_id = redis.get(username)  // server looks up the REAL session by username alone
session_data = read_file(f"/sessions/{username}/{real_session_id}")
// the client's own "session" cookie value is never checked against real_session_id
```

...then simply changing the `username` cookie to any other user's name grants their identity,
**provided a session/state file for that username already exists server-side**. The `session`
cookie you send can be any value — it's cosmetic, never actually validated.

**Important limitation**: this only works if the target identity already has real, existing
session state to hijack. If no such account/session exists yet (e.g. a fresh challenge instance
with no admin ever logged in), this bug alone gets you nothing — you also need a way to *plant*
forged state at the exact path the lookup expects. See [[predictable-session-id-timestamp-hash]]
and [[zip-slip-symlink-bypass]] for how that gap was closed on Desires.

## Source challenge

HackTheBox "Desires" (Go/Fiber + Node SSO backend). `SessionMiddleware` trusted the `username`
cookie completely (`agent/graph.py`-equivalent finding: confirmed via a 500-vs-403 status
difference — 500 when no Redis entry exists for the impersonated username, 403 once one does
but the role is wrong). Combined with [[predictable-session-id-timestamp-hash]] and
[[zip-slip-symlink-bypass]] to fully exploit — see `evals/practice_runs.md` for the complete
chain and the captured flag.

## Related

- [[predictable-session-id-timestamp-hash]]
- [[zip-slip-symlink-bypass]]
- [[json-parser-key-casing-differential]] — different bug, same theme: two components
  disagreeing about what to trust.
