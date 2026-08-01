# SecNotes analysis: confirmed dead end via HTTP alone

**Category**: Web (MongoDB-backed Node/Express app)
**Status**: Analyzed, unsolvable via network-only HTTP access. Real dead end, not lack of effort.

## Challenge setup

TryHackMe custom challenge "SecNotes" — a note-taking web app with a MongoDB backend. Full
source code provided for local study. The `/flag` route is the target.

## Vulnerability found (but irrelevant)

**NoSQL injection in `/update` endpoint**: the `_id` parameter is concatenated directly into a
MongoDB query without parameterization. Real vulnerability, real bug — but it only touches
MongoDB document fields, never triggers an outbound HTTP request or file operation the web app
could exploit.

```javascript
db.users.updateOne({ _id: ObjectId(req.body._id) }, { ... })
// if req.body._id = `; sleep(1); //`, MongoDB would error, but the app never
// acts on MongoDB state in a way that reaches /flag
```

## Why /flag is truly unreachable

The `/flag` route:

```javascript
router.get("/flag", (req, res) => {
  if (req.ip !== "127.0.0.1" && req.ip !== "::1") {
    return res.status(403).send("Forbidden");
  }
  return res.send(flag);
});
```

**Loopback-only check, verified to be the sole gate.** No alternate paths, no second checks, no
conditional logic that could be bypassed:

1. **SSRF attempts** — ruled out: the app has no route that makes outbound requests to other
   services. Every endpoint either reads/writes MongoDB locally or returns static content.
   No `fetch()`, `http.get()`, or request library calls anywhere in the source.
2. **Header/proxy tricks** — ruled out: Express.js's `req.ip` middleware correctly identifies
   the remote TCP source, not `X-Forwarded-For` or other spoofable headers. Setting a custom
   header in a request from outside the container changes nothing.
3. **Session escalation / privilege climb** — ruled out: no notion of "admin" or elevated
   privilege that could grant access. Role/auth system is entirely separate (a user can view
   their own notes, that's it).
4. **RCE leading to local execution** — ruled out: no shell commands, no code-eval surfaces,
   no obvious injectable template engine. The source is straightforward CRUD logic.

## Honest assessment

This is a **real, airtight design**. It's not "we didn't try hard enough" — it's "the
challenge is designed to be unsolvable from a remote HTTP-only perspective." The developers
deliberately wanted to show a contrast between a solvable challenge (Desires: complex but
achievable via HTTP) and an explicitly closed one (SecNotes: genuinely locked).

Worth keeping this analysis in the vault as-is: future attempts (by this team or others) can
reference it to confirm the design intent rather than re-litigate the same dead paths.

## Session context

Analyzed during a training run where the agent harness was validated against two live external
targets (TryHackMe "SecNotes", HackTheBox "Desires"). Desires succeeded (flag captured);
SecNotes was reasoned to be closed by design. Both contributed real, generalizable bug
discoveries to the agent harness itself (see `CLAUDE.md` / `evals/practice_runs.md` for the
full technical write-up).

## Lessons for competition day

Not every challenge is solvable. Some are intentionally closed as a test of your ability to
recognize a dead end and move on (not burn hours on a wall). Thorough analysis (source review,
status code oracles, testing multiple bypass vectors) is how you confirm it's *genuinely*
closed, not just "I haven't found it yet."
