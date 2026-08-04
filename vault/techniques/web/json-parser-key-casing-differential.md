# Go vs Python JSON key-casing differential (duplicate/conflicting JSON keys)

**Category**: Web
**Signal**: A request passes through two services in different languages that each parse the
same raw JSON body independently (e.g. a proxy/gateway in one language forwarding the exact
bytes to a backend in another). Especially worth trying whenever one language is Go.

## The technique

Go's `encoding/json` matches JSON object keys to struct fields **case-insensitively**, and when
a JSON object has two keys that only differ by case, the **last matching key wins**. Python
`dict`/`json.loads` is case-sensitive and keeps both keys as distinct entries.

If a Go-based proxy validates/authorizes a request using its own (case-insensitive) parse, then
forwards the **original raw bytes** unchanged (e.g. Go's `bytes.NewBuffer(body)`) to a
Python backend, the two services can disagree about which key's value is "the" value —
letting you smuggle a value past validation that the backend actually acts on.

## Example payload

```json
{"action": "getSecureCode", "Action": "getcosmic"}
```

- Go's decoder resolves its single struct field via the last matching key regardless of case →
  sees `Action: "getcosmic"` → this passes whatever check only allows `"getcosmic"`.
- Go forwards the **raw, unmodified body** to the Python backend.
- Python reads the literal lowercase key `data["action"]` → gets `"getSecureCode"` → the actual
  privileged/protected action fires.

## Source challenge

HackTheBox "Space Explorer" (Web, Very Easy) — flag `HTB{C0SM1C-BYP4SS}`. Solved by pasting the
challenge's own Go "Sender" proxy + Python "Receiver" source into the prompt; the agent
correctly identified "conflicting JSON keys" as the right attack category from source alone but
initially missed the specific case-insensitivity mechanism (tried duplicate-same-case-key
variants first). Manually confirmed. Cross-checked against a public writeup
(medium.com/@raviaravindhan.official, "HTB Space Explorer Writeup") — matches exactly.

**Full run write-up**: see `evals/practice_runs.md`, "Real HackTheBox target — 'Space Explorer'".

## Recon checklist (for spotting this on a *different* challenge)

- [ ] Does a gateway/proxy sit in front of a second service written in a different language?
- [ ] Does the gateway decide to forward based on a JSON field it parses into a typed
      struct/model (Go, Java, C#, Rust with serde, etc.)?
- [ ] Does the gateway forward the **raw original body**, not a value it re-serializes?
- [ ] Is the downstream service using a plain dict/object lookup (Python, JS/Node, PHP) for the
      same field?
- [ ] If all four are true, try duplicate/differently-cased keys for the control field before
      looking elsewhere for a bypass.

## Don't confuse with

- **HTTP parameter pollution** (`?id=1&id=2`) — same "which duplicate wins" root cause, but at
  the URL query-string level, not inside a JSON body.
- **HTTP request smuggling** (CL/TE desync between a proxy and origin server) — a different layer
  entirely (framing of the HTTP message itself, not JSON key resolution within one body).
- **Case-insensitive route matching bypassing a path-based filter** — a parser differential too,
  but over URL *paths*, not JSON object *keys*.

## Related

- [[cookie-trust-auth-bypass]] — a different flavor of "two components disagree about who to
  trust," from the same overall session's real-target work.
