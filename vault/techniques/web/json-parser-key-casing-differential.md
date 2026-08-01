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

## Related

- [[cookie-trust-auth-bypass]] — a different flavor of "two components disagree about who to
  trust," from the same overall session's real-target work.
