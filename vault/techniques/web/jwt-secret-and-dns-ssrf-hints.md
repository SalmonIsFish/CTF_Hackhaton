# Reading a requirements.txt as a vulnerability roadmap (JWT + DNS-SSRF case study)

**Category**: Web, methodology
**Signal**: You have (or can get) a target's dependency list — `requirements.txt`,
`package.json`, `go.mod`, etc. — even without full source access. Each unusual dependency is a
hint about what mechanism the challenge actually tests, often more useful than blind probing.

## The technique

A dependency list narrows the hypothesis space fast. For a Flask app with
`flask, selenium, pyjwt, requests, dnspython`:

- **`selenium`** — confirms the PDF/screenshot feature (see [[pdf-generator-ssrf-selenium]]) is
  a *real* headless-browser SSRF surface, not a lightweight PDF library. Matches the PDF
  metadata already observed (`Skia/PDF`, real `Chrome/1xx` user-agent).
- **`pyjwt`** — JWT is in play *somewhere*, even if no JWT was visible yet in cookies/headers.
  Worth actively looking for: a session cookie, a signed download link, a "receipt" token
  returned alongside the PDF, or — given the app has a field literally labeled "YOUR LITTLE
  SECRET" — the user-supplied `secret` value may not be an arbitrary string at all, it may be
  fed directly into JWT signing/verification somewhere server-side. That reframes "brute-force
  guessing what `secret` does" into "test whether `secret` controls or leaks a JWT signing key."
  Concrete things to try: does changing `secret` change a JWT's signature validity anywhere
  observable? Is there an `alg: none` bypass? Is the same `secret` reused to sign something the
  attacker can also independently verify/forge (HS256 key confusion if an RS256 public key is
  ever exposed)?
- **`dnspython`** — a DNS resolution library rarely appears in a typical CRUD app; its presence
  strongly suggests the SSRF guard on the `url` parameter does its own DNS resolution + IP
  blocklist check (rather than a pure string check), which explains behavior a pure string-check
  theory doesn't: a plain string-blocklist check responds *instantly* (matches what was observed
  for `file://`), while an active DNS-resolution-based check can *hang* if outbound DNS itself
  is unavailable in a sandboxed challenge container (matches what was observed for every plain
  `http://` URL, including ones to `127.0.0.1` — if the guard tries to resolve/verify via DNS
  before allowing the browser to navigate, and DNS resolution itself never completes, nothing
  downstream ever runs, regardless of whether the target IP would ultimately have been allowed).
  This reframes "http:// is just blocked/hanging" into a much more specific hypothesis: **the
  guard's own DNS check is the broken/slow step**, not necessarily egress being fully blocked.
  Bypasses worth trying specifically because of this: IP-literal URLs that never need a DNS
  lookup at all (already tried and also hung — worth revisiting once the target has recovered,
  since a degraded renderer pool could have caused those hangs too, confounding the test), or
  DNS rebinding if the guard resolves once and the browser re-resolves separately.
- **`requests`** — likely just the app's own outbound HTTP client (could be what the SSRF
  guard itself uses internally, e.g. a HEAD request to validate reachability before handing off
  to Selenium — another place a hang could originate).

## Why this matters for CTF strategy generally

Blind probing (try `file://`, try common internal ports, try common paths) is what most
solvers, human or agent, default to. Reading the dependency list first turns that into
*targeted* probing — every unusual import is a hint the challenge author left, intentionally or
not, about which specific mechanism is the intended vulnerability. This is a cheap, high-value
step to do *before* spending a large probing budget, not after.

## Status on the specific case this note came from

HackTheBox "Offlinea" — not yet solved. Updated after session 3 (live Chrome browser recon,
full write-up in `evals/practice_runs.md`):

- **Internal origin confirmed: `http://127.0.0.1:8000`** — leaked by the returned PDF's own
  print-to-PDF header (Chrome stamps the printed page's URL at the top). Public port proxies to
  the app on internal `:8000`; the SSRF's internal target origin is now known outright.
- **The `url` check is a positive allowlist ("must be http(s)://"), not a `file://` blocklist** —
  `data:` URIs are rejected with the same instant "Dont try to trick me!" as `file://`. So the
  `data:`-URI rendering primitive is dead; only http(s) passes.
- **Every `http://` url hangs ~45s, including a CLOSED local port** (`127.0.0.1:1`). A closed port
  hanging (rather than fast-refusing) is the tell: the guard's *own* pre-navigation step hangs on
  every http url — best explained by a `dnspython` lookup with no resolver in the offline
  container. This is likely the literal meaning of "Offline": the DNS-based SSRF guard can never
  complete, so nothing downstream runs.
- **`name`/`secret` are not reflected on the invalid-url render** — they only appear on the
  valid-url card path, which hangs, so the name-injection hypothesis is untestable until the hang
  is defeated.

**Next attempt (fresh instance):** try `url=http://localhost:8000/` FIRST — `/etc/hosts`
resolution may sidestep the DNS hang that IP literals hit. Read the PDF via the
fetch-blob→`URL.createObjectURL`→full-viewport-`<iframe>`→screenshot trick (Chrome renders it and
its header leaks internal URLs — how the `:8000` origin was found), not the manual PDF decoder.
Strict budget: each http-triggering call risks a 45s stall and the instance degrades fast — one
fresh instance per attempt.

## Related

- [[pdf-generator-ssrf-selenium]]
