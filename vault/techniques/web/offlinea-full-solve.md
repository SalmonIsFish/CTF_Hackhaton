# HTB "Offlinea" — full solve (from source)

**Category**: Web (IPv6-mapped SSRF → Python format-string injection → JWT forge)
**Status**: ✅ **SOLVED LIVE** (2026-08-03) against `154.57.164.67:30928`.
**Flag**: `HTB{ddd7ceeb7dae10f4f2f1ed1b28b1f753}`
The intended DNS-rebinding path is documented below, but the **IPv6 shortcut works and needs no
infra** — see "Live solve" at the bottom for the one detail that decided it.

## Architecture (two tiers, one container)

- **PHP frontend** `service/bartender.php` on `0.0.0.0:8000` (the only externally exposed port).
  Takes `?url=&name=&secret=`, validates `url` via `no_way_trick_me()`, then curls
  `http://127.0.0.1:5000/generate?<same query>&time=<t>` and redirects the client to the
  resulting `/pdfs/results-<t>.pdf` (or `/pdfs/no_way.pdf` on rejection).
- **Flask backend** `internal/app.py` on `127.0.0.1:5000` (localhost-only, unreachable from
  outside). Routes: `/generate` (renders `url` via headless Chrome, stores `url` in `history`
  and `(name,secret)` in `secrets`), `/logs` (renders history — **vulnerable**), `/bartender`
  (returns all `secrets` — **JWT-gated, holds the flag**).
- **Flag**: `Dockerfile` copies `flag.txt` to `/flag.txt`; `init_db.py` inserts it into the
  `secrets` table as `('oldest_user_of_bartender', <flag>)`. So the flag is a DB row, only read
  by `/bartender`.

## The five links of the chain

### 1. SSRF is the only way to reach the internal app
`peek_website()` does `driver.get(url)` in headless Chrome. `/logs` and `/bartender` live on
`127.0.0.1:5000` and are reachable *only* by making Chrome navigate there — i.e. SSRF via the
`url` parameter.

### 2. Bypassing the twin guards + `check_equiv`
- **PHP `no_way_trick_me($url)`**: `gethostbyname($host)` then blocks private ranges
  (127/8, 10/8, 172.17/12, 192.168/16, 0/8, 169.254/16, ::1, fe80::/10); `url_check()` curls the
  url and requires HTTP 200; rejects non-http(s); **rejects any `{` or `}`** (`preg_match('/[{}]/')`).
- **Flask `is_request_safe(url)`**: if host is an IP literal → returns True *with no private
  check*; else resolves via `8.8.8.8` and requires **TTL ≥ 40** (explicitly anti-rebinding).
- **`check_equiv(driver.current_url, url)`**: normalized `(scheme, netloc, path.rstrip('/'),
  query)` must match — kills redirect-based SSRF and forces a **netloc-preserving** bypass.
- **Intended bypass = DNS rebinding**: a hostname that (a) `gethostbyname` → *public* IP so PHP's
  range check passes, (b) serves HTTP 200 for `url_check`'s curl, (c) has TTL ≥ 40 for Flask
  (note Flask only checks the TTL, never that the IP is public — the real flaw), and (d) resolves
  to `127.0.0.1` when Chrome navigates. Multi-A-record rebinding (public + 127.0.0.1, high TTL)
  fits because the hostname/netloc stays constant → `check_equiv` passes.
- **Possible no-infra shortcut**: `http://[::ffff:127.0.0.1]:5000/...` (IPv4-mapped IPv6).
  PHP: `parse_url` keeps the brackets so `filter_var`/`gethostbyname`/`inet_pton` all treat it as
  invalid/unresolvable (range checks skipped) while curl still connects to 127.0.0.1 → 200.
  Flask: `urlparse().hostname` strips brackets → `ipaddress.ip_address('::ffff:127.0.0.1')` is
  valid → instant True. **Risk**: Chrome may rewrite `::ffff:127.0.0.1` to `127.0.0.1` /
  `[::ffff:7f00:1]`, changing `driver.current_url`'s netloc and failing `check_equiv`. Untested —
  one render decides it.

### 3. Python `str.format()` injection in `/logs`
`logify()` builds `history_1` from the `history.url` column and calls
`history_1.format(logify=logify)`. Attacker-controlled url + `.format()` = classic format-string
injection. Since `logify` is passed as a kwarg, `{logify.__globals__[app].config[SECRET_KEY]}`
walks: `logify.__globals__` → module globals → `['app']` (Flask app) → `.config` →
`['SECRET_KEY']`. That leaks the JWT signing key (random per boot: `os.urandom(32).hex()`), which
appears in the rendered `/logs` PDF.
- **Seeding the payload past PHP's `{}` filter**: only `/generate` (reached via SSRF, not PHP)
  can store a brace-bearing url. PHP `$_GET['url']` and Flask `request.args.get('url')` each
  urldecode once, so a single-encoded brace is blocked by PHP's `preg_match`. **Double-encode**
  (`%257B`/`%257D`): PHP decodes once → `%7B` (no literal brace, passes), forwards the raw
  QUERY_STRING to Flask which decodes once → `%7B`… so seed via a *nested* SSRF: outer benign url
  → Chrome → `http://<bypass>:5000/generate?url=http://<bypass>:5000/logs%23%7B<payload>%7D&name=a&secret=a&time=1`,
  where the inner `/generate` stores `http://<bypass>:5000/logs#{payload}` in `history` (the
  `#fragment` is ignored by the server and by `normalize()`, so `check_equiv` still passes and the
  page still renders /logs → 200).

### 4. Forge the JWT
`token_required` does `jwt.decode(token, SECRET_KEY, algorithms=["HS256"])` then rejects only if
`not data.get('is_admin') and data.get('username') == 'bartender'`. So a validly-signed token with
`{"is_admin": true}` (or any `username != "bartender"`) passes. No `alg:none` (algorithms pinned),
so the leaked `SECRET_KEY` from step 3 is required: `jwt.encode({"is_admin": True}, SECRET_KEY,
algorithm="HS256")`.

### 5. Read the flag
SSRF to `http://<bypass>:5000/bartender?token=<forged_jwt>` → returns
`{"secrets":[{"name":"oldest_user_of_bartender","secret":"HTB{...}"}, ...]}`. Read it out of the
rendered PDF.

## Why the black-box sessions (1–4) all stalled
- `file:`/`data:` → PHP `parse_url` host empty / scheme check → instant `no_way.pdf` ("Dont try
  to trick me!"). The "positive allowlist" read was right for the wrong reason.
- `http://localhost:8000/...`, `http://127.0.0.1:...` → PHP private-range block → redirect to
  `no_way.pdf` (looks like "redirect to /").
- External `http://` → passes PHP/Flask but the offline container has no egress → Selenium's
  `set_page_load_timeout(40)` fires → ~40–45s **hang**. "Offline" = no HTTP egress; DNS (8.8.8.8)
  still works. Every "DNS-guard hangs" / "path-specific hang" theory was wrong — it was just the
  40s Selenium load timeout on unreachable hosts.
- Instance degradation = the per-request headless-Chrome cost, unchanged conclusion: budget hard.

## Execution reality
**Resolved — see "Live solve" below.** The DNS-rebinding path (public server returning 200 +
multi-A-record/rebind domain, TTL ≥ 40, also answering 127.0.0.1) is a valid but unnecessary
fallback: the IPv6 shortcut removes the infra need entirely, *provided you submit the **hex**
form `[::ffff:7f00:1]` that Chrome canonicalizes to* so the netloc survives `check_equiv`. Solved
live in 3 sequential renders (seed → leak `SECRET_KEY` → read flag); the instance tolerated the
render load fine when requests were spaced out.

## Live solve (2026-08-03) — the detail that decided it

The whole "no-infra" question came down to **which string form Chrome canonicalizes the
IPv4-mapped IPv6 address to**, because `check_equiv` compares `driver.current_url`'s netloc
against the submitted `url`'s netloc. Empirically, against the live instance:

- `http://[::ffff:127.0.0.1]:5000/logs` (**dotted**) → `no_way.pdf`, ~2s (PHP passed, Chrome
  rendered, but `check_equiv` **failed** — Chrome rewrote the netloc).
- `http://[::ffff:7f00:1]:5000/logs` (**hex**) → `results-<t>.pdf`, ~7s (includes `sleep(5)`) —
  **`check_equiv` passed**. Chrome canonicalizes the mapped address to the **hex** form, so you
  must submit *that* form for the netloc to match. This is the single fact that turns the IPv6
  shortcut from "untested theory" into a working, infra-free solve. **No DNS rebinding needed.**

Every hop therefore uses `[::ffff:7f00:1]:5000`. Endpoint is `/bartender.php` (not `/`).

### Working chain (all pure HTTP GETs to `/bartender.php`)
1. **Seed** the format-string payload via nested SSRF. Outer value Chrome navigates:
   `http://[::ffff:7f00:1]:5000/generate?url=<enc(inner)>&name=y&secret=y&time=1`
   where `inner = http://[::ffff:7f00:1]:5000/logs#{logify.__globals__[app].config[SECRET_KEY]}`.
   Encoding that actually worked: `send = quote(quote(inner)-wrapped OUTER)`, i.e. the inner
   braces end up double-encoded in the bytes sent so **PHP** sees `%7B` (passes `preg_match`),
   **outer Flask** decodes once → `%7B`, Chrome keeps `%7B` on the wire, **inner Flask** decodes
   once → literal `{` stored in `history`. Both PHP's `url_check` curl *and* the forwarded
   `/generate` seed it (payload lands twice — harmless, `format()` just expands each).
2. **Leak** `SECRET_KEY`: GET `/bartender.php?url=<enc(http://[::ffff:7f00:1]:5000/logs)>` →
   `/logs` runs `str.format()` over `history` → the seeded row expands to the 64-hex key in the
   rendered PDF. Live value this instance: `1cd6315…231ac9` (regenerates on every Flask boot).
3. **Forge** `HS256` JWT `{"is_admin": true}` signed with the leaked key (hand-rolled with
   `hmac`/`hashlib`, no PyJWT needed) and GET
   `/bartender.php?url=<enc(http://[::ffff:7f00:1]:5000/bartender?token=<JWT>)>` → the `/bartender`
   JSON (with the flag row) renders into the PDF.

### Gotchas confirmed live
- Endpoint is **`/bartender.php`**; hitting `/` just serves the static game page (HTTP 200, no
  redirect) and looks like a silent failure.
- `#` in the seed must stay a **literal fragment** at the moment inner-Flask/Chrome navigate it
  (so `/logs` loads and `check_equiv` — which ignores the fragment — passes); it's fine as text
  in the stored row afterward.
- PHP only blocks `{`/`}` — `[` `]` `#` pass its filter untouched, so only the curly braces need
  hiding.
- `results-<t>.pdf` = success, `no_way.pdf` = failure, and you can tell a PHP-reject (~0.3s, no
  render) from a render-then-`check_equiv`-fail (~2s) from a success (~7s, includes `sleep(5)`)
  purely by timing — useful when the redirect target alone is ambiguous.
- Extract the flag from the PDF with `pdftotext` (poppler).

Full scripts used: `solve.py` (seed + leak) and `step4.py` (forge + read) from the solve session.

## Related
- [[jwt-secret-and-dns-ssrf-hints]] — the dependency-list recon that pointed here (now resolved).
- [[pdf-generator-ssrf-selenium]] — the headless-Chrome-PDF SSRF primitive.
