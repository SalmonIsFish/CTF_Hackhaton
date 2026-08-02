# HTB "Offlinea" — full solve (from source)

**Category**: Web (SSRF → DNS rebinding → Python format-string injection → JWT forge)
**Status**: Fully reverse-engineered from the challenge source bundle
(`HTB Challnges/web_offlinea/`). Intended solution below; live execution needs DNS-rebinding
infra (or the IPv6 shortcut surviving `check_equiv`).

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
Full live solve needs DNS-rebinding infrastructure (public server returning 200 + a
multi-A-record/rebind domain with TTL ≥ 40 that also answers 127.0.0.1), driven through 3
sequential renders (seed payload → read /logs for `SECRET_KEY` → read /bartender for flag) on a
target that tolerates ~2–3 renders per instance. The IPv6 `[::ffff:127.0.0.1]` shortcut removes
the infra need *if* Chrome preserves the netloc through `check_equiv` — the single highest-value
thing to test live.

## Related
- [[jwt-secret-and-dns-ssrf-hints]] — the dependency-list recon that pointed here (now resolved).
- [[pdf-generator-ssrf-selenium]] — the headless-Chrome-PDF SSRF primitive.
