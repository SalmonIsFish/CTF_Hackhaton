# Advanced Web Challenge Testing Methodology

**Category**: Web security, methodology
**Level**: Intermediate to Advanced (20+ years pentesting experience)
**When to use**: Every web challenge; start here, then reference specific technique notes as needed

## Phase 0: Pre-Engagement Intelligence Gathering

Before touching the target, gather context that will shape your approach:

1. **Source code review** (if available)
   - Read the application story (comments, README, git log)
   - Identify all frameworks and dependencies
   - Look for obvious security misconfigurations (DEBUG=True, hardcoded secrets)
   - Trace data flow from user input to database/output

2. **Framework fingerprinting**
   - Check error pages, response headers, file structure
   - Determine if it's a modern SPA, traditional server-rendered, or hybrid
   - Identify API version and endpoints from JS bundles

3. **Scope definition**
   - What data does this app handle? (PII, financial, medical, flags)
   - Authentication present? (Yes → focus on bypass; No → focus on data access)
   - File upload? (Yes → RCE is probably the win)
   - External integrations? (API calls → SSRF vector)

## Phase 1: Passive Reconnaissance (Read-Only)

### 1.1 HTTP/Response Analysis
- [ ] **All responses**: Check status code, headers, body size for patterns
- [ ] **Server header**: Identify framework, version, OS hints
- [ ] **Security headers**: X-Frame-Options, CSP, HSTS, X-Content-Type-Options
- [ ] **Cookies**: SameSite, Secure, HttpOnly, domain, path restrictions
- [ ] **Content-Type**: JSON, XML, HTML, PDF — each has different injection points
- [ ] **Caching**: Cache-Control, ETag, Last-Modified (cache poisoning vectors)
- [ ] **Encoding**: Transfer-Encoding, Content-Encoding; chunk size can leak data

### 1.2 JavaScript Reconnaissance
- [ ] **Extract from source**: Use DevTools > Sources or fetch `.map` files
- [ ] **Search for**: API endpoints, hardcoded credentials, feature flags, debug code
- [ ] **API discovery**: `fetch(`, `axios.`, `$.ajax(`, `XMLHttpRequest` patterns
- [ ] **Sensitive data in JS**: Search for `flag`, `password`, `token`, `secret`, `admin`
- [ ] **Comments and TODOs**: `// TODO: fix`, `/* FIXME`, `// DEBUG`, `// HACK`
- [ ] **Framework-specific**:
  - React: `window.__REACT_DEVTOOLS_GLOBAL_HOOK__`, state props
  - Angular: Injector/service inspection
  - Vue: `window.__VUE__`

### 1.3 HTML/DOM Structure
- [ ] **All forms**: Fields, method (GET/POST), action, hidden fields
- [ ] **All links**: Enumerate every href, data attributes, onclick handlers
- [ ] **DOM events**: onclick, onload, onchange, onsubmit handlers
- [ ] **Meta tags**: Especially `<meta name="csrf-token">` or custom tokens
- [ ] **Comments**: HTML comments often contain debugging info or hints
- [ ] **Inline styles/scripts**: Hardcoded paths, API URLs, feature flags

### 1.4 Endpoint Enumeration (from static analysis)
- [ ] **Documentation**: `/api/docs`, `/swagger.json`, `/graphql`, `/.well-known/`
- [ ] **GraphQL introspection**: `POST /graphql` with introspection query (if GraphQL)
- [ ] **From JavaScript**: Extract all fetch/axios URLs, build endpoint map
- [ ] **Robots.txt & sitemap.xml**: Often reveal intended and hidden paths
- [ ] **Common paths**: `/admin`, `/api`, `/debug`, `/health`, `/metrics`

## Phase 2: Active Testing — Vulnerability Categories (Ordered by Likelihood & Time)

### Priority 1: Information Disclosure (Zero Risk, Immediate Wins)

- [ ] **Git exposure**: `/.git/HEAD`, `/.git/config`, enumerate commits
- [ ] **Backup files**: `backup.zip`, `dump.sql`, `.env.backup`, `.bak` files
- [ ] **Config exposure**: `config.php`, `settings.json`, `application.yml`, `web.config`
- [ ] **Source leaks**: Uncompiled `.js`, `.py`, `.rb` files directly accessible
- [ ] **Environment variables**: `.env` file, `phpinfo()`, `env.json`
- [ ] **Error page info**: Stack traces, database schema hints, file paths
- [ ] **Directory listings**: Missing index files, listing enabled
- [ ] **Response headers**: Server version, X-Powered-By, X-AspNet-Version
- [ ] **Comments & metadata**: EXIF data on images, PDF metadata, JS comments
- [ ] **API metadata**: `/api/version`, `/api/config`, `/api/info`

### Priority 2: Unauthenticated/Low-Auth Access (Usually Quick Wins)

- [ ] **Missing auth checks**: Try accessing `/admin`, `/api/users`, `/private` without login
- [ ] **IDOR (Insecure Direct Object Reference)**:
  - [ ] Numeric IDs: `/user/1`, `/user/2`, `/user/999`, `/user/0`
  - [ ] UUID/hash-based: Try incrementing last byte, guessing sequential patterns
  - [ ] Time-based: If created_at is visible, enumerate by date ranges
  - [ ] Username-based: `/user/admin`, `/user/test`, `/user/root`
  - [ ] Timing analysis: Valid ID responds 200ms, invalid 50ms (can enumerate blind)

- [ ] **Default credentials**: Test common combinations across all auth endpoints
  - admin/admin, admin/password, admin/123456, root/root
  - test/test, guest/guest, demo/demo
  - Framework defaults (Tomcat, Axis2, etc.)

- [ ] **Auth bypass via HTTP methods**:
  - [ ] GET instead of POST (POST endpoint secured, GET not)
  - [ ] PUT instead of DELETE
  - [ ] HEAD request (often logged differently)
  - [ ] OPTIONS (may return 200 on protected endpoint)

- [ ] **Null/empty auth**: Remove auth header, submit empty/null tokens
- [ ] **Case/encoding variation**: `Admin`, `ADMIN`, `admin@`, `admin%00`

### Priority 3: Cryptographic/Token Weaknesses

- [ ] **JWT analysis**:
  - [ ] Decode claims (no signature verification needed for claims)
  - [ ] Test `"alg": "none"` (token without signature)
  - [ ] Algorithm confusion: Try changing to symmetric algorithm if asymmetric is used
  - [ ] Key confusion: If RS256 but server accepts HS256 with public key as secret
  - [ ] Token prediction: Weak PRNG or timestamp-based generation

- [ ] **Session token analysis**:
  - [ ] Sequential generation: `token_1`, `token_2`, `token_3` (brute-force)
  - [ ] Timestamp-based: Can predict future tokens
  - [ ] Format analysis: Base64 → decode for structure, hex → convert
  - [ ] Manipulation: Change user ID in token, see if server trusts it

- [ ] **Signature bypass**: Missing signature, weak cryptographic algorithm, hard-coded key

### Priority 4: Authentication Bypass

- [ ] **SQL Injection in login**: `' OR '1'='1`, `admin' --`, `' UNION SELECT 1,2,3 --`
- [ ] **LDAP Injection**: `*`, `*)(|(uid=`, `admin*`
- [ ] **NoSQL injection**: `{$ne: ""}`, `{$where: "1==1"}` in JSON login
- [ ] **Username enumeration**: Registration/password reset reveals valid users (different responses)
- [ ] **Password reset tokens**: Predictable, reusable, no expiration
- [ ] **OAuth/Social login**: Unverified email, missing state validation, account linking

### Priority 5: Authorization/Access Control

- [ ] **Privilege escalation**:
  - [ ] Modify `role`, `admin`, `is_admin` fields in request/token
  - [ ] Horizontal escalation: Access other users' data
  - [ ] Vertical escalation: Become admin via parameter tampering

- [ ] **Header-based auth bypass**:
  - [ ] X-Forwarded-For (if trusted for rate limiting or IP checks)
  - [ ] X-Original-URL, X-Rewrite-URL (bypass front-end restrictions)
  - [ ] Host header manipulation (ALLOWED_HOSTS bypass)

- [ ] **API key exposure**: Leaked in source code, error messages, or git history

### Priority 6: Injection Attacks

#### 6.1 SQL Injection
- [ ] **Error-based SQLi**: Trigger errors to reveal schema (UNION, EXTRACTVALUE, etc.)
- [ ] **Boolean-based blind SQLi**: `AND 1=1` vs `AND 1=2` to infer true/false
- [ ] **Time-based blind SQLi**: `SLEEP(5)` to confirm vulnerability
- [ ] **Out-of-band (OOB)**: DNS/HTTP callbacks to exfiltrate data
- [ ] **Database enumeration**: Version, user, databases, tables, columns
- [ ] **Escalation**: Dump credentials, read files (LOAD_FILE, OUTFILE), execute code

#### 6.2 NoSQL Injection
- [ ] **MongoDB**: `{$ne: ""}`, `{$gt: ""}`, `{$where: "..."}`, regex operators
- [ ] **Redis commands**: If input reaches Redis commands (SET, DEL, FLUSHDB)
- [ ] **Document structure**: Break query structure with `}, {$ne: {`, etc.

#### 6.3 Server-Side Template Injection (SSTI)
- [ ] **Identify engine**: Jinja2, Mako, Twig, ERB, Velocity, Freemarker
- [ ] **Test expression**: `{{ 7 * 7 }}`, `<%= 7 * 7 %>`, `${7*7}`
- [ ] **Object introspection**: `{{ "".__class__ }}`, `{{ obj.class }}`
- [ ] **RCE via builtins**: Access `__builtins__`, `os.system`, `subprocess`
- [ ] **Payload construction**: Chain through `__init__.__globals__`, etc.

#### 6.4 Command Injection
- [ ] **Common metacharacters**: `;`, `|`, `||`, `&`, `&&`, `` ` ``, `$()`
- [ ] **Filter bypass**: Encode, case variation, quotes
- [ ] **Second-order execution**: Inject into file, then execute
- [ ] **Blind detection**: Time-based (`sleep 5`), OOB DNS (`nslookup attacker.com`)

#### 6.5 XPath Injection
- [ ] **XML manipulation**: `' or '1'='1`, `' or '1'='1` in XML queries
- [ ] **Blind extraction**: Bit-by-bit via `substring()` function
- [ ] **Count-based**: `count(//node[condition])` reveals boolean

#### 6.6 LDAP Injection
- [ ] **Wildcard expansion**: `*`, breaks authentication if unchecked
- [ ] **Filter injection**: `*)(|(uid=`, `admin*))(|(password=`
- [ ] **Blind extraction**: Time-based or error-based

### Priority 7: File Handling & Traversal

- [ ] **File upload**:
  - [ ] **Extension bypass**: `.php5`, `.php7`, `.phtml`, `.shtml`, `.svg+xml`
  - [ ] **MIME type bypass**: Submit `.php` but claim it's `image/jpeg`
  - [ ] **Path traversal**: `../../shell.php`, `...//...//shell.php`
  - [ ] **Null byte**: `shell.php%00.jpg` (if old PHP)
  - [ ] **ZIP symlink**: Upload ZIP with symlink pointing to sensitive file
  - [ ] **Double extension**: `.php.jpg` (some servers process right-to-left)
  - [ ] **Case variation**: `shell.PhP`, `.pHP5`

- [ ] **File download/traversal**:
  - [ ] **Path traversal**: `/download?file=../../../etc/passwd`
  - [ ] **URL encoding**: `%2e%2e%2f` (encoded `../`)
  - [ ] **Unicode encoding**: `..%c0%af` (UTF-8 encoded `/`)
  - [ ] **Null byte**: `/download?file=/etc/passwd%00.txt`
  - [ ] **Symbolic link following**: If filesystem allows, symlinks to sensitive files

- [ ] **Directory listing**: Missing index file, directory listing enabled

### Priority 8: Cross-Site Scripting (XSS)

- [ ] **Reflected XSS**: Input echoed back in response
  - [ ] Test: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`
  - [ ] All user-controlled inputs: URL params, POST data, headers, cookies

- [ ] **Stored XSS**: Input stored and displayed to other users
  - [ ] Comments, profiles, settings, feedback forms
  - [ ] DOM XSS: JavaScript-only vulnerability, no server reflection

- [ ] **Bypass filters**:
  - [ ] Tag alternatives: `<svg>`, `<iframe>`, `<embed>`, `<object>`, `<marquee>`
  - [ ] Event alternatives: `onload`, `onmouseover`, `oninput`, `onchange`, `ontouchstart`
  - [ ] Encoding: HTML entities, URL encoding, UTF-8, hex, double encoding
  - [ ] Case variation: `<ScRiPt>`, `<IMG>`

### Priority 9: CSRF & Related Attacks

- [ ] **CSRF tokens**:
  - [ ] Missing token on POST (GET requests not protected)
  - [ ] Token not tied to session (reusable across sessions)
  - [ ] Predictable tokens (sequential, weak random)
  - [ ] Not validated on origin (missing Referer/Origin check)

- [ ] **SameSite bypass**:
  - [ ] SameSite=None; Secure → full CSRF exploitation
  - [ ] Missing SameSite on sensitive cookies

### Priority 10: XXE (XML External Entity)

- [ ] **File read**: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`
- [ ] **SSRF via XXE**: Entity pointing to `http://localhost:8080/admin`
- [ ] **Out-of-band data exfiltration**: DNS callback or HTTP callback
- [ ] **Blind XXE**: No error output, use timing or OOB

### Priority 11: SSRF (Server-Side Request Forgery)

- [ ] **Common parameters**: `url=`, `file=`, `proxy=`, `link=`, `image=`, `document=`
- [ ] **Cloud metadata**: AWS `169.254.169.254`, GCP `metadata.google.internal`
- [ ] **Internal services**: `localhost:8080`, `127.0.0.1:9200`, `internal-api:3000`
- [ ] **Protocol fuzzing**: `gopher://`, `dict://`, `ldap://`, `sftp://`, `file://`
- [ ] **Authentication bypass**: Using SSRF to access internal admin panels

### Priority 12: Deserialization RCE

- [ ] **Java**: Look for `.ser` files, Java serialized objects in requests
- [ ] **PHP**: `unserialize()` of user input
- [ ] **Python**: `pickle.loads()`, `yaml.load()`, `json.loads()` with malicious data
- [ ] **Gadget chains**: ysoserial for Java, pickle gadgets for Python

### Priority 13: Race Conditions & TOCTOU

- [ ] **Check-then-act**: Verify permission, then execute (gap where permission changes)
- [ ] **Concurrent requests**: Send multiple requests simultaneously
- [ ] **Common victims**: File operations, money transfers, unique constraint checks

## Phase 3: Exploitation (Once Vulnerability Confirmed)

1. **Reproduce reliably**: Confirm vulnerability multiple times, understand exact conditions
2. **Extract credentials**: If auth bypass, extract admin credentials for further access
3. **Enumerate data**: Dump users, passwords, configuration, internal data
4. **Escalate privileges**: Use leaked credentials to access higher-privilege functions
5. **Achieve RCE**: If file upload or code injection exists, achieve remote code execution
6. **Find the flag**: Usually in database, filesystem, or admin-only endpoint

## Phase 4: Post-Exploitation

1. **Clean up**: Remove shells, cover tracks in logs if applicable
2. **Verify flag**: Ensure flag is correct before submitting
3. **Document chain**: How did individual vulnerabilities chain together?

## Advanced Techniques for Difficult Targets

- **White-box advantage**: If source code available, search for dangerous functions, focus on areas with least testing
- **GraphQL exploitation**: Query for sensitive fields, test nested queries, look for N+1 problems
- **Polyglot attacks**: Combine multiple attack vectors (SSTI + SQLi, XXE + SSRF)
- **Side-channel attacks**: Timing differences, error message variations, response size analysis
- **Automation**: Use `dir_enum` tool for path discovery, then manual exploitation

## Time Management

For a typical CTF challenge:
1. **0-5 min**: Source code review (if available), framework ID
2. **5-15 min**: Passive reconnaissance, endpoint enumeration
3. **15-30 min**: Priority 1-3 testing (info disclosure, IDOR, auth bypass)
4. **30-45 min**: Priority 4-6 testing (injection attacks)
5. **45-60 min**: Priority 7-13 testing (file handling, XSS, SSRF, etc.)
6. **60+ min**: Deep exploitation, multi-vulnerability chains

**If flag not found after 60 min**: Re-read challenge statement, check if source code provides hints, or move to next challenge.

## Related Technique Notes

- [[idor-insecure-direct-object-reference]]
- [[sql-injection-creative-bypasses]]
- [[server-side-template-injection-ssti]]
- [[command-injection-shell-escape]]
- [[zip-slip-symlink-bypass]]
- [[deserialization-rce]]
- [[cookie-trust-auth-bypass]]
- [[jwt-algorithm-confusion]]
- [[xxe-external-entity-injection]]
- [[ssrf-cloud-metadata-exposure]]
