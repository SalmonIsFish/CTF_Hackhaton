# Web challenge testing methodology & checklist

**Category**: Web, methodology
**When to use**: Every web challenge. This is your baseline testing plan when you don't know
the vulnerability category yet.

## Phase 1: Passive reconnaissance (no payload, just reading)

1. **Load the app**: Visit the homepage, note the tech stack (language, framework, libraries)
   from error messages, headers, HTML comments, or visible clues.
2. **Explore all pages/endpoints**: Click every link, list all forms, identify all parameters
   (URL params, POST body fields, headers, cookies).
3. **Read HTML source**: Look for comments, hidden inputs, `<!-- TODO: fix CSRF -->`, JavaScript
   URLs, inline scripts.
4. **Check robots.txt, .git, /.well-known/**: Often reveal hidden paths or admin panels.
5. **Fuzz for common paths**: Test `/admin`, `/api`, `/debug`, `/backup`, `/upload`, `/login`,
   `/users`, `/config`, `/download` — any one of these might exist and be unprotected.
6. **Document everything**: Write down all endpoints, parameters, cookies, auth state, and tech
   hints. You'll reference this repeatedly.

## Phase 2: Active testing — vulnerability categories (ordered by likelihood)

### Priority 1: Info disclosure (zero risk, instant wins)

- [ ] **Source code leakage**: Check for `.git`, `.env`, `backup.zip`, `app.js` in the web root.
- [ ] **Config exposure**: Try `/config.php`, `/settings.json`, `/database.ini`.
- [ ] **Comments & metadata**: Read JS files, look for `// TODO`, `// DEBUG`, hardcoded keys.
- [ ] **HTTP headers**: Check `Server`, `X-Powered-By`, `X-Frame-Options` — reveals tech and
  misconfigurations.
- [ ] **Verbose errors**: Trigger errors (invalid input, missing file) — stack traces leak
  paths and logic.

### Priority 2: Unauthenticated access (usually low effort)

- [ ] **IDOR**: Try changing numeric IDs in URLs (`/user/1`, `/user/2`). See
  [[idor-insecure-direct-object-reference]].
- [ ] **Missing auth checks**: Try accessing `/admin`, `/api/internal`, `/private` directly
  without logging in.
- [ ] **Default credentials**: Test `admin/admin`, `admin/password`, `test/test`, `admin/123456`.
- [ ] **Bypass via methods**: Try `GET` vs `POST` vs `HEAD` vs `OPTIONS` on protected endpoints
  (some frameworks handle them differently).

### Priority 3: Auth bypass & credential leakage

- [ ] **Username enumeration**: Test registration, password reset, login with variations
  (`admin`, `test`, `administrator`). Different responses reveal valid usernames.
- [ ] **Weak password resets**: Test if password reset tokens are predictable or reusable.
- [ ] **Token prediction**: If you get a session token, test if incrementing/modifying it
  grants access to other accounts.
- [ ] **Credential in request**: Check if any response body contains passwords/API keys (often
  developers copy-paste credentials into comments or test data).

### Priority 4: Common injection attacks

- [ ] **SQL injection**: See [[sql-injection-creative-bypasses]]. Start with basic payloads:
  `' OR '1'='1`, `; --`, `UNION SELECT 1,2,3`. If blocked, try alternate encoding or comment
  styles.
- [ ] **NoSQL injection**: For MongoDB/JSON APIs, test operators instead of quotes:
  `{ "username": { "$ne": "" }, "password": { "$ne": "" } }` (MongoDB auth bypass).
- [ ] **SSTI/Template injection**: See [[server-side-template-injection-ssti]]. Test math:
  `{{ 7 * 7 }}`, `<%= 7 * 7 %>`, `${7*7}`. If it evaluates, escalate to object introspection.
- [ ] **XSS (Stored & Reflected)**: Test `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`.
  Often wins flags if the app echoes input or stores it in a page.
- [ ] **XXE (XML External Entity)**: If the app accepts XML input, test XXE for file read:
  `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`.

### Priority 5: File handling & path traversal

- [ ] **File upload**: Upload a `.txt` or `.html` file, see if you can access it via the web.
  Escalate to RCE if possible (`.php`, `.jsp`, `.aspx`).
- [ ] **Path traversal**: Test `/download?file=../../../etc/passwd`, `/view?path=../../.env`.
- [ ] **Symlink bypass**: If the app extracts archives, test if symlinks are revalidated. See
  [[zip-slip-symlink-bypass]].

### Priority 6: Post-processing & system interaction

- [ ] **Command injection**: See [[command-injection-shell-escape]]. Test `; id #`,
  `$(whoami)`, `` `whoami` `` in filenames or search queries.
- [ ] **Deserialization**: See [[deserialization-rce]]. Test for Java serialized objects,
  PHP serialize, pickle payloads.

## Phase 3: Exploitation (once a vulnerability is confirmed)

1. **Reproduce the vulnerability reliably**: Confirm you can trigger it multiple times with
   controlled input.
2. **Escalate**: If it's SQLi, dump the database. If it's RCE, get a reverse shell. If it's
   IDOR, enumerate all users.
3. **Look for the flag**: Often it's in a database table, a file, an environment variable, or
   hidden behind an admin/privileged endpoint you now have access to.

## Tips for CTF context

- **Time-box each category**: Don't spend 30 min on SQLi if XSS works immediately. Test the
  easiest-to-exploit vectors first.
- **Combine vulnerabilities**: IDOR → credential reuse → privilege escalation is a common
  chain. One exploit rarely gets the flag alone.
- **Use your tools**: `fetch_url` (with headers support), `upload_file`, and the agent's
  `search_vault`/`search_skills` for technique reminders when stuck.
- **Read error messages carefully**: They often leak the vulnerability directly.

## Related technique notes

Deep-dive into these after using the checklist to narrow down the vulnerability:

**Auth & Access Control**:
- [[idor-insecure-direct-object-reference]] — ID-based access control bypass
- [[cookie-trust-auth-bypass]] — authentication bypass via unsigned cookies

**Injection Attacks**:
- [[sql-injection-creative-bypasses]] — SQL injection with filter bypasses
- [[server-side-template-injection-ssti]] — template injection to RCE
- [[command-injection-shell-escape]] — shell metacharacter injection

**File & Data Handling**:
- [[zip-slip-symlink-bypass]] — archive extraction directory traversal
- [[deserialization-rce]] — unsafe deserialization to RCE

**Reconnaissance & Escalation**:
- [[credential-reuse-enumeration-pattern]] — finding and reusing leaked credentials

Use this checklist to decide *which* technique to deep-dive into once you've narrowed down the
vulnerability class.
