# IDOR (Insecure Direct Object Reference)

**Category**: Web
**Prevalence**: Extremely high — one of the most frequently overlooked web vulnerabilities
**Signal**: An API endpoint returns data keyed by a user-supplied ID (e.g. `/user/123`,
`/api/report?id=456`), and the server trusts that ID without verifying the caller owns/can access
that object.

## The technique

If an endpoint looks like:

```python
@app.route("/user/<user_id>/profile")
def get_profile(user_id):
    profile = User.query.get(user_id)  # No auth check!
    return jsonify(profile)
```

An attacker simply guesses or increments the ID: `/user/1/profile`, `/user/2/profile`, etc. —
and reads every user's data. Often escalates to:

1. **Reading admin profiles** (ID 1 is frequently admin, or you enumerate until you find one).
2. **Finding private data** (emails, hashes, API keys in profile fields).
3. **Lateral movement** (credentials found → login as another user → higher privilege).

## Why it's so common

- Developers often assume "if they can guess the ID, they're already authenticated" — but that
  only means they logged in, not that they should see *every* object.
- Modern APIs hide IDs as large random strings, but often still trust them without ownership
  verification.
- Testing requires only changing a number or string in a URL — easy to miss in code review
  because it looks "normal."

## Competition approach

1. **Identify ID parameters**: Look for numeric or UUID patterns in URLs, query strings, JSON
   bodies (`id`, `user_id`, `report_id`, `object_id`, `resource_id`, etc.).
2. **Test substitution**: Change your own ID to a different number or a known ID (e.g., `1`,
   `admin`, `test`). If you get a response, you've found an IDOR.
3. **Enumerate**: Write a quick script to loop through ID ranges and collect all accessible
   objects (usernames, emails, hashes, keys, private messages).
4. **Escalate**: Look for admin/privileged user IDs (lower numbers, specific naming patterns),
   read their data, and use any credentials or tokens to get higher access.

## Real gotcha

Many IDOR vulnerabilities are **conditional** — you can read some users' data but not others.

Example: you can see user IDs 2–10, but 11 returns 404 (they're a moderator/admin with extra
protection). This is actually a hint that user 11 is important. Try a few more IDs around
known-important accounts (e.g., if you know there's an admin, try IDs 1, 10, 100, admin).

Or you can read *public* fields but not *private* ones — test both authenticated and
unauthenticated access, and test with IDs belonging to different user roles (regular user vs
moderator vs admin).

**Also test parameter variation**: Sometimes IDOR is in hidden parameters you wouldn't guess:
`/api/profile` might not have an ID, but `?user_id=1` might work. Or it's in a POST body instead
of a URL param.

## Source

Recurring pattern across 0xdf's HTB writeups — IDOR chains frequently combine with credential
reuse or privilege escalation to reach admin functionality. One of the highest-ROI
vulnerabilities to check early in a web challenge.

## Related

- [[credential-reuse-enumeration-pattern]] — IDOR often reveals credentials that work elsewhere
