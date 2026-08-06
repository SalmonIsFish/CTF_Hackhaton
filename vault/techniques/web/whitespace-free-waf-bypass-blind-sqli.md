# Blind boolean SQLi past a WAF that blocks quotes/whitespace/comments (parens + `char()`)

**Category**: Web
**Signal**: A numeric-looking parameter (an `id`, an existence-check endpoint) sits behind a WAF
that returns a **specific classification** for what it blocked (e.g. `{"blocked": "quote"}`,
`{"blocked": "whitespace"}`) rather than a generic denial. A talkative WAF like this is a gift —
use its own error messages to map the filter instead of guessing blind.

## The technique

Three WAF rules together look airtight but aren't, because SQL doesn't actually need any of
them:

1. **No whitespace** → doesn't matter if the injected expression never needs a keyword boundary
   made of a space. Parentheses are token delimiters too: `(1)AND(1=1)` parses identically to
   `(1) AND (1=1)` — no space required anywhere, for `AND`/`OR`/nested subqueries/function calls.
2. **No quotes** → don't build string literals with `'...'` at all. SQLite (and MySQL/Postgres
   have equivalents — `CHAR()`, `CHR()`) can construct a string from bare integer codepoints:
   `char(116,97,98,108,101)` evaluates to `'table'` with zero quote characters anywhere in the
   payload. Every string literal a payload needs — table names to filter on, comparison targets —
   goes through this instead.
3. **No comments (`--`, `/* */`) and no semicolons** → irrelevant if the original query has
   nothing *after* the injected value to suppress. Confirm this first (inject something that
   would only work with nothing trailing, like a bare boolean tautology) before assuming you need
   a terminator at all — many single-value injection points (`WHERE id = <here>`, nothing else)
   never needed comment-stripping in the first place.

None of the three blocked categories touch the actual primitives blind boolean extraction needs:
`(`, `)`, `AND`, `OR`, `=`, `<`, `>`, digits, and bare identifiers (table/column names — never
quoted in SQL to begin with). A WAF that blocks quote/whitespace/comment characters specifically
is defending against the *textbook* payload shape, not the underlying capability.

## Full blind extraction recipe (once the bypass is confirmed)

1. **Confirm control, not just blocking**: `id=(1)OR(1=1)` should flip an otherwise-false lookup
   to true; `id=(<known-good-id>)AND(1=2)` should flip an otherwise-true lookup to false. If both
   hold, you have a real boolean oracle, not just "the WAF let something through."
2. **Fingerprint the SQL dialect** without quotes: `(1)AND((SELECT(COUNT(*))FROM(sqlite_master))>0)`
   for SQLite; swap in `information_schema.tables` for MySQL/Postgres. Only one will return true.
3. **Enumerate schema** via `sqlite_master` (or `information_schema.tables`/`.columns`):
   `(SELECT(name)FROM(sqlite_master)WHERE(type=char(...'table'...))LIMIT(1)OFFSET(i))` for the
   i-th table name, extracted character-by-character (below). The `sql` column of `sqlite_master`
   gives you the full `CREATE TABLE` statement — including every column name — in one extraction
   instead of guessing column names separately.
4. **Extract any string via binary search**, not linear guessing — this is the actual speed
   lever. For each character position `i`:
   `(unicode(substr(<expr>,i,1)))<=mid` — binary search `mid` over the byte/codepoint range
   (start with 0-255, expand only if that upper bound never trips true, i.e. the character is
   non-Latin1). ~8 requests per character instead of ~95 for a full ASCII linear scan. Get the
   string's `length(<expr>)` first the same way (linear is fine here since lengths are usually
   short, or binary-search this too for a large blob).
5. **Look past the "normal" tables.** If the schema enumeration turns up a table the application
   never queries through its own documented endpoints (here: a `secrets` table sitting next to
   the expected `documents`/`users` tables), that's very likely the actual target — a WAF and an
   auth layer both only defend the paths the app is *supposed* to take; a table that's reachable
   only through injection was never in either one's threat model.

## Source challenge

Hackathon organizer (UCSI26) "Vault" (Web) — a document store with `GET /api/doc?id=<n>` behind
session auth and a query firewall that returned `{"error": "blocked by query firewall",
"classification": "waf-block", "blocked": "<reason>"}` for quote/whitespace/line-comment/
block-comment/semicolon. Full write-up: `evals/practice_runs.md` → "Vault".

## Don't confuse with

- **NoSQL injection** (`{"$ne": null}`-style operator injection into a MongoDB-backed query) —
  same *spirit* (bypass a filter to control query logic) but a completely different payload
  shape; this note is specifically about SQL string/whitespace/comment avoidance.
- **Time-based blind SQLi** (`SLEEP()`/`pg_sleep()` oracles) — only needed when there's no
  content/boolean signal to read at all. Here the endpoint already returns a boolean
  (`found: true/false`), so a much faster content-based oracle was available — always prefer a
  boolean/content oracle over a timing one if the response gives you literally any signal to
  distinguish true from false.

## Related

- [[sql-injection-creative-bypasses]] — the general reference library entry this specific
  worked technique sharpens; that note lists comment/encoding tricks in the abstract, this one
  is the concrete "the WAF blocks X, Y, Z and none of them are load-bearing" playbook.
