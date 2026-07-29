# Web Placeholder

Test fixture for `search_vault` — Farhan will replace/expand this with real notes.

## HTTP status codes worth knowing

- 200 OK — request succeeded
- 301/302 — redirect, check the `Location` header for where it points
- 401 Unauthorized — missing/invalid auth, try common credentials or auth bypass
- 403 Forbidden — check for alternate paths, method overrides, or header tricks
- 404 Not Found — good sign a hidden endpoint doesn't exist yet, keep guessing paths
- 500 Internal Server Error — often leaks stack traces with useful info

## Common places flags hide in web challenges

- Page source (view-source, `Ctrl+U`) — HTML comments, hidden `<input>` fields, inline `<script>` blocks
- Response headers — custom headers like `X-Flag`, `Set-Cookie`, or debug headers
- Cookies — check values for base64/JWT-encoded flags, not just session IDs
- robots.txt / sitemap.xml — sometimes lists disallowed paths that are the actual target
- JS files — search bundled/minified JS for hardcoded strings or API keys
- API responses — flag may only appear in JSON, not the rendered page
