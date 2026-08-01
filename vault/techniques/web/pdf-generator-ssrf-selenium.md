# PDF-generator SSRF (Selenium/headless Chrome "print to PDF")

**Category**: Web
**Signal**: An app takes a user-supplied URL and returns a PDF (a "screenshot this page,"
"download as PDF," "print my report" feature). Check the PDF's own metadata — `/Producer` and
`/Creator` fields often leak the exact rendering stack (e.g. `Skia/PDF m143` + a `Chrome/1xx.x`
user-agent string means it's a real headless Chrome instance via Selenium/Puppeteer/Playwright
driving DevTools Protocol's "print to PDF," not a lightweight library like wkhtmltopdf).

## Why this is a high-value target

A full headless browser rendering a user-controlled URL is one of the most powerful SSRF
primitives available — it doesn't just fetch a URL, it *executes JavaScript, follows redirects,
loads iframes/images, and resolves any scheme Chrome itself supports* (`file://`, `data:`,
`http://`, sometimes `chrome://` if not locked down). Whatever validation the app puts in front
of it is the entire attack surface.

## Reading the actual output: decoding a PDF's rendered text

**Don't rely on `fetch_url`'s raw text output for a PDF response** — PDF page content is
FlateDecode-compressed (raw zlib) and, if the page uses embedded/subsetted fonts (common with
Chrome's PDF export), the visible text is encoded as **glyph IDs**, not literal characters — you
need the PDF's own `ToUnicode` CMap (a `beginbfchar`/`beginbfrange` block) to map glyph codes
back to real Unicode. A naive "does the raw response contain a flag-shaped string" check will
never find text hidden this way, and worse, raw compressed binary can produce **false-positive
flag-pattern matches** on garbage bytes (confirmed live: caused an agent's flag-detection regex
to fire on nonsense — see the regex fix in `agent/graph.py`'s `FLAG_PATTERN`).

To read it properly (pure Python, no PDF library needed):

```python
import re, zlib

def decode_pdf_text(pdf_bytes: bytes) -> list[bytes]:
    """Extract and decompress every FlateDecode stream in a PDF."""
    streams = []
    for m in re.finditer(rb'stream\r?\n(.*?)\r?\nendstream', pdf_bytes, re.DOTALL):
        try:
            streams.append(zlib.decompress(m.group(1)))
        except Exception:
            continue
    return streams

def decode_tj_with_cmap(content_stream: bytes, cmap_stream: bytes) -> str:
    """Map a content stream's <hex> Tj glyph codes back to real characters using the
    ToUnicode CMap's beginbfchar/beginbfrange tables."""
    bfchar = {m.group(1).decode(): m.group(2).decode()
              for m in re.finditer(rb'<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>', cmap_stream)}
    bfrange = [(int(m.group(1), 16), int(m.group(2), 16), int(m.group(3), 16))
               for m in re.finditer(rb'<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>', cmap_stream)]
    def lookup(code):
        h = f'{code:04X}'
        if h in bfchar:
            return chr(int(bfchar[h], 16))
        for lo, hi, start in bfrange:
            if lo <= code <= hi:
                return chr(start + (code - lo))
        return '?'
    out = []
    for m in re.finditer(rb'<([0-9A-Fa-f]+)>\s*Tj', content_stream):
        hexstr = m.group(1).decode()
        codes = [int(hexstr[i:i+4], 16) for i in range(0, len(hexstr), 4)]
        out.append(''.join(lookup(c) for c in codes))
    return ' '.join(out)
```

This is how a rendered page's real text ("Dont try to trick me!") was recovered from an
otherwise-unreadable compressed PDF stream during a live HTB run.

## Common validation patterns and how they get bypassed

- **Scheme blocklist on the raw `url` string** (e.g. `if url.startswith("file://"): reject`) —
  fast, string-only check, easy to spot because it responds *instantly* compared to a real
  network attempt. Bypasses: alternate `file:` forms (`file:/etc/passwd`, `File://`,
  `FILE:///etc/passwd`, URL-encoding the scheme), or find a *different* injection point that
  reaches the same renderer without going through this specific check (see below).
- **DNS-based SSRF guard** (resolve the hostname, check the resolved IP against a private-range
  blocklist before allowing navigation) — the tell is a `dnspython`/similar DNS library in the
  app's dependencies. Classic bypasses: DNS rebinding (resolve to a public IP for the check,
  then to a private IP for the actual fetch — needs a DNS server you control with a very short
  TTL), or non-obvious IP representations that still resolve correctly in a browser but may not
  match a naive blocklist regex (decimal integer IP: `http://2130706433/` = `127.0.0.1`, octal:
  `http://0177.0.0.1/`, IPv6-mapped: `http://[::ffff:127.0.0.1]/`).
- **The `url` parameter isn't the only injection point.** If a *second* user-controlled field
  (e.g. a `name` shown in the rendered page's text) gets embedded unescaped into the HTML the
  browser renders, HTML/attribute injection there (`<iframe src="file:///flag">`) can reach
  the same powerful renderer while completely bypassing whatever validation was written
  specifically for the `url` parameter — the validation logic was never designed to think about
  a second reflection point.

## Real gotcha: this backend is expensive per-request — don't hammer it

A real headless Chrome instance per request is heavy. Repeated rapid-fire testing (many
`fetch_url` calls in quick succession, especially across two full agent runs plus manual
probing) can genuinely degrade or exhaust the target's renderer pool/rate limits — confirmed
live: after enough requests, even the plain homepage (previously instant) started timing out.
This is a real, valuable signal to recognize and act on, not just bad luck: **back off** rather
than retrying blindly, the same way the harness's own `route_after_observe` loop-detection is
designed to stop hammering a live target after repeated identical calls. Give the target time
to recover before testing further.

## Source

HackTheBox "Offlinea" (Web) — session in progress, not yet solved. Stack confirmed from a
provided `requirements.txt`: `flask`, `selenium`, `pyjwt`, `requests`, `dnspython`. See
[[jwt-secret-and-dns-ssrf-hints]] for how the `pyjwt`/`dnspython` presence reframes the likely
intended attack path away from plain `file://`/`http://` SSRF. Full session write-up in
`evals/practice_runs.md`.

## Related

- [[jwt-secret-and-dns-ssrf-hints]]
- [[zip-slip-symlink-bypass]] — another "the file-handling/rendering pipeline is more powerful
  than the validation in front of it" pattern
