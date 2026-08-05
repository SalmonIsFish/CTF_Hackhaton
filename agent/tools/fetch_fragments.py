"""Fetch and join fragments split across multiple pages on the same host, without ever making
the model manually retype or reassemble the exact fragment text by hand.

Exists specifically to close a real, observed, and repeat-confirmed failure mode: a picoCTF
"Includes" challenge splits its flag across two included files (each holding half in a comment,
labeled 1of2/2of2). The model correctly read both real fragments out of two separate fetch_url
results, but introduced a stray space concatenating them by hand in its final answer. A
system-prompt instruction telling it to concatenate precisely was added and was NOT enough to
stop this from recurring on a re-run (see evals/practice_runs.md's "Includes" write-up, both
attempts) -- the same lesson keyed_decode.py already learned for manual cipher arithmetic:
prompting alone doesn't reliably fix a manual-reassembly habit, a code-level fix does.
Extracting each fragment via a server-side regex and joining them in code, in one call, removes
the manual-reassembly step entirely rather than just warning against it again.

A second, related failure mode (picoCTF's "Scavenger Hunt", a 5-file version of the same split
pattern) showed a single shared `pattern` isn't always enough: each file used a genuinely
different wrapper around its fragment (an HTML comment, a CSS block comment, two different
shell-style '#' line comments, and one file with no comment delimiter at all, just a "Part N:"
label). A regex written to bound the HTML comment's fragment relied on a literal '}' as its stop
condition, but that file's own comment (<!-- ...picoCTF{t --> ) never contains a '}' at all -- so
the match ran to the end of that file's entire body instead of stopping at the real fragment,
because the *next* '}' anywhere was in a completely different file's response. `patterns` (plural,
one regex per path) exists so each file's own wrapper can be matched precisely instead of forcing
one pattern to (mis)handle every style at once.

A third failure mode (picoCTF's "dont-use-client-side"/"Never trust the client") showed the split
doesn't always come from multiple files at all -- sometimes ALL the fragments live in ONE page,
as separate substring/index checks in some client-side JS (e.g. checkpass.substring(0,4)=='pico',
checkpass.substring(24,28)=='eb02', ...). The model correctly identified every individual
fragment from the real page, but hand-typing all 8 of them out in order in its own final answer
introduced a spurious extra character partway through -- the same manual-reassembly failure class
as the two bugs above, just with more fragments and no separate URLs to point a `paths` list at.
Repeating the SAME path in `paths` (once per fragment, with a distinct entry in `patterns` for
each) handles this correctly with the existing interface -- and the response for each repeated
path is fetched only once and reused, not re-requested per repetition.
"""
import re
from typing import Optional
from urllib.parse import urlparse

import requests
from langchain_core.tools import tool

from agent.tools._response_text import decode_response_body

FETCH_TIMEOUT_SECONDS = 8.0
MAX_PATHS = 10
MAX_FRAGMENT_CHARS = 512


@tool
def fetch_and_join_fragments(
    base_url: str, paths: str, group: int = 1,
    pattern: Optional[str] = None, patterns: Optional[str] = None,
) -> str:
    """Fetch multiple pages under the same base_url (e.g. base_url="http://host:port", paths=
    "style.css,script.js") IN THE GIVEN ORDER, extract a fragment from each one's response body,
    strip surrounding whitespace off each fragment, and concatenate them directly with no
    separator -- all in one call, so the exact fragment text never has to pass through your own
    final answer. Use this whenever a flag (or any other exact string) is split across multiple
    files/responses that need to be joined verbatim -- manually retyping and joining fragments
    yourself is unreliable and has produced a wrong answer before (a stray space introduced
    between two otherwise-correct fragments, on more than one attempt).

    To include the root page itself (base_url with no extra path) as one of the fragments, use an
    EMPTY entry in paths at that position, e.g. paths=",style.css,script.js" for 3 fragments where
    the first comes from base_url directly -- do not omit it or leave it out expecting it to be
    implied; an empty entry is meaningful and preserved, not dropped. If you provide `patterns`,
    it must have exactly one entry per path INCLUDING any empty ones -- count paths by commas, not
    by how many "real" filenames you wrote.

    Provide EITHER pattern (a single regex, capture group `group`, applied to every path in
    turn -- fine when every file wraps its fragment the same way, e.g. r'(?:/\\*|//)\\s*(.*?)\\s*
    (?:\\*/|$)' matches both a CSS/JS block comment and a line comment in one pattern) OR patterns
    (one regex per path, newline-separated, in the SAME ORDER as paths -- required when different
    files use genuinely different wrappers, e.g. an HTML file's "<!-- ... -->" vs a CSS file's
    "/* ... */" vs a plain-text file with no comment delimiter around its fragment at all).
    Do not try to force one pattern to bound every style at once with something like
    r'picoCTF\\{[^}]*' and no real closing anchor -- each path is matched only against its OWN
    response, so if that file's own content never contains the character your pattern relies on
    as a stop condition (confirmed live: an HTML comment with no '}' inside it at all), the match
    can run to the end of that file's entire body instead of stopping at the real fragment,
    producing a garbled result -- write a pattern with a real closing anchor specific to that
    file's own wrapper (e.g. end the HTML case at '-->', not at a '}' that isn't there).

    If every fragment actually lives on ONE page (e.g. several separate substring/index checks in
    some client-side JS, not separate files), repeat that same path once per fragment in `paths`
    (e.g. "index.html,index.html,index.html") and give each repetition its own capturing pattern
    in `patterns`, in the FINAL flag order (not necessarily the order the checks appear in the
    page's own source, which is often deliberately shuffled) -- do not read the fragments off the
    page and retype them yourself, the same manual-reassembly mistake that motivated this tool in
    the first place has happened with many fragments from one page too. A repeated path is only
    actually fetched once and the response reused for each of its patterns, not re-requested.

    Never raises -- a fetch failure or unmatched pattern on any path aborts immediately and
    reports which path failed and how many fragments were already found, rather than silently
    joining a partial or wrong set."""
    if pattern and patterns:
        return "Provide either pattern or patterns, not both."
    if not pattern and not patterns:
        return "Provide either pattern (one regex for every path) or patterns (one regex per path, newline-separated)."
    if not paths.strip():
        return "paths must not be empty."

    # An empty entry between commas (e.g. ",mycss.css,myjs.js") means "the root page itself, no
    # extra path segment" -- a real, observed confusion otherwise: a model tried exactly that
    # leading-empty-entry convention expecting 3 paths (root + 2 files), but a plain "if p.strip()"
    # filter used to silently drop it, shrinking the list to 2 without any signal that happened.
    # patterns (correctly sized for 3) then failed the length check against the silently-shrunk
    # list, and nothing about that error pointed at the actual problem (the dropped empty entry),
    # so repeated retries only ever adjusted regex content, never the real cause. Empty entries are
    # now preserved and treated as "fetch base_url with no path appended" instead of being dropped.
    paths_list = [p.strip().lstrip("/") for p in paths.split(",")]
    if len(paths_list) > MAX_PATHS:
        return f"Too many paths (max {MAX_PATHS})."

    if patterns:
        raw_patterns = patterns.split("\n")
        if len(raw_patterns) != len(paths_list):
            return (
                f"patterns has {len(raw_patterns)} entries but paths has {len(paths_list)} -- "
                "they must match 1:1, one pattern per path, newline-separated."
            )
    else:
        raw_patterns = [pattern] * len(paths_list)

    compiled_list = []
    for raw in raw_patterns:
        try:
            compiled_list.append(re.compile(raw, re.MULTILINE))
        except re.error as exc:
            return f"Invalid pattern {raw!r}: {exc}"

    base = base_url.rstrip("/")
    fragments = []
    details = []
    # Keyed by url, not path, so a repeated path (the "all fragments on one page" case -- see
    # module docstring) is fetched once and its body reused, rather than re-requesting the same
    # page once per fragment.
    body_cache: dict = {}
    for path, compiled in zip(paths_list, compiled_list):
        url = f"{base}/{path}"
        if url in body_cache:
            body = body_cache[url]
        else:
            try:
                response = requests.get(url, timeout=FETCH_TIMEOUT_SECONDS)
            except requests.RequestException as exc:
                return (
                    f"Request to {url} failed: {exc} (aborted after {len(fragments)} of "
                    f"{len(paths_list)} fragments)"
                )
            body = decode_response_body(response)
            body_cache[url] = body
        match = compiled.search(body)
        if not match:
            return (
                f"Pattern {compiled.pattern!r} did not match anything in {url} (aborted after "
                f"{len(fragments)} of {len(paths_list)} fragments)."
            )
        try:
            fragment: Optional[str] = match.group(group)
        except IndexError:
            return f"Pattern for {url} has no capture group {group}."
        if fragment is None:
            return f"Capture group {group} did not participate in the match for {url}."
        fragment = fragment.strip()
        if len(fragment) > MAX_FRAGMENT_CHARS:
            return (
                f"Fragment from {url} too long (max {MAX_FRAGMENT_CHARS} chars) -- likely means "
                "the pattern for this path isn't correctly bounded (missing a real closing "
                "anchor for this file's own comment/wrapper style)."
            )
        fragments.append(fragment)
        details.append(f"{path or '(base_url root)'}: {fragment!r}")

    joined = "".join(fragments)
    host = urlparse(base).hostname or base
    # "Joined: ..." deliberately comes FIRST, before the per-fragment debug listing -- a real,
    # confirmed bug: agent/graph.py's observe() (and find_flag_pattern's FLAG_PATTERN) do a
    # left-to-right regex search over the whole tool result for the first flag{...}-shaped span.
    # When a fragment itself starts with "picoCTF{" (the common case: it's the first chunk of
    # the real flag) and the debug listing below is printed BEFORE the joined result, the regex
    # greedily matches from that accidental "picoCTF{" all the way to the next stray "}" -- which
    # can land much later, inside a different fragment's repr -- producing a completely wrong
    # "flag" built out of raw debug text instead of the correctly joined one. Putting the real
    # answer first means the regex matches the correct flag immediately and never reaches the
    # debug section at all.
    payload = f"Joined: {joined}\n\nFragments (in order):\n" + "\n".join(details)
    return f'<untrusted_data source="fetch_and_join_fragments:{host}">\n{payload}\n</untrusted_data>'
