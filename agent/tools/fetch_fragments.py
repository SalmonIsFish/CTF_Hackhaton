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

    Never raises -- a fetch failure or unmatched pattern on any path aborts immediately and
    reports which path failed and how many fragments were already found, rather than silently
    joining a partial or wrong set."""
    if pattern and patterns:
        return "Provide either pattern or patterns, not both."
    if not pattern and not patterns:
        return "Provide either pattern (one regex for every path) or patterns (one regex per path, newline-separated)."

    paths_list = [p.strip().lstrip("/") for p in paths.split(",") if p.strip()]
    if not paths_list:
        return "paths must contain at least one path."
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
    for path, compiled in zip(paths_list, compiled_list):
        url = f"{base}/{path}"
        try:
            response = requests.get(url, timeout=FETCH_TIMEOUT_SECONDS)
        except requests.RequestException as exc:
            return (
                f"Request to {url} failed: {exc} (aborted after {len(fragments)} of "
                f"{len(paths_list)} fragments)"
            )
        body = decode_response_body(response)
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
        details.append(f"{path}: {fragment!r}")

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
