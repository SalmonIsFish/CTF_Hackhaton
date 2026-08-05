import os
import re

from langchain_core.tools import tool

# Known flag prefixes only (not a bare \w+, which false-matches garbage in binary/compressed
# content -- confirmed live: a PDF response's raw deflate stream happened to contain bytes
# matching \w+\{...\}, which the old bare pattern accepted as a "flag"). Length-capped so one
# stray '{' followed by a long run of non-'}' bytes in binary data can't produce a runaway
# match either. "htb" included alongside flag/ctf since real captured flags this project has
# seen use that format (e.g. HTB{...}), which the old flag/ctf-only pattern would have missed
# entirely. "picoctf" added after a real live run against picoCTF's "Old Session" challenge:
# the agent found and correctly identified picoCTF{s3t_s3ss10n_3xp1rat10n5_51c526ab}, but this
# pattern (and agent/graph.py's flag-exit check, which imports this exact constant) missed it
# entirely -- a bare "ctf" alternative can never match inside "picoCTF{" because \b requires a
# word-boundary immediately before "ctf", and "pico" sits directly against it with no boundary
# in between. agent/graph.py's observe() imports build_flag_pattern/FLAG_PATTERN from here
# rather than keeping its own copy, so the two can't drift out of sync the way they did before.
DEFAULT_PREFIXES = ("flag", "ctf", "htb", "picoctf")

# Sanitize each candidate prefix to word characters only: it's spliced straight into a regex
# alternation, so a stray '(', '{', '|', etc. in a mis-set FLAG_PREFIXES value would otherwise
# either break re.compile outright or (worse) silently change what the pattern matches. Dropping
# non-\w chars keeps a fat-fingered env value from taking the whole flag-detection path down on
# competition day.
_PREFIX_SANITIZE_RE = re.compile(r"[^A-Za-z0-9_]")


def _parse_prefixes(raw: str | None) -> list[str]:
    """Turn a comma-separated FLAG_PREFIXES value into a clean, deduped, lowercased prefix list.
    Empty/None -> []. Each entry is stripped to word characters (see _PREFIX_SANITIZE_RE)."""
    if not raw:
        return []
    out: list[str] = []
    for token in raw.split(","):
        cleaned = _PREFIX_SANITIZE_RE.sub("", token.strip()).lower()
        if cleaned and cleaned not in out:
            out.append(cleaned)
    return out


def build_flag_pattern(extra_prefixes=None) -> re.Pattern:
    """Build the flag-detection regex for DEFAULT_PREFIXES plus any extra prefixes (a comma-
    separated string, or an iterable of strings). The shape is unchanged from the long-standing
    hardcoded pattern -- \\b(?:...)\\{[^{}]{1,300}\\} -- preserving both the length cap and the
    [^{}] guard that stopped a deflate stream's stray '{...}' from being accepted as a flag. Extra
    prefixes are additive: the four defaults always match, so an unset/empty FLAG_PREFIXES yields
    a pattern byte-for-byte equivalent to the original.

    Exists so the actual competition flag format (often custom, e.g. HACKHATON{...}) can be added
    the moment it's known, via the FLAG_PREFIXES env var or a per-request override, without
    editing code -- agent/graph.py's observe() early-exit and this module's find_flag_pattern
    tool both go through it, so they stay in lockstep."""
    if isinstance(extra_prefixes, str):
        extra = _parse_prefixes(extra_prefixes)
    elif extra_prefixes:
        extra = _parse_prefixes(",".join(str(p) for p in extra_prefixes))
    else:
        extra = []
    prefixes: list[str] = list(DEFAULT_PREFIXES)
    for p in extra:
        if p not in prefixes:
            prefixes.append(p)
    alternation = "|".join(prefixes)
    return re.compile(rf"\b(?:{alternation})\{{[^{{}}]{{1,300}}\}}", re.IGNORECASE)


# Module-level default, built once from the environment at import time. observe() uses this unless
# a run supplies its own per-request prefixes (see AgentState.flag_prefixes in agent/graph.py).
FLAG_PATTERN = build_flag_pattern(os.getenv("FLAG_PREFIXES"))

# Braced content that's clearly an unfilled template rather than a real, computed flag --
# confirmed live: a picoCTF "Shared Secrets" challenge's OWN generator script (encryption.py)
# literally contained `flag = b"picoCTF{...}"` as a placeholder (the real flag gets substituted
# in only when the challenge instance is built). [^{}]{1,300} places no requirement on the
# content being real, only on it not containing another brace, so it matched "picoCTF{...}"
# straight out of the raw source. This isn't a hypothetical edge case: local-file tools
# (read_local_file, extract_metadata, etc.) routinely return a challenge's own source/generator
# code, which very often contains exactly this kind of unfilled template -- and once matched,
# this ended the run immediately (observe()'s flag-detection triggers early-exit) with a
# fabricated "flag" that was never actually computed, before the agent ever found or read the
# real data file the script writes its output to.
_PLACEHOLDER_TOKENS = frozenset({
    "...", "..", "???", "??", "?", "todo", "fixme", "redacted", "xxx", "tbd",
    "placeholder", "your_flag_here", "flag_here", "insert_flag_here", "n/a", "none", "null",
})


def _looks_like_placeholder(full_match: str) -> bool:
    """True if the content inside a flag{...}-shaped match's braces looks like an unfilled
    template rather than a real, computed flag (no actual alphanumeric content at all, e.g.
    just "..." or "???", or an exact match against a known placeholder token like "REDACTED")."""
    inner = full_match.partition("{")[2]
    if inner.endswith("}"):
        inner = inner[:-1]
    stripped = inner.strip()
    if not stripped or not re.search(r"[A-Za-z0-9]", stripped):
        return True
    return stripped.lower() in _PLACEHOLDER_TOKENS


@tool
def find_flag_pattern(text: str) -> str:
    """Search text for CTF-style flag patterns such as flag{...}, CTF{...}, HTB{...}, or
    picoCTF{...} (plus any extra prefixes configured via the FLAG_PREFIXES env var). Returns
    every match found, or a message if none are present. Skips matches that look like an
    unfilled template (e.g. picoCTF{...} or picoCTF{???} sitting in a challenge's own source
    code) rather than a real flag -- if you see one of those in a file's raw content, that's a
    signal the real value lives somewhere else, not a solved answer."""
    matches = [m for m in FLAG_PATTERN.findall(text) if not _looks_like_placeholder(m)]
    if not matches:
        return "No flag pattern found."
    return "\n".join(matches)
