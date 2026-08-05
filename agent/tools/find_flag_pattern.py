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


@tool
def find_flag_pattern(text: str) -> str:
    """Search text for CTF-style flag patterns such as flag{...}, CTF{...}, HTB{...}, or
    picoCTF{...} (plus any extra prefixes configured via the FLAG_PREFIXES env var). Returns
    every match found, or a message if none are present."""
    matches = FLAG_PATTERN.findall(text)
    if not matches:
        return "No flag pattern found."
    return "\n".join(matches)
