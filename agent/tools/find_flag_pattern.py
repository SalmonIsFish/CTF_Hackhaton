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
# in between. agent/graph.py's observe() imports this exact pattern rather than keeping its own
# copy, so the two can't drift out of sync the way they did before this fix.
FLAG_PATTERN = re.compile(r"\b(?:flag|ctf|htb|picoctf)\{[^{}]{1,300}\}", re.IGNORECASE)


@tool
def find_flag_pattern(text: str) -> str:
    """Search text for CTF-style flag patterns such as flag{...}, CTF{...}, HTB{...}, or
    picoCTF{...}. Returns every match found, or a message if none are present."""
    matches = FLAG_PATTERN.findall(text)
    if not matches:
        return "No flag pattern found."
    return "\n".join(matches)
