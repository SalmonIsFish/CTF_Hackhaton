import re

from langchain_core.tools import tool

FLAG_PATTERN = re.compile(r"(?:flag|ctf)\{[^{}]+\}", re.IGNORECASE)


@tool
def find_flag_pattern(text: str) -> str:
    """Search text for CTF-style flag patterns such as flag{...} or CTF{...}.
    Returns every match found, or a message if none are present."""
    matches = FLAG_PATTERN.findall(text)
    if not matches:
        return "No flag pattern found."
    return "\n".join(matches)
