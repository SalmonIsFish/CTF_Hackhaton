"""Shared local-file-path validation, used by every tool that reads a specific local file
(read_local_file, extract_metadata, extract_hidden_key, rsa_decrypt_file) instead of each
reimplementing the same bare os.path.isfile() check.

Exists to fix a real, confirmed failure: a challenge prompt gave the agent a directory path
(not individual filenames, since it's natural to just say "the files are in this folder"). The
model reasonably tried that path directly, got a bare "No such file" from a naive isfile()
check, and concluded the challenge's files didn't exist at all -- so it gave up on local files
entirely and fell back to web_search, lifting a flag from a public writeup of a DIFFERENT
instance of the same challenge (confirmed wrong -- picoCTF randomizes flags per deployment). A
directory isn't "no such file"; it's a real, existing path that just needs narrowing to a
specific file inside it, and the fix is to say so and list what's there.
"""
import os
from typing import Optional


def check_local_file(path: str) -> Optional[str]:
    """Returns an error message string if `path` isn't a usable single file, or None if it's
    fine to proceed. Distinguishes "doesn't exist at all" from "exists but is a directory" --
    the latter lists the directory's contents so the caller can immediately retry with a
    specific file instead of wasting a round-trip guessing why the first attempt failed."""
    if os.path.isfile(path):
        return None
    if os.path.isdir(path):
        try:
            entries = sorted(os.listdir(path))
        except OSError as exc:
            return f"{path} is a directory, but its contents could not be listed: {exc}"
        if not entries:
            return f"{path} is a directory, but it's empty."
        listing = ", ".join(entries)
        return (
            f"{path} is a directory, not a file -- call this tool again with the full path to "
            f"a specific file inside it. Files/folders here: {listing}"
        )
    return f"No such file: {path}"
