"""Pulls embedded metadata out of an image file -- EXIF tags plus format-specific info-dict
entries (e.g. PNG tEXt/iTXt/zTXt text chunks, a common place CTF forensics challenges stash a
flag directly in plain text). Uses Pillow only (already an installed dependency, pulled in
transitively) rather than adding exifread as a new one -- exifread only reads EXIF, so it would
miss PNG text chunks entirely, while Pillow's Image.info dict already covers both.
"""
from typing import Any

from langchain_core.tools import tool
from PIL import ExifTags, Image


@tool
def extract_metadata(file_path: str) -> str:
    """Read embedded metadata out of a local image file: EXIF tags (camera/software/GPS/
    timestamps, present in JPEG/TIFF) and any format-specific info-dict entries Pillow exposes
    (e.g. PNG tEXt/iTXt/zTXt text chunks -- a common place CTF forensics challenges hide a flag
    directly). file_path is a local path the agent already has access to (e.g. a challenge file
    dropped alongside the prompt), not a URL -- fetch_url first if the file needs downloading.
    Returns a human-readable report, or a descriptive message if the file doesn't exist, isn't a
    recognizable image format, or carries no metadata. Never raises."""
    try:
        image = Image.open(file_path)
    except FileNotFoundError:
        return f"No such file: {file_path}"
    except Exception as exc:
        return f"Could not open {file_path} as an image: {exc}"

    with image:
        lines = [
            f"format: {image.format}",
            f"mode: {image.mode}",
            f"size: {image.size[0]}x{image.size[1]}",
        ]

        info_items: dict[str, Any] = {
            key: value
            for key, value in image.info.items()
            if isinstance(value, (str, bytes, int, float))
        }
        if info_items:
            lines.append("info:")
            for key, value in info_items.items():
                if isinstance(value, bytes):
                    value = value.decode("utf-8", errors="replace")
                lines.append(f"  {key}: {value}")

        try:
            exif = image.getexif()
        except Exception:
            exif = None

        if exif:
            lines.append("exif:")
            for tag_id, value in exif.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                lines.append(f"  {tag}: {value}")

    if len(lines) == 3:
        lines.append("No EXIF or info-dict metadata found.")
    return "\n".join(lines)
