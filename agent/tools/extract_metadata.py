"""Pulls embedded metadata out of an image or PDF file -- EXIF tags plus format-specific
info-dict entries for images (e.g. PNG tEXt/iTXt/zTXt text chunks, a common place CTF forensics
challenges stash a flag directly in plain text), and the /Info dict plus any embedded
attachments for PDFs (another common hiding spot: a flag in the "Author"/"Subject"/"Keywords"
field, or a whole attached file). Uses Pillow for images (already an installed dependency,
pulled in transitively) and pypdf for PDFs (added specifically for this -- lightweight,
pure-Python, no system dependency like poppler).
"""
from typing import Any

from langchain_core.tools import tool
from PIL import ExifTags, Image

from agent.tools._local_file_check import check_local_file


def _extract_pdf_metadata(file_path: str) -> str:
    from pypdf import PdfReader
    from pypdf.errors import PdfReadError

    try:
        reader = PdfReader(file_path)
    except FileNotFoundError:
        return f"No such file: {file_path}"
    except PdfReadError as exc:
        return f"Could not open {file_path} as a PDF: {exc}"

    lines = [f"format: PDF", f"pages: {len(reader.pages)}"]

    info = reader.metadata
    if info:
        lines.append("info:")
        for key, value in info.items():
            lines.append(f"  {key}: {value}")

    try:
        attachments = reader.attachments
    except Exception:
        attachments = {}
    if attachments:
        lines.append("attachments:")
        for name, contents in attachments.items():
            sizes = ", ".join(str(len(c)) for c in contents)
            lines.append(f"  {name} ({sizes} bytes)")

    if len(lines) == 2:
        lines.append("No /Info metadata or attachments found.")
    return "\n".join(lines)


@tool
def extract_metadata(file_path: str) -> str:
    """Read embedded metadata out of a local image or PDF file. For images: EXIF tags
    (camera/software/GPS/timestamps, present in JPEG/TIFF) and any format-specific info-dict
    entries Pillow exposes (e.g. PNG tEXt/iTXt/zTXt text chunks -- a common place CTF forensics
    challenges hide a flag directly). For PDFs: the document's /Info dictionary (Title, Author,
    Subject, Keywords, Producer, etc. -- another common flag-hiding spot) and a list of any
    embedded file attachments. file_path is a local path the agent already has access to (e.g. a
    challenge file dropped alongside the prompt), not a URL -- fetch_url first if the file needs
    downloading. Returns a human-readable report, or a descriptive message if the file doesn't
    exist, isn't a recognizable image/PDF, or carries no metadata. Never raises. If given a
    directory instead of a file, lists the directory's contents rather than just saying "no such
    file" -- the directory is real, it just needs narrowing to a specific file. Use
    read_local_file instead for any other file type (plain text, encrypted/.enc blobs, archives)."""
    check_error = check_local_file(file_path)
    if check_error:
        return check_error

    try:
        with open(file_path, "rb") as f:
            header = f.read(5)
    except OSError as exc:
        return f"Could not read {file_path}: {exc}"

    if header == b"%PDF-":
        return _extract_pdf_metadata(file_path)

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
