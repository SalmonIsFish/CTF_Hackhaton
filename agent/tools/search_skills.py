from pathlib import Path

from langchain_core.tools import tool

SKILLS_DIR = Path(__file__).resolve().parent.parent.parent / ".agents" / "skills"
CONTEXT_LINES = 2
MAX_HITS = 8


@tool
def search_skills(query: str) -> str:
    """Search the installed CTF technique-reference skill packs (.agents/skills/**/*.md,
    covering offensive categories like web/crypto/pwn/reverse/forensics/malware/osint/misc/ai-ml
    and defensive/blue-team ones like incident response, SIEM detection engineering, and SOAR
    playbooks) for a query string (case-insensitive substring match). Returns each matching file
    with the matching line and surrounding context, capped to the most relevant hits, or a
    message if nothing matches."""
    if not query.strip():
        return "Empty query."
    if not SKILLS_DIR.is_dir():
        return f"Skills directory not found: {SKILLS_DIR}"

    needle = query.lower()
    hits = []
    for path in sorted(SKILLS_DIR.rglob("*.md")):
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        matched_indices = [i for i, line in enumerate(lines) if needle in line.lower()]
        if not matched_indices:
            continue

        rel_name = path.relative_to(SKILLS_DIR).as_posix()
        snippets = []
        for i in matched_indices:
            start = max(0, i - CONTEXT_LINES)
            end = min(len(lines), i + CONTEXT_LINES + 1)
            context = "\n".join(lines[start:end])
            snippets.append(f"  line {i + 1}:\n{context}")
        hits.append((len(matched_indices), f"{rel_name}:\n" + "\n\n".join(snippets)))

    if not hits:
        return f"No matches for '{query}' in installed skills."

    hits.sort(key=lambda h: h[0], reverse=True)
    return "\n\n".join(text for _, text in hits[:MAX_HITS])
