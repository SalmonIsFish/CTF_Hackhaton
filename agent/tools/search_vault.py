from pathlib import Path

from langchain_core.tools import tool

VAULT_DIR = Path(__file__).resolve().parent.parent.parent / "vault"
CONTEXT_LINES = 2


@tool
def search_vault(query: str) -> str:
    """Search all .md files under ./vault/ for a query string (case-insensitive substring match).
    Returns each matching file with the matching line and surrounding context lines,
    or a message if no .md files match."""
    if not query.strip():
        return "Empty query."
    if not VAULT_DIR.is_dir():
        return f"Vault directory not found: {VAULT_DIR}"

    needle = query.lower()
    hits = []
    for path in sorted(VAULT_DIR.rglob("*.md")):
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        matched_indices = [i for i, line in enumerate(lines) if needle in line.lower()]
        if not matched_indices:
            continue

        rel_name = path.relative_to(VAULT_DIR).as_posix()
        snippets = []
        for i in matched_indices:
            start = max(0, i - CONTEXT_LINES)
            end = min(len(lines), i + CONTEXT_LINES + 1)
            context = "\n".join(lines[start:end])
            snippets.append(f"  line {i + 1}:\n{context}")
        hits.append(f"{rel_name}:\n" + "\n\n".join(snippets))

    if not hits:
        return f"No matches for '{query}' in vault."
    return "\n\n".join(hits)
