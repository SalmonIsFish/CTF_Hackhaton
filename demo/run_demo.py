"""One-command demo runner: solve a seeded (or given) challenge end to end.

Usage:
    python -m demo.run_demo
    python -m demo.run_demo path/to/other_challenge.txt

Exit code is 0 if a flag was found, 1 otherwise (useful for a rehearsal script
to catch a regression before demo day, not just eyeballing the output).
"""
import os
import sys
from pathlib import Path

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from agent.graph import MAX_STEPS, build_graph, message_text

DEFAULT_CHALLENGE = Path(__file__).resolve().parent / "response_headers.txt"


def load_challenge(path: Path) -> str:
    if not path.is_file():
        sys.exit(f"Challenge file not found: {path}")
    return path.read_text(encoding="utf-8")


def preflight() -> None:
    if not os.getenv("GOOGLE_API_KEY"):
        sys.exit(
            "GOOGLE_API_KEY is not set. Copy .env.example to .env and fill it in "
            "before running the demo — don't discover this mid-presentation."
        )


def main() -> None:
    preflight()
    challenge_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_CHALLENGE
    artifact = load_challenge(challenge_path)

    prompt = (
        "A teammate captured this while poking at a web challenge. Find the flag.\n\n"
        + artifact
    )

    print(f"=== Solving: {challenge_path.name} ===\n")
    app = build_graph()
    result = app.invoke(
        {
            "messages": [HumanMessage(content=prompt)],
            "steps": 0,
            "flag": None,
            "category": None,
        },
        config={"recursion_limit": MAX_STEPS * 4 + 2},
    )

    print("--- Tool calls made ---")
    for m in result["messages"]:
        if isinstance(m, AIMessage) and m.tool_calls:
            for call in m.tool_calls:
                print(f"  {call['name']}({call['args']})")
        elif isinstance(m, ToolMessage):
            preview = m.content if len(m.content) <= 120 else m.content[:117] + "..."
            print(f"    -> {preview}")

    # A flag match ends the loop right after the tool call that produced it (by
    # design — see agent/graph.py's observe(), and it's what makes case 2/3 exit
    # early instead of burning the full MAX_STEPS budget), so the last message is
    # often the raw tool result, not a model-authored sentence. Only show the
    # model's own prose when there wasn't a flag to short-circuit on.
    if not result["flag"]:
        print("\n--- Final answer ---")
        print(message_text(result["messages"][-1]))

    print(f"\nCategory : {result['category']}")
    print(f"Steps    : {result['steps']}")
    print(f"Flag     : {result['flag'] or '(not found)'}")

    if not result["flag"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
