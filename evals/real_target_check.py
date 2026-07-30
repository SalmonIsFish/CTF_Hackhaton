"""One-off, manually-run check against a REAL internet target — scanme.nmap.org, nmap's own
public test box (see https://nmap.org/book/legal-issues.html: they explicitly host it for
scanning practice). Deliberately NOT part of evals/test_tools_smoke.py or anything that runs
automatically on every merge — every other eval in this repo is fully offline/local; this one
depends on real internet access and someone else's public infrastructure, so it stays opt-in.

Kept respectful on purpose: a single run, a short 3-port candidate list (not a wide sweep),
through port_scan's normal per-port timeouts — not a loop, not repeated automated hits.

Usage:
    python -m evals.real_target_check
"""
import sys

from langchain_core.messages import AIMessage, HumanMessage

from agent.graph import MAX_STEPS, build_graph, message_text

TARGET_HOST = "scanme.nmap.org"
CANDIDATE_PORTS = "22,80,9929"  # 22 and 80 are documented open; 9929 (ncat) is a known extra


def main() -> None:
    prompt = (
        f"{TARGET_HOST} is a public test target nmap's own project hosts specifically for "
        "scanning practice — it's fine to probe it lightly. Scan ports "
        f"{CANDIDATE_PORTS} on it and report what's open and any service/version banner you "
        "find. Keep it to this one scan, don't repeat it."
    )

    print(f"=== Real-target check: {TARGET_HOST} ===\n")
    app = build_graph()
    result = app.invoke(
        {"messages": [HumanMessage(content=prompt)], "steps": 0, "flag": None, "category": None},
        config={"recursion_limit": MAX_STEPS * 4 + 2},
    )

    tool_calls_made = [
        call["name"]
        for m in result["messages"]
        if isinstance(m, AIMessage)
        for call in (m.tool_calls or [])
    ]
    print("tool calls:", tool_calls_made)
    print("category:", result["category"])
    print("steps:", result["steps"])
    print("\n--- final answer ---")
    print(message_text(result["messages"][-1]))

    if "port_scan" not in tool_calls_made:
        sys.exit("port_scan was not called — check the prompt/model before trusting this run")


if __name__ == "__main__":
    main()
