import re
from typing import Annotated, Optional, Sequence, TypedDict

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages

from agent.model_router import get_model
from agent.tools.find_flag_pattern import find_flag_pattern
from agent.tools.identify_and_decode import identify_and_decode
from agent.tools.search_skills import search_skills
from agent.tools.search_vault import search_vault

MAX_STEPS = 15
FLAG_PATTERN = re.compile(r"\w+\{[^{}]+\}")


def message_text(message: BaseMessage) -> str:
    """Extract plain text from a message's content, whether it's a bare string
    (the common case) or a list of content blocks (some Gemini responses attach
    thought-signature metadata, making content a list of {'type': 'text', ...} dicts)."""
    content = message.content
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            block.get("text", "") for block in content
            if isinstance(block, dict) and block.get("type") == "text"
        )
    return str(content)

# Sub-agent routing: maps a triage category to the installed skill-pack directory
# name(s) under .agents/skills/ that hold the relevant technique reference notes.
# "general" is the fallback for prompts that aren't a specific CTF category (or
# aren't a CTF challenge at all, e.g. a plain echo test).
CATEGORY_SKILL_DIRS = {
    "web": ["ctf-web"],
    "crypto": ["ctf-crypto"],
    "pwn": ["ctf-pwn"],
    "reverse": ["ctf-reverse"],
    "forensics": ["ctf-forensics"],
    "malware": ["ctf-malware"],
    "osint": ["ctf-osint"],
    "misc": ["ctf-misc"],
    "ai-ml": ["ctf-ai-ml"],
    "blue-team": ["ir-report-builder", "siem-detection-engineer", "soar-playbook-builder"],
    "general": [],
}

TRIAGE_PROMPT = SystemMessage(
    content=(
        "You triage CTF (and adjacent security) prompts into exactly one category. "
        f"Reply with only the category word, nothing else. Categories: {', '.join(CATEGORY_SKILL_DIRS)}.\n"
        "web=HTTP/browser bugs. crypto=encryption/hashing/math attacks. pwn=binary exploitation. "
        "reverse=understanding a compiled/obfuscated target. forensics=disk/memory/pcap/stego artifacts. "
        "malware=analyzing a malicious sample or C2 traffic. osint=public-source/social-media/geolocation lookups. "
        "misc=jails, encodings, esoteric puzzles that don't fit elsewhere. ai-ml=attacking/prompting a model. "
        "blue-team=defensive tasks: incident response, SIEM detection rules, SOAR/alert triage. "
        "general=anything else, including plain tool tests with no security content."
    )
)


def build_system_prompt(category: str) -> SystemMessage:
    skill_dirs = CATEGORY_SKILL_DIRS.get(category, [])
    if skill_dirs:
        grounding = (
            f"This looks like a **{category}** task. The skill pack(s) {', '.join(skill_dirs)} "
            "under .agents/skills/ hold relevant technique notes — call search_skills with a "
            f"specific term (e.g. related to {category}) before relying on general knowledge."
        )
    else:
        grounding = "No specific category matched — reason from the tools available."
    return SystemMessage(
        content=(
            "You are a CTF-solving assistant. The team keeps curated CTF knowledge notes "
            "(techniques, common flag locations, cheat sheets) in a vault of Markdown files, "
            "and a separate library of vetted technique-reference skill packs (offensive "
            "categories plus defensive/blue-team ones) under .agents/skills/. Before answering "
            "a technique or 'what should I check' style question from your own general "
            "knowledge, call search_vault and/or search_skills to check whether curated notes "
            "already cover it, and ground your answer in what they return when they do.\n\n"
            + grounding
        )
    )


@tool
def echo(text: str) -> str:
    """Echo the input text back unchanged. Placeholder tool for exercising the ReAct loop before real tools exist."""
    return text


TOOLS = [echo, find_flag_pattern, identify_and_decode, search_vault, search_skills]
TOOLS_BY_NAME = {t.name: t for t in TOOLS}


class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], add_messages]
    steps: int
    flag: Optional[str]
    category: Optional[str]


def build_graph(provider: str = "google"):
    model = get_model(provider).bind_tools(TOOLS)
    triage_model = get_model(provider)

    def triage(state: AgentState) -> dict:
        human_messages = [m for m in state["messages"] if isinstance(m, HumanMessage)]
        prompt = human_messages[0].content if human_messages else ""
        response = triage_model.invoke([TRIAGE_PROMPT, HumanMessage(content=str(prompt))])
        category = message_text(response).strip().lower()
        if category not in CATEGORY_SKILL_DIRS:
            category = "general"
        return {"category": category}

    def think(state: AgentState) -> dict:
        messages = state["messages"]
        if not messages or not isinstance(messages[0], SystemMessage):
            messages = [build_system_prompt(state.get("category") or "general")] + list(messages)
        response = model.invoke(messages)
        return {"messages": [response], "steps": state["steps"] + 1}

    def act(state: AgentState) -> dict:
        last_message = state["messages"][-1]
        tool_messages = []
        for call in last_message.tool_calls:
            result = TOOLS_BY_NAME[call["name"]].invoke(call["args"])
            tool_messages.append(
                ToolMessage(content=str(result), name=call["name"], tool_call_id=call["id"])
            )
        return {"messages": tool_messages}

    def observe(state: AgentState) -> dict:
        for message in reversed(state["messages"]):
            if not isinstance(message, ToolMessage):
                break
            match = FLAG_PATTERN.search(message.content)
            if match:
                return {"flag": match.group(0)}
        return {}

    def route_after_think(state: AgentState) -> str:
        last_message = state["messages"][-1]
        if not isinstance(last_message, AIMessage) or not last_message.tool_calls:
            return END
        return "act"

    def route_after_observe(state: AgentState) -> str:
        if state.get("flag") or state["steps"] >= MAX_STEPS:
            return END
        return "think"

    graph = StateGraph(AgentState)
    graph.add_node("triage", triage)
    graph.add_node("think", think)
    graph.add_node("act", act)
    graph.add_node("observe", observe)

    graph.set_entry_point("triage")
    graph.add_edge("triage", "think")
    graph.add_conditional_edges("think", route_after_think, {"act": "act", END: END})
    graph.add_edge("act", "observe")
    graph.add_conditional_edges("observe", route_after_observe, {"think": "think", END: END})

    return graph.compile()


def run_case(app, prompt: str) -> AgentState:
    initial_state: AgentState = {
        "messages": [HumanMessage(content=prompt)],
        "steps": 0,
        "flag": None,
        "category": None,
    }
    # One triage step, then each loop iteration visits think -> act -> observe
    # (3 graph steps), so give recursion_limit enough headroom for MAX_STEPS iterations.
    final_state = app.invoke(initial_state, config={"recursion_limit": MAX_STEPS * 3 + 2})
    for message in final_state["messages"]:
        message.pretty_print()
    print("category:", final_state["category"])
    print("steps:", final_state["steps"])
    print("flag:", final_state["flag"])
    return final_state


if __name__ == "__main__":
    app = build_graph()

    print("=== case 1: plain echo, expect loop to run to natural completion ===")
    run_case(app, "Call the echo tool with the text 'hello world', then stop.")

    print("\n=== case 2: echo a flag, expect early exit as soon as it's detected ===")
    case_2_final = run_case(app, "Call the echo tool with the exact text 'flag{test_early_exit}'.")
    assert case_2_final["flag"] == "flag{test_early_exit}", "flag was not captured"
    assert case_2_final["steps"] < MAX_STEPS, "loop did not exit early on flag detection"

    print("\n=== case 3: multi-step decode, expect two identify_and_decode calls to reach the flag ===")
    case_3_final = run_case(
        app,
        "Decode this: NjY2YzYxNjc3YjZkNzU2Yzc0Njk1ZjczNzQ2NTcwNWY3NzZmNzI2YjczN2Q=",
    )
    print("steps:", case_3_final["steps"])
    print("flag:", case_3_final["flag"])
    assert case_3_final["flag"] == "flag{multi_step_works}", "multi-step decode did not reach the flag"

    print("\n=== case 4: vault knowledge lookup, expect search_vault call grounded in Web_Placeholder.md ===")
    case_4_final = run_case(
        app,
        "I'm looking at a web challenge and found something odd in the response "
        "headers — what should I check?",
    )
    tool_calls_made = {
        message.name for message in case_4_final["messages"] if isinstance(message, ToolMessage)
    }
    assert "search_vault" in tool_calls_made, f"expected search_vault to be called, got {tool_calls_made}"
    assert tool_calls_made <= {"search_vault", "search_skills"}, (
        f"expected only grounding-lookup tools to be called, got {tool_calls_made}"
    )
    final_answer = message_text(case_4_final["messages"][-1]).lower()
    assert any(
        term in final_answer for term in ("x-flag", "set-cookie", "custom header")
    ), f"expected answer to reference Web_Placeholder.md's header content, got: {final_answer}"

    print(
        "\n=== case 5: sub-agent triage, expect category=crypto and search_skills grounded "
        "in ctf-crypto RSA attack notes ==="
    )
    case_5_final = run_case(
        app,
        "I have RSA parameters n, e, and a ciphertext c and need to recover the plaintext "
        "— what attack should I try first?",
    )
    assert case_5_final["category"] == "crypto", (
        f"expected triage to classify this as crypto, got {case_5_final['category']}"
    )
    tool_calls_made_5 = {
        message.name for message in case_5_final["messages"] if isinstance(message, ToolMessage)
    }
    assert "search_skills" in tool_calls_made_5, (
        f"expected search_skills to be called, got {tool_calls_made_5}"
    )
    final_answer_5 = message_text(case_5_final["messages"][-1]).lower()
    assert any(
        term in final_answer_5 for term in ("wiener", "coppersmith", "common modulus", "low exponent", "low public exponent")
    ), f"expected answer grounded in a known RSA attack technique, got: {final_answer_5}"
