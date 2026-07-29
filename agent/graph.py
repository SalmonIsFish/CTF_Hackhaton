import re
from typing import Annotated, Optional, Sequence, TypedDict

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages

from agent.model_router import get_model
from agent.tools.find_flag_pattern import find_flag_pattern
from agent.tools.identify_and_decode import identify_and_decode

MAX_STEPS = 15
FLAG_PATTERN = re.compile(r"\w+\{[^{}]+\}")


@tool
def echo(text: str) -> str:
    """Echo the input text back unchanged. Placeholder tool for exercising the ReAct loop before real tools exist."""
    return text


TOOLS = [echo, find_flag_pattern, identify_and_decode]
TOOLS_BY_NAME = {t.name: t for t in TOOLS}


class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], add_messages]
    steps: int
    flag: Optional[str]


def build_graph(provider: str = "google"):
    model = get_model(provider).bind_tools(TOOLS)

    def think(state: AgentState) -> dict:
        response = model.invoke(state["messages"])
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
    graph.add_node("think", think)
    graph.add_node("act", act)
    graph.add_node("observe", observe)

    graph.set_entry_point("think")
    graph.add_conditional_edges("think", route_after_think, {"act": "act", END: END})
    graph.add_edge("act", "observe")
    graph.add_conditional_edges("observe", route_after_observe, {"think": "think", END: END})

    return graph.compile()


def run_case(app, prompt: str) -> AgentState:
    initial_state: AgentState = {
        "messages": [HumanMessage(content=prompt)],
        "steps": 0,
        "flag": None,
    }
    # Each loop iteration visits think -> act -> observe (3 graph steps), so
    # give recursion_limit enough headroom for MAX_STEPS iterations.
    final_state = app.invoke(initial_state, config={"recursion_limit": MAX_STEPS * 3 + 1})
    for message in final_state["messages"]:
        message.pretty_print()
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
