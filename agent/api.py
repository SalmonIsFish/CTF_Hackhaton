"""HTTP bridge between the LangGraph agent and Hasif's Next.js dashboard.

Next.js can't import Python directly, so this exists to give a Next.js API
route something real to call: a small FastAPI server wrapping agent/graph.py.

Run it with:
    uvicorn agent.api:app --reload --port 8000

Endpoints:
    GET  /health         liveness check
    POST /solve          run to completion, return the full result as JSON
    POST /solve/stream    same run, but emitted as Server-Sent Events (SSE) —
                          one event per graph node, for a live step-by-step trace
"""
import json
import os
from functools import lru_cache
from typing import Iterator

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from langchain_core.messages import AIMessage, HumanMessage, RemoveMessage
from pydantic import BaseModel

from agent.graph import MAX_STEPS, build_graph, extract_tool_trace, message_text

app = FastAPI(title="CTF Agent API")

# Dev-only CORS: the dashboard runs on Next.js's default dev port. Tighten this
# (or read from an env var) before deploying either service anywhere but a
# teammate's laptop.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class SolveRequest(BaseModel):
    prompt: str
    provider: str = "google"


@lru_cache(maxsize=None)
def get_app_for_provider(provider: str):
    return build_graph(provider)


def initial_state(prompt: str) -> dict:
    return {
        "messages": [HumanMessage(content=prompt)],
        "steps": 0,
        "flag": None,
        "category": None,
    }


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "default_provider_key_set": bool(os.getenv("GOOGLE_API_KEY"))}


@app.post("/solve")
def solve(request: SolveRequest) -> dict:
    if not request.prompt.strip():
        raise HTTPException(status_code=400, detail="prompt must not be empty")

    try:
        graph = get_app_for_provider(request.provider)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        result = graph.invoke(
            initial_state(request.prompt),
            config={"recursion_limit": MAX_STEPS * 4 + 2},
        )
    except Exception as exc:  # noqa: BLE001 - surface as a clean 500, not a stack trace to the dashboard
        raise HTTPException(status_code=500, detail=f"agent run failed: {exc}") from exc

    return {
        "category": result["category"],
        "steps": result["steps"],
        "flag": result["flag"],
        "final_answer": message_text(result["messages"][-1]),
        "tool_calls": extract_tool_trace(result["messages"]),
    }


@app.post("/solve/stream")
def solve_stream(request: SolveRequest) -> StreamingResponse:
    if not request.prompt.strip():
        raise HTTPException(status_code=400, detail="prompt must not be empty")

    try:
        graph = get_app_for_provider(request.provider)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    def events() -> Iterator[str]:
        # stream_mode="updates" yields one {node_name: partial_state} dict per
        # node the graph visits — a natural fit for "which tool is it calling
        # right now", one SSE event per step, without waiting for the whole run.
        #
        # Each node's update only contains the messages *that node* added or
        # removed (e.g. "act" adds a ToolMessage in a separate update from the
        # "think" update that added the AIMessage carrying its tool_calls), so
        # extract_tool_trace can't pair a call with its result from any single
        # update alone. Mirror what the add_messages reducer does across the
        # whole run instead: keep a running by-id map (upsert on a normal
        # message, delete on a RemoveMessage from trim_context), and recompute
        # the full trace from that after every step.
        messages_by_id: dict[str, object] = {}

        try:
            for update in graph.stream(
                initial_state(request.prompt),
                config={"recursion_limit": MAX_STEPS * 4 + 2},
                stream_mode="updates",
            ):
                if not isinstance(update, dict):
                    continue
                for node_name, partial_state in update.items():
                    if not isinstance(partial_state, dict):
                        continue
                    payload = {"node": node_name}
                    if "category" in partial_state:
                        payload["category"] = partial_state["category"]
                    if "flag" in partial_state:
                        payload["flag"] = partial_state["flag"]
                    if "messages" in partial_state:
                        for message in partial_state["messages"]:
                            if isinstance(message, RemoveMessage):
                                messages_by_id.pop(message.id, None)
                            else:
                                messages_by_id[message.id] = message
                        current_messages = list(messages_by_id.values())
                        payload["tool_calls"] = extract_tool_trace(current_messages)
                        # Only a final AIMessage with no tool_calls is model-authored
                        # prose worth surfacing as "text" (as opposed to a tool result).
                        text_parts = [
                            message_text(m) for m in partial_state["messages"]
                            if isinstance(m, AIMessage) and not m.tool_calls
                        ]
                        if text_parts:
                            payload["text"] = "".join(text_parts)
                    yield f"data: {json.dumps(payload)}\n\n"
        except Exception as exc:  # noqa: BLE001
            yield f"data: {json.dumps({'error': str(exc)})}\n\n"
        yield "event: done\ndata: {}\n\n"

    return StreamingResponse(events(), media_type="text/event-stream")
