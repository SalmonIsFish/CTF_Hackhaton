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
import uuid
from functools import lru_cache
from typing import Iterator, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from langchain_core.messages import AIMessage, HumanMessage, RemoveMessage
from langgraph.types import Command
from pydantic import BaseModel

from agent.graph import build_graph, extract_tool_trace, log_run, message_text, run_config

app = FastAPI(title="CTF Agent API")

# CORS origins default to Next.js's dev port (the local dashboard) but are overridable via the
# CORS_ORIGINS env var (comma-separated) -- so if the dashboard is served from any other origin on
# the day (a deployed URL, a different port, a teammate's LAN IP), requests don't silently fail the
# same-origin check. Unset -> identical to the previous hardcoded localhost:3000 behavior.
_DEFAULT_CORS_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000"]
_cors_env = os.getenv("CORS_ORIGINS")
_cors_origins = (
    [o.strip() for o in _cors_env.split(",") if o.strip()] if _cors_env else _DEFAULT_CORS_ORIGINS
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SolveRequest(BaseModel):
    prompt: str
    provider: str = "google"
    # Optional dashboard convenience: a host/IP/host:port the challenge targets. When set,
    # it's folded into the prompt text (not carried as separate graph state) so it flows
    # through the same extract_allowed_hosts() path in agent/graph.py that a plain-text
    # mention would — one source of truth for the allowlist, not two to keep in sync.
    target: Optional[str] = None
    # Enforce Permissions (harness element #5): when True, a live-target tool call
    # (fetch_url/tcp_open/port_scan) pauses the run instead of executing outright — see
    # _pending_approval() and /solve/resume below. Defaults to False, so every existing
    # caller (there are none live yet) is unaffected.
    require_approval: bool = False
    # Optional per-request flag-format override (comma-separated prefixes, e.g. "hackhaton").
    # Added to the default flag prefixes for this run's early-exit detection, so the dashboard
    # can set the real competition format without a server restart. Unset -> module defaults.
    flag_prefixes: Optional[str] = None


class ResumeRequest(BaseModel):
    thread_id: str
    provider: str = "google"
    decision: str  # "approve" or "deny"


@lru_cache(maxsize=None)
def get_app_for_provider(provider: str):
    return build_graph(provider)


def initial_state(
    prompt: str,
    target: Optional[str] = None,
    require_approval: bool = False,
    flag_prefixes: Optional[str] = None,
) -> dict:
    if target:
        prompt = f"Target: {target}\n\n{prompt}"
    return {
        "messages": [HumanMessage(content=prompt)],
        "steps": 0,
        "flag": None,
        "category": None,
        "require_approval": require_approval,
        "flag_prefixes": flag_prefixes,
    }


def _pending_approval(result: dict, thread_id: str) -> dict:
    return {
        "status": "pending_approval",
        "thread_id": thread_id,
        "interrupt": result["__interrupt__"][0].value,
    }


def _completed(result: dict) -> dict:
    return {
        "category": result["category"],
        "steps": result["steps"],
        "flag": result["flag"],
        "final_answer": message_text(result["messages"][-1]),
        "tool_calls": extract_tool_trace(result["messages"]),
    }


@app.get("/health")
def health() -> dict:
    # Check both the single and the plural (rotation) key vars: the team runs on GOOGLE_API_KEYS
    # (comma-separated) per CLAUDE.md, so checking only GOOGLE_API_KEY would report the key as
    # unset even when rotation keys are configured -- a misleading pre-demo health check.
    key_set = bool(os.getenv("GOOGLE_API_KEY") or os.getenv("GOOGLE_API_KEYS"))
    return {
        "status": "ok",
        # Kept for any dashboard already reading this field; now accurate for either var.
        "default_provider_key_set": key_set,
        "google_key_set": key_set,
    }


@app.post("/solve")
def solve(request: SolveRequest) -> dict:
    if not request.prompt.strip():
        raise HTTPException(status_code=400, detail="prompt must not be empty")

    try:
        graph = get_app_for_provider(request.provider)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    thread_id = uuid.uuid4().hex
    try:
        result = graph.invoke(
            initial_state(
                request.prompt, request.target, request.require_approval, request.flag_prefixes
            ),
            config=run_config(thread_id, provider=request.provider),
        )
    except Exception as exc:  # noqa: BLE001 - surface as a clean 500, not a stack trace to the dashboard
        raise HTTPException(status_code=500, detail=f"agent run failed: {exc}") from exc

    if "__interrupt__" in result:
        return _pending_approval(result, thread_id)
    log_run(result)
    return _completed(result)


@app.post("/solve/resume")
def solve_resume(request: ResumeRequest) -> dict:
    if request.decision not in ("approve", "deny"):
        raise HTTPException(status_code=400, detail="decision must be 'approve' or 'deny'")

    try:
        graph = get_app_for_provider(request.provider)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        result = graph.invoke(
            Command(resume=request.decision),
            config=run_config(request.thread_id, provider=request.provider),
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"agent resume failed: {exc}") from exc

    if "__interrupt__" in result:
        return _pending_approval(result, request.thread_id)
    log_run(result)
    return _completed(result)


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
        thread_id = uuid.uuid4().hex
        final_category = None
        final_steps = 0
        final_flag = None
        start_state = initial_state(
            request.prompt, request.target, request.require_approval, request.flag_prefixes
        )
        # Seed with the initial HumanMessage: it's part of the input, not a delta any node
        # emits, so it would never otherwise reach messages_by_id -- and log_run() needs it
        # to record what the run was actually asked to solve.
        messages_by_id: dict[str, object] = {m.id: m for m in start_state["messages"]}

        try:
            for update in graph.stream(
                start_state,
                config=run_config(thread_id, provider=request.provider),
                stream_mode="updates",
            ):
                if not isinstance(update, dict):
                    continue
                if "__interrupt__" in update:
                    # A live-target tool call is paused awaiting approval. End the stream here
                    # (no "event: done") — the client resumes this exact thread_id via
                    # POST /solve/resume, same endpoint the non-streaming /solve uses.
                    payload = {
                        "node": "act",
                        "thread_id": thread_id,
                        "interrupt": update["__interrupt__"][0].value,
                    }
                    yield f"data: {json.dumps(payload)}\n\n"
                    return
                for node_name, partial_state in update.items():
                    if not isinstance(partial_state, dict):
                        continue
                    payload = {"node": node_name}
                    if "category" in partial_state:
                        final_category = partial_state["category"]
                        payload["category"] = partial_state["category"]
                    if "flag" in partial_state:
                        final_flag = partial_state["flag"]
                        payload["flag"] = partial_state["flag"]
                    if "steps" in partial_state:
                        final_steps = partial_state["steps"]
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
            # Loop finished without hitting the interrupt-and-return path above, i.e. the run
            # actually completed -- log it the same way /solve does, from the accumulated
            # by-id message map instead of a single final state object (stream_mode="updates"
            # never hands back one).
            log_run(
                {
                    "messages": list(messages_by_id.values()),
                    "category": final_category,
                    "steps": final_steps,
                    "flag": final_flag,
                }
            )
        except Exception as exc:  # noqa: BLE001
            yield f"data: {json.dumps({'error': str(exc)})}\n\n"
        yield "event: done\ndata: {}\n\n"

    return StreamingResponse(events(), media_type="text/event-stream")
