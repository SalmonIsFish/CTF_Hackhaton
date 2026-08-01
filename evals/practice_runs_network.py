"""Full-agent-loop practice runs against realistic local CTF-shaped targets.

Closes the gap flagged in NEXT_STEPS.md Phase 1: the network tools had only been proven
against a single trivial local server (one GET, one echo exchange). This exercises
tcp_session on a genuine multi-turn (login then command) service, fetch_url on a
redirect+cookie chain, and port_scan on a mixed open/closed port sweep — all through the
real triage -> think -> act -> observe loop, not the tool in isolation (that mechanics-level
coverage is evals/test_tools_smoke.py's job).

These are local stand-ins for real picoCTF/organizer targets — see evals/practice_runs.md
for the explicit caveat about what this does and doesn't prove.

Usage:
    python -m evals.practice_runs_network
"""
import sys

from langchain_core.messages import AIMessage, HumanMessage

from agent.graph import build_graph, message_text, run_config
from evals.practice_targets import (
    BANNER_TEXT,
    LOGIN_FLAG,
    LOGIN_PASSWORD,
    REDIRECT_FLAG,
    BannerTCPHandler,
    LoginGatedTCPHandler,
    RedirectCookieHTTPHandler,
    start_server,
)

app = build_graph()
results = []


def run_case(name: str, prompt: str) -> dict:
    print(f"\n=== {name} ===")
    print(f"prompt: {prompt}\n")
    result = app.invoke(
        {"messages": [HumanMessage(content=prompt)], "steps": 0, "flag": None, "category": None},
        config=run_config(),
    )
    tool_calls_made = [
        call["name"]
        for m in result["messages"]
        if isinstance(m, AIMessage)
        for call in (m.tool_calls or [])
    ]
    print("tool calls:", tool_calls_made)
    print("flag:", result["flag"])
    print("final answer:", message_text(result["messages"][-1])[:300])
    return {"result": result, "tool_calls": tool_calls_made}


def record(name: str, passed: bool, notes: str) -> None:
    results.append((name, passed, notes))
    print(f"--- {'PASS' if passed else 'FAIL'}: {name} ({notes}) ---")


# Scenario 1: login-gated multi-turn TCP service — stresses tcp_open -> tcp_send -> tcp_send
tcp_server, tcp_port = start_server(LoginGatedTCPHandler)
try:
    case_1 = run_case(
        "login-gated TCP service",
        f"There's a login-gated service at 127.0.0.1:{tcp_port}. The password is "
        f"'{LOGIN_PASSWORD}' — connect, log in, then ask for the flag by sending 'flag'.",
    )
    ok_1 = (
        case_1["result"]["flag"] == LOGIN_FLAG
        and "tcp_open" in case_1["tool_calls"]
        and "tcp_send" in case_1["tool_calls"]
    )
    record("login-gated TCP (multi-turn tcp_session)", ok_1, f"flag={case_1['result']['flag']}")
finally:
    tcp_server.shutdown()
    tcp_server.server_close()

# Scenario 2: redirect + cookie HTTP chain — stresses fetch_url's allow_redirects path
http_server, http_port = start_server(RedirectCookieHTTPHandler)
try:
    case_2 = run_case(
        "redirect/cookie web challenge",
        f"There's a web challenge at http://127.0.0.1:{http_port}/ — fetch it and find the flag.",
    )
    ok_2 = case_2["result"]["flag"] == REDIRECT_FLAG and "fetch_url" in case_2["tool_calls"]
    record("redirect/cookie HTTP (fetch_url follows redirect)", ok_2, f"flag={case_2['result']['flag']}")
finally:
    http_server.shutdown()
    http_server.server_close()

# Scenario 3: port + banner discovery — stresses port_scan against a mixed open/closed sweep
banner_server, banner_port = start_server(BannerTCPHandler)
try:
    nearby_ports = ",".join(str(p) for p in (banner_port, banner_port + 1, banner_port + 2))
    case_3 = run_case(
        "port + banner discovery",
        f"There's something running on 127.0.0.1 somewhere near port {banner_port}. Scan "
        f"ports {nearby_ports} and tell me what service/version you find, if any.",
    )
    final_text_3 = message_text(case_3["result"]["messages"][-1])
    ok_3 = "port_scan" in case_3["tool_calls"] and BANNER_TEXT in final_text_3
    record("port + banner discovery (port_scan)", ok_3, f"tool_calls={case_3['tool_calls']}")
finally:
    banner_server.shutdown()
    banner_server.server_close()


print("\n=== Summary ===")
all_passed = True
for name, passed, notes in results:
    print(f"{'PASS' if passed else 'FAIL'}: {name} — {notes}")
    all_passed = all_passed and passed

if not all_passed:
    sys.exit(1)
