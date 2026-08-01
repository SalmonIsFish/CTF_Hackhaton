import http.server
import socketserver
import threading

from langchain_core.messages import AIMessage, HumanMessage, RemoveMessage, ToolMessage

from agent.graph import (
    MAX_CONTEXT_MESSAGES,
    _last_tool_calls_repeated,
    extract_allowed_hosts,
    extract_tool_trace,
    trim_context,
)
from agent.tools import tcp_session
from agent.tools.fetch_url import fetch_url
from agent.tools.find_flag_pattern import find_flag_pattern
from agent.tools.identify_and_decode import identify_and_decode
from agent.tools.port_scan import port_scan
from agent.tools.search_skills import search_skills
from agent.tools.search_vault import search_vault
from agent.tools.tcp_session import tcp_close, tcp_open, tcp_send
from agent.tools.web_search import web_search

print("=== find_flag_pattern: string containing a flag ===")
print(find_flag_pattern.invoke({"text": "the answer is flag{abc123}, don't lose it"}))

print("\n=== find_flag_pattern: string with no flag ===")
print(find_flag_pattern.invoke({"text": "just some ordinary sentence, nothing to see here"}))

print("\n=== identify_and_decode: known base64 (aGVsbG8gd29ybGQ= -> hello world) ===")
print(identify_and_decode.invoke({"text": "aGVsbG8gd29ybGQ="}))

print("\n=== identify_and_decode: known hex (68656c6c6f -> hello) ===")
print(identify_and_decode.invoke({"text": "68656c6c6f"}))

print("\n=== search_vault: known term ('cookies', present in Web_Placeholder.md) ===")
found = search_vault.invoke({"query": "cookies"})
print(found)
assert "Web_Placeholder.md" in found, "expected Web_Placeholder.md in results"
assert "cookie" in found.lower(), "expected matched line in results"

print("\n=== search_vault: term not present anywhere in the vault ===")
not_found = search_vault.invoke({"query": "zzz_definitely_not_in_vault_zzz"})
print(not_found)
assert "Web_Placeholder.md" not in not_found, "unexpected filename in no-match result"
assert "No matches" in not_found, "expected clean no-match message"

print("\n=== search_skills: known term ('Wiener', present in ctf-crypto's RSA attack notes) ===")
skills_found = search_skills.invoke({"query": "Wiener"})
print(skills_found)
assert "ctf-crypto" in skills_found, "expected a ctf-crypto file in results"

print("\n=== search_skills: term not present anywhere in installed skills ===")
skills_not_found = search_skills.invoke({"query": "zzz_definitely_not_in_skills_zzz"})
print(skills_not_found)
assert "No matches" in skills_not_found, "expected clean no-match message"

print("\n=== web_search: empty query ===")
empty_search = web_search.invoke({"query": "  "})
print(empty_search)
assert empty_search == "Empty query.", f"expected clean empty-query message, got {empty_search}"

print("\n=== web_search: no TAVILY_API_KEY set, expect graceful degradation not a crash ===")
import os as _os  # local import, avoids polluting the module-level namespace above

_saved_key = _os.environ.pop("TAVILY_API_KEY", None)
try:
    no_key_result = web_search.invoke({"query": "zip slip symlink bypass"})
    print(no_key_result)
    assert "TAVILY_API_KEY not set" in no_key_result, (
        f"expected the graceful unavailable message, got {no_key_result}"
    )
finally:
    if _saved_key is not None:
        _os.environ["TAVILY_API_KEY"] = _saved_key
# A real live-API call is deliberately not part of this automated suite (same reasoning as
# evals/real_target_check.py) -- verify manually with a real TAVILY_API_KEY set if needed.

print("\n=== trim_context: under threshold, expect no-op ===")
small_state = {
    "messages": [HumanMessage(content="hi", id="human-1")]
    + [AIMessage(content=f"turn {i}", id=f"msg-{i}") for i in range(4)],
}
small_result = trim_context(small_state)
print(small_result)
assert small_result == {}, "expected no trimming below MAX_CONTEXT_MESSAGES"

print("\n=== trim_context: over threshold, expect oldest non-anchor messages removed ===")
overflow = 5
trimmable_count = MAX_CONTEXT_MESSAGES + overflow
big_messages = [HumanMessage(content="the actual challenge prompt", id="human-1")]
big_messages += [
    ToolMessage(content=f"tool result {i}", name="echo", tool_call_id=f"call-{i}", id=f"msg-{i}")
    for i in range(trimmable_count)
]
big_state = {"messages": big_messages}
big_result = trim_context(big_state)
print(big_result)
removed_ids = {rm.id for rm in big_result["messages"]}
assert all(isinstance(m, RemoveMessage) for m in big_result["messages"]), "expected only RemoveMessage entries"
assert "human-1" not in removed_ids, "the first HumanMessage (the challenge prompt) must never be trimmed"
assert removed_ids == {f"msg-{i}" for i in range(overflow)}, (
    f"expected exactly the oldest {overflow} trimmable messages removed, got {removed_ids}"
)

print("\n=== extract_tool_trace: pairs an AIMessage's tool call with its ToolMessage result ===")
trace_messages = [
    HumanMessage(content="decode this", id="h-1"),
    AIMessage(
        content="",
        id="ai-1",
        tool_calls=[{"name": "identify_and_decode", "args": {"text": "abc"}, "id": "call-1"}],
    ),
    ToolMessage(content="base64: xyz", name="identify_and_decode", tool_call_id="call-1", id="tm-1"),
]
trace = extract_tool_trace(trace_messages)
print(trace)
assert trace == [{"name": "identify_and_decode", "args": {"text": "abc"}, "result": "base64: xyz"}], (
    f"expected a single paired trace entry, got {trace}"
)

print("\n=== extract_tool_trace: a call with no ToolMessage yet has result=None ===")
pending_trace = extract_tool_trace(trace_messages[:2])
print(pending_trace)
assert pending_trace == [{"name": "identify_and_decode", "args": {"text": "abc"}, "result": None}], (
    f"expected result=None while the ToolMessage hasn't arrived yet, got {pending_trace}"
)

print("\n=== extract_allowed_hosts: IPv4, nc-style, host:port, and URL forms ===")
hosts_ip = extract_allowed_hosts("Connect to 10.0.0.5 on port 1337 to grab the flag.")
assert "10.0.0.5" in hosts_ip, f"expected IPv4 extraction, got {hosts_ip}"

hosts_nc = extract_allowed_hosts("nc chal.example.org 1337 to interact with the service.")
assert "chal.example.org" in hosts_nc, f"expected nc-style host extraction, got {hosts_nc}"

hosts_hostport = extract_allowed_hosts("The service is at chal.example.org:1337, good luck.")
assert "chal.example.org" in hosts_hostport, f"expected host:port extraction, got {hosts_hostport}"

hosts_url = extract_allowed_hosts("The challenge is at http://chal.example.org:8080/index.html")
assert "chal.example.org" in hosts_url, f"expected URL host extraction, got {hosts_url}"

print("\n=== extract_allowed_hosts: additional real-world phrasings (Phase 1 stress test) ===")
hosts_colon_port = extract_allowed_hosts("Target: 10.0.0.7:4000")
assert "10.0.0.7" in hosts_colon_port, f"expected 'Target: host:port' extraction, got {hosts_colon_port}"

hosts_service_domain = extract_allowed_hosts("Connect to service.chal.ctf:9999")
assert "service.chal.ctf" in hosts_service_domain, (
    f"expected multi-label hostname:port extraction, got {hosts_service_domain}"
)

hosts_parenthetical_port = extract_allowed_hosts("The box is 172.16.5.20 (port 31337)")
assert "172.16.5.20" in hosts_parenthetical_port, (
    f"expected IPv4 extraction alongside a parenthetical port mention, got {hosts_parenthetical_port}"
)

print("\n=== _last_tool_calls_repeated: 3 identical calls trigger, 3 varied calls don't ===")
repeated_calls = [
    AIMessage(
        content="", id=f"rep-{i}",
        tool_calls=[{"name": "fetch_url", "args": {"url": "http://x"}, "id": f"rc-{i}"}],
    )
    for i in range(3)
]
assert _last_tool_calls_repeated(repeated_calls) is True, (
    "expected 3 identical tool calls to be flagged as repeated"
)

varied_calls = [
    AIMessage(
        content="", id=f"var-{i}",
        tool_calls=[{"name": "fetch_url", "args": {"url": f"http://x{i}"}, "id": f"vc-{i}"}],
    )
    for i in range(3)
]
assert _last_tool_calls_repeated(varied_calls) is False, (
    "expected varied tool call args to NOT be flagged as repeated"
)

print("\n=== fetch_url: local throwaway HTTP server, expect status/header/body + untrusted_data wrapper ===")


class _EchoHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("X-Test-Flag", "flag{fetch_url_smoke_test}")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


http_httpd = socketserver.TCPServer(("127.0.0.1", 0), _EchoHTTPHandler)
http_port = http_httpd.server_address[1]
http_thread = threading.Thread(target=http_httpd.serve_forever, daemon=True)
http_thread.start()
try:
    fetch_result = fetch_url.invoke({"url": f"http://127.0.0.1:{http_port}/"})
    print(fetch_result)
    assert "<untrusted_data" in fetch_result, "expected untrusted_data wrapper"
    assert "flag{fetch_url_smoke_test}" in fetch_result, "expected the flag header to appear in the result"
    assert "HTTP 200" in fetch_result, "expected the status line in the result"
finally:
    http_httpd.shutdown()
    http_httpd.server_close()

print("\n=== fetch_url: connection refused, expect a clean error string, not an exception ===")
refused = fetch_url.invoke({"url": "http://127.0.0.1:1/"})
print(refused)
assert "failed" in refused.lower(), f"expected a clean failure message, got: {refused}"


print("\n=== tcp_session: open/send/close against a local echo server ===")


class _EchoTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(1024)
        self.request.sendall(b"echo: " + data)


tcp_httpd = socketserver.TCPServer(("127.0.0.1", 0), _EchoTCPHandler)
tcp_port = tcp_httpd.server_address[1]
tcp_thread = threading.Thread(target=tcp_httpd.serve_forever, daemon=True)
tcp_thread.start()
try:
    open_result = tcp_open.invoke({"host": "127.0.0.1", "port": tcp_port})
    print(open_result)
    assert "session_id=" in open_result, f"expected a session_id in open result, got {open_result}"
    session_id = open_result.split("session_id=")[1].split(" ")[0]

    send_result = tcp_send.invoke({"session_id": session_id, "data": "hello"})
    print(send_result)
    assert "echo: hello" in send_result, f"expected echoed data back, got {send_result}"
    assert "<untrusted_data" in send_result, "expected untrusted_data wrapper on tcp_send result"

    close_result = tcp_close.invoke({"session_id": session_id})
    print(close_result)
    assert "closed" in close_result.lower()

    print("\n=== tcp_session: sending on a closed/unknown session_id is a clean error, not an exception ===")
    stale_result = tcp_send.invoke({"session_id": session_id, "data": "hello again"})
    print(stale_result)
    assert "unknown" in stale_result.lower() or "expired" in stale_result.lower()

    print("\n=== tcp_session: concurrent session cap is enforced ===")
    opened_ids = []
    for _ in range(tcp_session.MAX_CONCURRENT_SESSIONS):
        cap_result = tcp_open.invoke({"host": "127.0.0.1", "port": tcp_port})
        assert "session_id=" in cap_result, f"expected session to open, got {cap_result}"
        opened_ids.append(cap_result.split("session_id=")[1].split(" ")[0])

    over_cap_result = tcp_open.invoke({"host": "127.0.0.1", "port": tcp_port})
    print(over_cap_result)
    assert "Refused" in over_cap_result, f"expected the session cap to be enforced, got {over_cap_result}"
    for sid in opened_ids:
        tcp_close.invoke({"session_id": sid})

    print("\n=== tcp_session: expired session lifetime is enforced ===")
    expiring_open = tcp_open.invoke({"host": "127.0.0.1", "port": tcp_port})
    expiring_id = expiring_open.split("session_id=")[1].split(" ")[0]
    tcp_session._sessions[expiring_id]["opened_at"] -= tcp_session.SESSION_LIFETIME_SECONDS + 1
    expired_result = tcp_send.invoke({"session_id": expiring_id, "data": "too late"})
    print(expired_result)
    assert "lifetime" in expired_result.lower() or "expired" in expired_result.lower()
finally:
    tcp_session.close_all_sessions()
    tcp_httpd.shutdown()
    tcp_httpd.server_close()


print("\n=== port_scan: open port with a banner, plus closed ports, against a local server ===")


class _BannerTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"BANNER-9000\n")


banner_httpd = socketserver.TCPServer(("127.0.0.1", 0), _BannerTCPHandler)
banner_port = banner_httpd.server_address[1]
banner_thread = threading.Thread(target=banner_httpd.serve_forever, daemon=True)
banner_thread.start()
try:
    scan_ports = f"{banner_port},{banner_port + 1},{banner_port + 2}"
    scan_result = port_scan.invoke({"host": "127.0.0.1", "ports": scan_ports})
    print(scan_result)
    assert "<untrusted_data" in scan_result, "expected untrusted_data wrapper"
    assert f"{banner_port}\topen\tBANNER-9000" in scan_result, (
        f"expected the open port's banner to be reported, got {scan_result}"
    )
    assert f"{banner_port + 1}\tclosed/filtered" in scan_result, (
        f"expected the unused adjacent port to be reported closed/filtered, got {scan_result}"
    )
finally:
    banner_httpd.shutdown()
    banner_httpd.server_close()

print("\n=== port_scan: default ports list is used when none is supplied ===")
default_scan = port_scan.invoke({"host": "127.0.0.1", "ports": ""})
print(default_scan[:200] + "...")
assert "<untrusted_data" in default_scan, "expected untrusted_data wrapper on default-ports scan"
assert default_scan.count("\n") >= 20, "expected roughly the default ~20-port list to be scanned"

print("\n=== port_scan: an oversized explicit ports list is capped, not run in full ===")
from agent.tools.port_scan import MAX_PORTS  # noqa: E402 - imported here to keep it near its one use

oversized_ports = ",".join(str(p) for p in range(20000, 20000 + MAX_PORTS + 25))
capped_scan = port_scan.invoke({"host": "127.0.0.1", "ports": oversized_ports})
port_rows = [
    line for line in capped_scan.split("\n")
    if "\t" in line and not line.startswith("port\t")
]
assert len(port_rows) == MAX_PORTS, f"expected exactly {MAX_PORTS} ports scanned, got {len(port_rows)}"
