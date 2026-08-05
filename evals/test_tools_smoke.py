import http.server
import socketserver
import threading

from langchain_core.messages import AIMessage, HumanMessage, RemoveMessage, ToolMessage

from agent.graph import (
    MAX_CONTEXT_MESSAGES,
    _last_tool_calls_repeated,
    build_system_prompt,
    extract_allowed_hosts,
    extract_tool_trace,
    message_text,
    observe,
    trim_context,
)
from agent.tools import fetch_url as fetch_url_module
from agent.tools import tcp_session
from agent.tools.dir_enum import dir_enum
from agent.tools.extract_metadata import extract_metadata
from agent.tools.fetch_url import fetch_url
from agent.tools.find_flag_pattern import find_flag_pattern
from agent.tools.identify_and_decode import identify_and_decode
from agent.tools.keyed_decode import fetch_and_decode_cipher, keyed_byte_decode
from agent.tools.port_scan import port_scan
from agent.tools.radare2_analyze import radare2_analyze
from agent.tools.search_skills import search_skills
from agent.tools.search_vault import search_vault
from agent.tools.tcp_session import tcp_close, tcp_open, tcp_send
from agent.tools.web_search import web_search

print("=== find_flag_pattern: string containing a flag ===")
print(find_flag_pattern.invoke({"text": "the answer is flag{abc123}, don't lose it"}))

print("\n=== find_flag_pattern: string with no flag ===")
print(find_flag_pattern.invoke({"text": "just some ordinary sentence, nothing to see here"}))

print("\n=== find_flag_pattern: picoCTF{...} format (real flag from a live picoCTF run) ===")
picoctf_result = find_flag_pattern.invoke(
    {"text": "session admin key leaked: picoCTF{s3t_s3ss10n_3xp1rat10n5_51c526ab}"}
)
print(picoctf_result)
assert "picoCTF{s3t_s3ss10n_3xp1rat10n5_51c526ab}" in picoctf_result, (
    f"expected the picoCTF-format flag to be recognized -- 'ctf' has no word boundary right "
    f"after 'pico', which is exactly the bug this regression-tests, got {picoctf_result}"
)

print("\n=== identify_and_decode: known base64 (aGVsbG8gd29ybGQ= -> hello world) ===")
print(identify_and_decode.invoke({"text": "aGVsbG8gd29ybGQ="}))

print("\n=== identify_and_decode: known hex (68656c6c6f -> hello) ===")
print(identify_and_decode.invoke({"text": "68656c6c6f"}))

print(
    "\n=== keyed_byte_decode: subtract-mode round trip (regression test for the picoCTF "
    "'Bookmarklet' hallucination -- the model tried this arithmetic by hand, corrupted several "
    "characters, and fabricated a flag instead of using a real tool) ==="
)
_keyed_plain = "picoCTF{keyed_decode_smoke_test}"
_keyed_key = "testkey"
_keyed_cipher = "".join(
    chr((ord(c) + ord(_keyed_key[i % len(_keyed_key)])) % 256) for i, c in enumerate(_keyed_plain)
)
keyed_result = keyed_byte_decode.invoke({"text": _keyed_cipher, "key": _keyed_key, "mode": "subtract"})
print(keyed_result)
assert keyed_result == _keyed_plain, f"expected the exact plaintext back, got {keyed_result!r}"

print("\n=== keyed_byte_decode: unsupported mode is a clean error, not an exception ===")
bad_mode_result = keyed_byte_decode.invoke({"text": "abc", "key": "k", "mode": "rot13"})
print(bad_mode_result)
assert "Unsupported mode" in bad_mode_result, f"expected a clean error, got {bad_mode_result}"

print("\n=== extract_metadata: PNG with a tEXt chunk, expect the chunk reported ===")
import tempfile as _tempfile  # local import, avoids polluting the module-level namespace above

from PIL import Image as _Image
from PIL.PngImagePlugin import PngInfo as _PngInfo

with _tempfile.TemporaryDirectory() as _tmpdir:
    png_path = f"{_tmpdir}/flag.png"
    png_info = _PngInfo()
    png_info.add_text("flag", "flag{extract_metadata_smoke_test}")
    _Image.new("RGB", (4, 4)).save(png_path, pnginfo=png_info)

    png_result = extract_metadata.invoke({"file_path": png_path})
    print(png_result)
    assert "flag{extract_metadata_smoke_test}" in png_result, (
        f"expected the PNG tEXt chunk's content in the report, got {png_result}"
    )
    assert "format: PNG" in png_result, f"expected the image format reported, got {png_result}"

    print("\n=== extract_metadata: missing file, expect a clean error string, not an exception ===")
    missing_result = extract_metadata.invoke({"file_path": f"{_tmpdir}/does_not_exist.png"})
    print(missing_result)
    assert "no such file" in missing_result.lower(), f"expected a clean missing-file message, got {missing_result}"

    print("\n=== extract_metadata: not an image, expect a clean error string, not an exception ===")
    not_image_path = f"{_tmpdir}/not_an_image.txt"
    with open(not_image_path, "w") as f:
        f.write("just plain text, not image bytes")
    not_image_result = extract_metadata.invoke({"file_path": not_image_path})
    print(not_image_result)
    assert "could not open" in not_image_result.lower(), (
        f"expected a clean not-an-image message, got {not_image_result}"
    )

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

print("\n=== observe: ignores a flag-shaped string inside a search_vault/search_skills/web_search "
      "result (regression test -- confirmed live: search_vault surfaced a real flag from an "
      "unrelated, already-solved challenge's vault write-up, and observe() wrongly reported it) ===")
vault_only_state = {
    "messages": [
        ToolMessage(
            content="...see techniques/web/offlinea-full-solve.md: Flag: HTB{not_this_ones_flag}...",
            name="search_vault",
            tool_call_id="call-1",
        ),
    ]
}
vault_only_result = observe(vault_only_state)
print(vault_only_result)
assert vault_only_result == {}, "a flag-shaped string from search_vault must not be reported as the answer"

print("\n=== observe: still detects a real flag from a live-target tool result ===")
live_flag_state = {
    "messages": [
        ToolMessage(
            content="...a decoy from vault: HTB{decoy}...",
            name="search_vault",
            tool_call_id="call-1",
        ),
        ToolMessage(
            content="<untrusted_data>...HTB{real_target_flag}...</untrusted_data>",
            name="fetch_url",
            tool_call_id="call-2",
        ),
    ]
}
live_flag_result = observe(live_flag_state)
print(live_flag_result)
assert live_flag_result == {"flag": "HTB{real_target_flag}"}, "expected the real fetch_url-derived flag, not the vault decoy"

print(
    "\n=== build_system_prompt: fabrication guardrail present (regression test -- confirmed live "
    "against a real picoCTF target: fetch_url failed to connect, and instead of reporting that, "
    "the model called web_search, found a public writeup of the same challenge, and confidently "
    "stated that writeup's flag as if it had been read from the real target. picoCTF/HTB randomize "
    "the flag per deployment -- confirmed via two writeups of the identical challenge with two "
    "different flag suffixes -- so that flag was simply wrong) ==="
)
guardrail_prompt = message_text(build_system_prompt("web"))
print(guardrail_prompt)
assert "reference-only" in guardrail_prompt, (
    "expected search_vault/search_skills/web_search to be explicitly marked reference-only, "
    "not a valid flag source, in the system prompt"
)
assert "target is unreachable" in guardrail_prompt, (
    "expected an explicit instruction to report an unreachable target instead of substituting "
    "a flag found via web_search"
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

print(
    "\n=== fetch_url: quoted header key (real observed model bug, e.g. \"'Content-Type'\") is "
    "sanitized before sending, not sent verbatim ==="
)


class _HeaderEchoHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(self.headers.get("Content-Type", "MISSING").encode())

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


header_echo_httpd = socketserver.TCPServer(("127.0.0.1", 0), _HeaderEchoHTTPHandler)
header_echo_port = header_echo_httpd.server_address[1]
header_echo_thread = threading.Thread(target=header_echo_httpd.serve_forever, daemon=True)
header_echo_thread.start()
try:
    quoted_header_result = fetch_url.invoke({
        "url": f"http://127.0.0.1:{header_echo_port}/",
        "method": "POST",
        "body": "a=1",
        "headers": {"'Content-Type'": "application/x-www-form-urlencoded"},
    })
    print(quoted_header_result)
    assert "application/x-www-form-urlencoded" in quoted_header_result, (
        f"expected the sanitized Content-Type header to reach the server, got {quoted_header_result}"
    )
    assert "MISSING" not in quoted_header_result, (
        f"expected the quoted key to still be recognized as Content-Type, got {quoted_header_result}"
    )

    print(
        "\n=== fetch_url: whole 'Header-Name: value' line stuffed into a header VALUE under a "
        "throwaway key (real observed model bug: {\"undefined\": \"Content-Type: application/json\"}) "
        "is re-split into a real key/value pair, not sent verbatim/dropped ==="
    )
    misplaced_header_result = fetch_url.invoke({
        "url": f"http://127.0.0.1:{header_echo_port}/",
        "method": "POST",
        "body": "a=1",
        "headers": {"undefined": "Content-Type: application/x-www-form-urlencoded"},
    })
    print(misplaced_header_result)
    assert "application/x-www-form-urlencoded" in misplaced_header_result, (
        f"expected the re-split Content-Type header to reach the server, got {misplaced_header_result}"
    )
    assert "MISSING" not in misplaced_header_result, (
        f"expected the misplaced header line to still be recognized as Content-Type, got {misplaced_header_result}"
    )
finally:
    header_echo_httpd.shutdown()
    header_echo_httpd.server_close()

print(
    "\n=== fetch_url: search_pattern reaches a flag buried well past MAX_BODY_CHARS (8 KB) -- "
    "regression test for a real hallucination observed live: asked to read a flag out of an "
    "11 MB heap-dump response truncated to 8 KB, the model fabricated a plausible-looking flag "
    "from training-data memory of a public writeup instead of admitting it couldn't see far "
    "enough. search_pattern exists so it never has to guess ==="
)


class _LargeBodyHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        padding = "x" * (fetch_url_module.MAX_BODY_CHARS * 4)
        body = f"{padding}picoCTF{{buried_past_the_truncation_cutoff}}{padding}".encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


large_body_httpd = socketserver.TCPServer(("127.0.0.1", 0), _LargeBodyHTTPHandler)
large_body_port = large_body_httpd.server_address[1]
large_body_thread = threading.Thread(target=large_body_httpd.serve_forever, daemon=True)
large_body_thread.start()
try:
    default_result = fetch_url.invoke({"url": f"http://127.0.0.1:{large_body_port}/"})
    assert "buried_past_the_truncation_cutoff" not in default_result, (
        "test setup assumption broken: the flag should be past the default 8 KB cutoff"
    )
    assert "truncated" in default_result, "expected the default path to report truncation"

    search_result = fetch_url.invoke({
        "url": f"http://127.0.0.1:{large_body_port}/",
        "search_pattern": r"picoCTF\{[^}]{1,60}\}",
    })
    print(search_result)
    assert "picoCTF{buried_past_the_truncation_cutoff}" in search_result, (
        f"expected search_pattern to find the flag past the truncation cutoff, got {search_result}"
    )

    no_match_result = fetch_url.invoke({
        "url": f"http://127.0.0.1:{large_body_port}/",
        "search_pattern": r"htb\{[^}]{1,60}\}",
    })
    print(no_match_result)
    assert "No match" in no_match_result, f"expected a clean no-match message, got {no_match_result}"
finally:
    large_body_httpd.shutdown()
    large_body_httpd.server_close()


print(
    "\n=== fetch_and_decode_cipher: extracts a ciphertext from a live page and decodes it in one "
    "call, mirroring picoCTF's 'Bookmarklet' challenge shape (var encryptedFlag = \"...\";) ==="
)


class _BookmarkletHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = (
            '<script>var encryptedFlag = "' + _keyed_cipher + '"; var key = "testkey";</script>'
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


bookmarklet_httpd = socketserver.TCPServer(("127.0.0.1", 0), _BookmarkletHTTPHandler)
bookmarklet_port = bookmarklet_httpd.server_address[1]
bookmarklet_thread = threading.Thread(target=bookmarklet_httpd.serve_forever, daemon=True)
bookmarklet_thread.start()
try:
    cipher_result = fetch_and_decode_cipher.invoke({
        "url": f"http://127.0.0.1:{bookmarklet_port}/",
        "key": "testkey",
        "pattern": r'encryptedFlag\s*=\s*"([^"]*)"',
        "mode": "subtract",
    })
    print(cipher_result)
    assert "<untrusted_data" in cipher_result, "expected untrusted_data wrapper"
    assert _keyed_plain in cipher_result, (
        f"expected the correctly decoded plaintext in the result, got {cipher_result}"
    )

    print("\n=== fetch_and_decode_cipher: pattern with no match is a clean message, not an exception ===")
    no_match_cipher_result = fetch_and_decode_cipher.invoke({
        "url": f"http://127.0.0.1:{bookmarklet_port}/",
        "key": "testkey",
        "pattern": r"notPresent=\"([^\"]*)\"",
        "mode": "subtract",
    })
    print(no_match_cipher_result)
    assert "did not match" in no_match_cipher_result, (
        f"expected a clean no-match message, got {no_match_cipher_result}"
    )
finally:
    bookmarklet_httpd.shutdown()
    bookmarklet_httpd.server_close()


print(
    "\n=== fetch_url: session_id persists cookies across calls (regression test for the "
    "IntroToBurp cookie-loss bug -- the agent's own run kept dropping the session cookie on "
    "plain GET calls, forcing an endless re-register loop instead of ever reaching an "
    "authenticated page) ==="
)


class _CookieSessionHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if "sid=granted" in self.headers.get("Cookie", ""):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"authenticated")
        else:
            self.send_response(200)
            self.send_header("Set-Cookie", "sid=granted; Path=/")
            self.end_headers()
            self.wfile.write(b"anonymous")

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


cookie_httpd = socketserver.TCPServer(("127.0.0.1", 0), _CookieSessionHTTPHandler)
cookie_port = cookie_httpd.server_address[1]
cookie_thread = threading.Thread(target=cookie_httpd.serve_forever, daemon=True)
cookie_thread.start()
try:
    first_call = fetch_url.invoke({
        "url": f"http://127.0.0.1:{cookie_port}/", "session_id": "test-session-a",
    })
    print(first_call)
    assert "anonymous" in first_call, f"expected the first call (no cookie yet) to be anonymous, got {first_call}"

    second_call = fetch_url.invoke({
        "url": f"http://127.0.0.1:{cookie_port}/", "session_id": "test-session-a",
    })
    print(second_call)
    assert "authenticated" in second_call, (
        f"expected the second call, same session_id, to automatically carry the cookie the "
        f"first response set, with no Cookie header supplied by hand, got {second_call}"
    )

    stateless_call = fetch_url.invoke({"url": f"http://127.0.0.1:{cookie_port}/"})
    print(stateless_call)
    assert "anonymous" in stateless_call, (
        f"expected a call with no session_id to stay fully stateless (no bleed-over from the "
        f"session_id path above), got {stateless_call}"
    )

    print("\n=== fetch_url: concurrent session cap is enforced ===")
    # test-session-a from above is still open and already counts toward the cap.
    for i in range(fetch_url_module.MAX_CONCURRENT_HTTP_SESSIONS - 1):
        sid = f"cap-session-{i}"
        cap_call = fetch_url.invoke({"url": f"http://127.0.0.1:{cookie_port}/", "session_id": sid})
        assert "Refused" not in cap_call, f"expected session {sid} to open, got {cap_call}"

    over_cap_call = fetch_url.invoke({
        "url": f"http://127.0.0.1:{cookie_port}/", "session_id": "one-too-many",
    })
    print(over_cap_call)
    assert "Refused" in over_cap_call, f"expected the session cap to be enforced, got {over_cap_call}"
    fetch_url_module.close_all_http_sessions()

    print(
        "\n=== fetch_url: expired session lifetime drops the cookie jar (falls back to a fresh "
        "session under the same id rather than reusing stale cookies) ==="
    )
    expiring_first = fetch_url.invoke({
        "url": f"http://127.0.0.1:{cookie_port}/", "session_id": "expiring-session",
    })
    assert "anonymous" in expiring_first
    fetch_url_module._http_sessions["expiring-session"]["created_at"] -= (
        fetch_url_module.HTTP_SESSION_LIFETIME_SECONDS + 1
    )
    expired_call = fetch_url.invoke({
        "url": f"http://127.0.0.1:{cookie_port}/", "session_id": "expiring-session",
    })
    print(expired_call)
    assert "anonymous" in expired_call, (
        f"expected the expired session's cookie jar to be dropped, not reused, got {expired_call}"
    )
finally:
    fetch_url_module.close_all_http_sessions()
    cookie_httpd.shutdown()
    cookie_httpd.server_close()


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


print("\n=== dir_enum: normal sweep, known hits reported and 404s omitted ===")


class _DirEnumHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/admin":
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        elif self.path == "/old-login":
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


dir_enum_httpd = socketserver.TCPServer(("127.0.0.1", 0), _DirEnumHTTPHandler)
dir_enum_port = dir_enum_httpd.server_address[1]
dir_enum_thread = threading.Thread(target=dir_enum_httpd.serve_forever, daemon=True)
dir_enum_thread.start()
try:
    sweep_result = dir_enum.invoke({
        "base_url": f"http://127.0.0.1:{dir_enum_port}",
        "paths": "admin,old-login,definitely-not-real",
    })
    print(sweep_result)
    assert "<untrusted_data" in sweep_result, "expected untrusted_data wrapper"
    assert "admin\t200" in sweep_result, f"expected the 200 hit reported, got {sweep_result}"
    assert "old-login\t302" in sweep_result and "/login" in sweep_result, (
        f"expected the redirect and its Location reported, got {sweep_result}"
    )
    assert "definitely-not-real\t" not in sweep_result, (
        f"expected the 404 path omitted from the report, got {sweep_result}"
    )
finally:
    dir_enum_httpd.shutdown()
    dir_enum_httpd.server_close()

print("\n=== dir_enum: wildcard/catch-all target aborts instead of reporting false positives ===")


class _WildcardHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"catch-all page")

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


wildcard_httpd = socketserver.TCPServer(("127.0.0.1", 0), _WildcardHTTPHandler)
wildcard_port = wildcard_httpd.server_address[1]
wildcard_thread = threading.Thread(target=wildcard_httpd.serve_forever, daemon=True)
wildcard_thread.start()
try:
    wildcard_result = dir_enum.invoke({"base_url": f"http://127.0.0.1:{wildcard_port}"})
    print(wildcard_result)
    assert "aborted" in wildcard_result.lower(), f"expected an abort message, got {wildcard_result}"
    assert "wildcard" in wildcard_result.lower() or "catch-all" in wildcard_result.lower(), (
        f"expected the wildcard/catch-all finding named, got {wildcard_result}"
    )
    assert "path\tstatus" not in wildcard_result, (
        f"expected no per-path row table on an aborted sweep, got {wildcard_result}"
    )
finally:
    wildcard_httpd.shutdown()
    wildcard_httpd.server_close()

print("\n=== dir_enum: an oversized explicit paths list is capped, not run in full ===")
from agent.tools.dir_enum import MAX_PATHS  # noqa: E402 - imported here to keep it near its one use


class _DirEnumCapHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/cap-item-"):
            self.send_response(200)
        else:
            self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):  # noqa: A002 - silence default request logging
        pass


dir_enum_cap_httpd = socketserver.TCPServer(("127.0.0.1", 0), _DirEnumCapHTTPHandler)
dir_enum_cap_port = dir_enum_cap_httpd.server_address[1]
dir_enum_cap_thread = threading.Thread(target=dir_enum_cap_httpd.serve_forever, daemon=True)
dir_enum_cap_thread.start()
try:
    oversized_paths = ",".join(f"cap-item-{i}" for i in range(MAX_PATHS + 25))
    capped_sweep = dir_enum.invoke({
        "base_url": f"http://127.0.0.1:{dir_enum_cap_port}",
        "paths": oversized_paths,
    })
    cap_rows = [line for line in capped_sweep.split("\n") if line.startswith("cap-item-")]
    assert len(cap_rows) == MAX_PATHS, f"expected exactly {MAX_PATHS} paths swept, got {len(cap_rows)}"
finally:
    dir_enum_cap_httpd.shutdown()
    dir_enum_cap_httpd.server_close()

print("\n=== dir_enum: unreachable target, expect a clean error string, not an exception ===")
dir_enum_refused = dir_enum.invoke({"base_url": "http://127.0.0.1:1"})
print(dir_enum_refused)
assert "failed" in dir_enum_refused.lower(), f"expected a clean failure message, got: {dir_enum_refused}"

print(
    "\n=== radare2_analyze: real end-to-end run against a real ELF (/bin/true, pulled live "
    "through WSL) -- not a mock, exercises the actual wsl.exe/rabin2/r2 bridge ==="
)
import base64 as _b64  # local import: only this test block needs it
import subprocess as _subprocess

_r2_test_bin = _subprocess.run(
    ["wsl.exe", "-e", "cat", "/bin/true"], capture_output=True, timeout=10
).stdout
assert _r2_test_bin, "expected /bin/true to actually produce bytes via WSL -- is WSL installed?"
_r2_b64 = _b64.b64encode(_r2_test_bin).decode()

r2_info = radare2_analyze.invoke({"content_b64": _r2_b64, "mode": "info"})
print(r2_info)
assert "elf" in r2_info.lower(), f"expected ELF file info from rabin2 -I, got: {r2_info}"

print("\n=== radare2_analyze: strings mode ===")
r2_strings = radare2_analyze.invoke({"content_b64": _r2_b64, "mode": "strings"})
print(r2_strings)
assert "<untrusted_data" in r2_strings, "expected the result wrapped in <untrusted_data> tags"

print("\n=== radare2_analyze: unknown mode is rejected with a clear error, not a crash ===")
r2_bad_mode = radare2_analyze.invoke({"content_b64": _r2_b64, "mode": "delete_everything"})
print(r2_bad_mode)
assert "Unknown mode" in r2_bad_mode, f"expected an unknown-mode error, got: {r2_bad_mode}"

print("\n=== radare2_analyze: invalid base64 is rejected with a clear error, not a crash ===")
r2_bad_b64 = radare2_analyze.invoke({"content_b64": "not valid base64!!!", "mode": "info"})
print(r2_bad_b64)
assert "not valid base64" in r2_bad_b64, f"expected a base64 error, got: {r2_bad_b64}"

print(
    "\n=== radare2_analyze: a symbol value shaped like a shell/r2-command injection attempt "
    "is rejected, not passed through to the -c command string ==="
)
r2_injection = radare2_analyze.invoke(
    {"content_b64": _r2_b64, "mode": "disasm", "symbol": "main; !rm -rf /"}
)
print(r2_injection)
assert "Invalid symbol" in r2_injection, f"expected the injection attempt rejected, got: {r2_injection}"
