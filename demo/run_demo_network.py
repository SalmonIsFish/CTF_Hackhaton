"""One-command demo runner exercising the live-network tool path (fetch_url), against a
throwaway local HTTP server the demo spins up itself. This keeps the demo offline/deterministic
(no real internet target, nothing that can flake on a bad venue connection) while still proving
the network-tool code path — allowlist guard, live HTTP fetch, untrusted_data wrapping — actually
works end to end, not just in isolated unit tests.

This is additive: demo/run_demo.py (the static-file demo) is unchanged and still the primary
fallback if this one's server setup misbehaves on stage.

Usage:
    python -m demo.run_demo_network
"""
import http.server
import os
import socketserver
import sys
import threading

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from agent.graph import build_graph, message_text, run_config

FLAG = "flag{live_network_tool_works}"
HOST = "127.0.0.1"


class _FlagHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-Flag", FLAG)
        self.end_headers()
        self.wfile.write(b"nothing to see in the body, check the response headers\n")

    def log_message(self, format, *args) -> None:  # noqa: A002 - silence default request logging
        pass


def preflight() -> None:
    if not os.getenv("GOOGLE_API_KEY"):
        sys.exit(
            "GOOGLE_API_KEY is not set. Copy .env.example to .env and fill it in "
            "before running the demo — don't discover this mid-presentation."
        )


def main() -> None:
    preflight()

    httpd = socketserver.TCPServer((HOST, 0), _FlagHandler)
    port = httpd.server_address[1]
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    try:
        url = f"http://{HOST}:{port}/"
        prompt = (
            f"There's a web challenge running at {url} — fetch it and find the flag "
            "(check the response headers)."
        )

        print(f"=== Solving live network challenge at {url} ===\n")
        app = build_graph()
        result = app.invoke(
            {
                "messages": [HumanMessage(content=prompt)],
                "steps": 0,
                "flag": None,
                "category": None,
            },
            config=run_config(),
        )

        print("--- Tool calls made ---")
        for m in result["messages"]:
            if isinstance(m, AIMessage) and m.tool_calls:
                for call in m.tool_calls:
                    print(f"  {call['name']}({call['args']})")
            elif isinstance(m, ToolMessage):
                preview = m.content if len(m.content) <= 200 else m.content[:197] + "..."
                print(f"    -> {preview}")

        if not result["flag"]:
            print("\n--- Final answer ---")
            print(message_text(result["messages"][-1]))

        print(f"\nCategory : {result['category']}")
        print(f"Steps    : {result['steps']}")
        print(f"Flag     : {result['flag'] or '(not found)'}")

        if not result["flag"]:
            sys.exit(1)
    finally:
        httpd.shutdown()
        httpd.server_close()


if __name__ == "__main__":
    main()
