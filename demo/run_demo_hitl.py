"""One-command HITL demo: same throwaway-local-server pattern as run_demo_network.py, but
built with require_approval=True so the agent actually pauses at the terminal and asks a real
human before calling fetch_url against the target — the "Enforce Permissions" harness element
(#5) from the organizer's Next Steps slide, demonstrated live rather than just described.

This is interactive by design (reads from stdin via run_interactive() in agent/graph.py) — it's
the thing to run in front of a judge, not something CI/eval scripts should invoke unattended.
demo/run_demo_network.py (require_approval defaults to falsy) stays the automated/offline one.

Usage:
    python -m demo.run_demo_hitl
"""
import http.server
import os
import socketserver
import sys
import threading

from agent.graph import build_graph, run_interactive

FLAG = "flag{hitl_approval_works}"
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

        print(f"=== Solving live network challenge at {url} (approval required) ===\n")
        app = build_graph()
        result = run_interactive(app, prompt)

        if not result["flag"]:
            print("\n(no flag found — either the fetch was denied, or something else went wrong)")
            sys.exit(1)
    finally:
        httpd.shutdown()
        httpd.server_close()


if __name__ == "__main__":
    main()
