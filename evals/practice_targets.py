"""Local throwaway CTF-shaped practice targets, used by evals/practice_runs_network.py to
stress the network tools against realistic multi-step patterns the earlier single-shot
tests/demo didn't touch: a multi-turn login-gated TCP service, an HTTP redirect+cookie chain,
and a banner-emitting service for port_scan to find.

plus an "even modulus" RSA service that hands out N/e/ciphertext over a socket.

These are local stand-ins, not real picoCTF/organizer targets — see evals/practice_runs.md
for the explicit caveat about what running against these does and doesn't prove.
"""
import http.server
import random
import socketserver
import threading
from typing import Tuple, Type, Union

LOGIN_PASSWORD = "letmein"
LOGIN_FLAG = "flag{multi_turn_tcp_works}"
REDIRECT_FLAG = "flag{redirect_cookie_works}"
BANNER_TEXT = "SSH-2.0-OpenSSH_9.6p1"
EVEN_RSA_FLAG = "flag{even_modulus_rsa_works}"


class LoginGatedTCPHandler(socketserver.BaseRequestHandler):
    """Connect -> 'Password: ' -> wrong password closes the connection, right password ->
    a welcome line -> waits for a second command ('flag') before sending the flag. Requires
    a real tcp_open -> tcp_send -> tcp_send sequence to reach the flag."""

    def handle(self) -> None:
        self.request.sendall(b"Password: ")
        password_line = self._read_line()
        if password_line != LOGIN_PASSWORD:
            self.request.sendall(b"Access denied.\n")
            return
        self.request.sendall(b"Welcome! Type 'flag' to receive it.\n")
        command_line = self._read_line()
        if command_line == "flag":
            self.request.sendall(f"{LOGIN_FLAG}\n".encode())
        else:
            self.request.sendall(b"Unknown command.\n")

    def _read_line(self) -> str:
        data = b""
        self.request.settimeout(5.0)
        try:
            while not data.endswith(b"\n"):
                chunk = self.request.recv(256)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
        return data.decode("utf-8", errors="replace").strip()


class RedirectCookieHTTPHandler(http.server.BaseHTTPRequestHandler):
    """GET / -> 302 to /secure with a Set-Cookie header; GET /secure -> 200 with the flag in
    a header. Exercises fetch_url's allow_redirects=True path against a redirect+cookie
    chain, not just a flat 200."""

    def do_GET(self) -> None:
        if self.path == "/":
            self.send_response(302)
            self.send_header("Location", "/secure")
            self.send_header("Set-Cookie", "session=abc123; Path=/")
            self.end_headers()
        elif self.path == "/secure":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("X-Flag", REDIRECT_FLAG)
            self.end_headers()
            self.wfile.write(b"welcome back\n")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args) -> None:  # noqa: A002 - silence default request logging
        pass


class BannerTCPHandler(socketserver.BaseRequestHandler):
    """Sends a banner immediately on connect, unprompted — simulates the SSH-style
    banner-first behavior port_scan's passive banner read is meant to catch."""

    def handle(self) -> None:
        try:
            self.request.sendall((BANNER_TEXT + "\n").encode())
        except OSError:
            pass


class EvenRSATCPHandler(socketserver.BaseRequestHandler):
    """Prints N, e, and the ciphertext on connect and immediately closes — a faithful local
    stand-in for picoCTF's "Even RSA Can Be Broken", down to the misspelled "cyphertext" label.
    N is EVEN (one prime factor is literally 2), and, like the real service, every connection
    regenerates q and therefore N and c, so a run cannot pass by reusing a memorized value.

    Exists because the real target is an expiring per-session picoCTF instance: the end-to-end
    agent run that first needed rsa_decrypt_ints could not be re-verified against it minutes
    later (the instance had already gone down, connection refused). This keeps that whole path
    — tcp_open, read three big integers, rsa_decrypt_ints, flag — testable offline forever.
    """

    flag = EVEN_RSA_FLAG

    def handle(self) -> None:
        q = _random_prime(512)
        n = 2 * q
        e = 65537
        m = int.from_bytes(self.flag.encode(), "big")
        c = pow(m, e, n)
        try:
            self.request.sendall(f"N: {n}\ne: {e}\ncyphertext: {c}\n".encode())
        except OSError:
            pass


def _random_prime(bits: int) -> int:
    """Small local helper rather than a dependency — this file is deliberately stdlib-only, and
    the primality test lives with the tool under test (agent/tools/rsa_int_tools.py)."""
    from agent.tools.rsa_int_tools import is_probable_prime

    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def start_server(
    handler_cls: Union[Type[socketserver.BaseRequestHandler], Type[http.server.BaseHTTPRequestHandler]],
) -> Tuple[socketserver.TCPServer, int]:
    server = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port
