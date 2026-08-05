"""SSH-delivered CTF challenges: fetch-and-analyze a binary, or run one command with optional
piped stdin -- without handing the model a general-purpose remote shell.

Added because "Bypass Me" (picoCTF, Reverse Engineering) is delivered as `ssh host -p port`,
login as a given user/password, run a named binary and answer its password prompt -- a shape
none of the existing tools cover (tcp_open/tcp_send are raw TCP only, no SSH handshake/auth; the
existing live-network tools have no way to pull an arbitrary binary off a remote filesystem).

Deliberately narrow, matching the same reasoning radare2_analyze.py documents for skipping
pwntools/angr: not a full shell. ssh_analyze_binary only ever reads one named file (SFTP `open`
in read mode) and hands it straight to analyze_binary_bytes -- never writes, never executes it
remotely. ssh_run executes exactly one command per call with at most one line of piped stdin; it
cannot chain further commands within a single call (a second ssh_run call is a fresh connection).
The actual safety boundary here is the same one every other live-target tool already uses --
host-allowlist + optional HITL approval, gating *whether this target may be contacted at all* --
not a content-based command allowlist, which isn't practical for "run an arbitrary CTF binary and
answer its prompt" the way a fixed set of read-only radare2 commands was for static analysis.

ssh_analyze_binary exists specifically to avoid a fragility this project has hit before (see
CLAUDE.md's gemini-3.5-flash-lite base64-transcription note): fetching bytes server-side and
handing them straight to analyze_binary_bytes means a binary's raw content never has to survive a
model-generated tool call as a giant base64 string, the same reasoning fetch_and_decode_cipher
already applies to ciphertext.
"""
import time
from typing import Optional

import paramiko
from langchain_core.tools import tool

from agent.tools.radare2_analyze import analyze_binary_bytes

CONNECT_TIMEOUT_SECONDS = 15.0
MAX_EXEC_WAIT_SECONDS = 30.0
MAX_OUTPUT_CHARS = 8192
MAX_FILE_BYTES = 20 * 1024 * 1024  # matches radare2_analyze's own MAX_INPUT_BYTES


def _connect(host: str, port: int, username: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host, port=port, username=username, password=password,
        timeout=CONNECT_TIMEOUT_SECONDS, banner_timeout=CONNECT_TIMEOUT_SECONDS,
        auth_timeout=CONNECT_TIMEOUT_SECONDS,
    )
    return client


def _wrap_untrusted(source: str, body: str) -> str:
    return f'<untrusted_data source="{source}">\n{body}\n</untrusted_data>'


@tool
def ssh_analyze_binary(
    host: str, port: int, username: str, password: str, remote_path: str,
    mode: str, symbol: str = "main",
) -> str:
    """Fetch a binary from a live SSH/SFTP target and run radare2_analyze's static analysis on it
    in one call, server-side -- the binary's raw bytes never pass through you as a tool argument
    (unlike radare2_analyze, which needs content_b64 supplied inline). Use this whenever a
    challenge hands you SSH connection details rather than a file you already have bytes for
    (e.g. "ssh to host:port, login as X with password Y, then run the binary named Z" -- get the
    binary onto disk here first so you can actually see how it works before interacting with it).
    host/port/username/password are the SSH connection details -- read them directly from the
    challenge prompt exactly as given (these are throwaway per-instance CTF credentials, not real
    secrets). remote_path is the file's path on the remote machine (a bare filename like
    "bypassme.bin" works if it's in the login user's home directory). mode/symbol behave exactly
    as in radare2_analyze -- see that tool's docstring for the full mode list and the debug-info
    addressing caveat for "disasm" (hex vaddr over plain symbol name). Only ever reads the named
    file (SFTP open in read mode) -- never writes to or executes anything on the remote target.
    Hard-capped at a 15 second connection timeout and a 20 MB file size. Never raises -- a bad
    host/port, wrong credentials, missing remote file, or timeout all come back as a descriptive
    string instead of an error. The returned analysis is wrapped in <untrusted_data> tags, same as
    radare2_analyze and for the same reason."""
    try:
        client = _connect(host, port, username, password)
    except Exception as exc:
        return f"SSH connection to {host}:{port} failed: {type(exc).__name__}: {exc}"

    try:
        try:
            sftp = client.open_sftp()
        except Exception as exc:
            return f"SFTP session to {host}:{port} failed: {type(exc).__name__}: {exc}"
        try:
            try:
                file_size = sftp.stat(remote_path).st_size
            except FileNotFoundError:
                return f"Remote file not found: {remote_path}"
            if file_size > MAX_FILE_BYTES:
                return f"Remote file {remote_path} is {file_size} bytes -- capped at {MAX_FILE_BYTES} bytes."
            with sftp.file(remote_path, "rb") as f:
                content = f.read()
        except Exception as exc:
            return f"Fetching {remote_path} over SFTP failed: {type(exc).__name__}: {exc}"
        finally:
            sftp.close()
    finally:
        client.close()

    return analyze_binary_bytes(content, mode, symbol)


@tool
def ssh_run(
    host: str, port: int, username: str, password: str, command: str,
    stdin_text: Optional[str] = None, stdin_delay_seconds: float = 2.0,
    wait_seconds: float = 15.0,
) -> str:
    """Connect over SSH and run exactly one command, optionally sending one line of stdin
    partway through (e.g. answering a password prompt), then capture and return everything the
    command printed. This is the tool for "run the challenge binary and interact with its
    prompt" -- it is NOT a general-purpose shell: only one command runs per call, with no way to
    chain further commands within that same call (make another ssh_run call for a next step).
    host/port/username/password are the SSH connection details, read directly from the challenge
    prompt. command is the single command to run remotely (e.g. "./bypassme.bin"). stdin_text, if
    given, is sent as one line after stdin_delay_seconds (default 2s, tune this up if the program
    prints a slow intro/animation before its actual prompt) -- leave it unset for a command that
    needs no input. wait_seconds (capped at 30s) is how long to keep reading output after
    connecting before giving up and returning whatever was captured so far.
    Hard-capped at a 15 second connection timeout, wait_seconds capped at 30s, and 8 KB of output
    (truncated beyond that). Never raises -- connection/auth failures and timeouts come back as
    descriptive strings. The returned output is wrapped in <untrusted_data> tags, same as every
    other live-target tool -- a running CTF binary's output is exactly the kind of thing those
    tags exist for."""
    wait_seconds = min(wait_seconds, MAX_EXEC_WAIT_SECONDS)
    try:
        client = _connect(host, port, username, password)
    except Exception as exc:
        return f"SSH connection to {host}:{port} failed: {type(exc).__name__}: {exc}"

    try:
        chan = client.invoke_shell()
        chan.settimeout(wait_seconds)
        time.sleep(0.5)
        if chan.recv_ready():
            chan.recv(65536)  # discard login banner/motd, not part of the command's own output

        chan.send(command + "\n")

        output = ""
        deadline = time.time() + wait_seconds
        stdin_sent = stdin_text is None
        stdin_at = time.time() + stdin_delay_seconds if stdin_text is not None else None

        while time.time() < deadline:
            if stdin_at is not None and not stdin_sent and time.time() >= stdin_at:
                chan.send(stdin_text + "\n")
                stdin_sent = True
            if chan.recv_ready():
                output += chan.recv(65536).decode(errors="replace")
            else:
                time.sleep(0.3)
    except Exception as exc:
        return f"ssh_run against {host}:{port} failed: {type(exc).__name__}: {exc}"
    finally:
        client.close()

    truncated = output[:MAX_OUTPUT_CHARS]
    if len(output) > MAX_OUTPUT_CHARS:
        truncated += f"\n...[truncated, {len(output) - MAX_OUTPUT_CHARS} more chars]"
    return _wrap_untrusted(f"ssh_run:{host}", truncated)
