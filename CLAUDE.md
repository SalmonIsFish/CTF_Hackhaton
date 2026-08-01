# CTF_HACKHATON — Agent Harness Instructions
> Drop this in your repo root. Claude Code loads it automatically every session.
> Fill in the `[ ]` placeholders once your team locks the idea.

## Mission
[One sentence: what does the agent do, for whom, and what's the demo-day "wow" moment?]

## Agent Formula
`Agent = LLM + Tools + Loop + Context`, running the ReAct cycle: **Thought → Action → Observation → repeat.**
Every sub-agent and tool you add should map back to one of those four parts — if it doesn't, cut it before demo day.

---

## Current Status — Session Handoff (last updated: solo build session, agent core complete)

**Read this first if you're a fresh Claude Code session picking this up.** Everything below is verified with real runs, not assumed. For "what should I actually do next," see **`NEXT_STEPS.md`** instead — this file is the technical reference, that one's the TODO list.

### What's built and working
- `agent/model_router.py` — `get_model(provider)` for anthropic/google/groq, lazy-loaded via LangChain's `init_chat_model`, keys from `.env`
- `agent/graph.py` — LangGraph loop: **triage → think → act → observe → trim_context**, `MAX_STEPS = 15`, exits early when a tool result matches the flag pattern or the model returns no tool call. The `triage` node is the harness's "Sub-Agents" element (§3 #4) — a lightweight, separate model call that classifies the incoming prompt into one of `web/crypto/pwn/reverse/forensics/malware/osint/misc/ai-ml/blue-team/general` (`CATEGORY_SKILL_DIRS` in `agent/graph.py`), then `think`'s `SystemMessage` is built per-category (`build_system_prompt()`), nudging the model to ground its reasoning in that category's skill pack via `search_skills` before falling back to general knowledge. Verified working end to end (see test case 5 below): triage correctly routed a web-flavored prompt to `web` and an RSA prompt to `crypto`, each time producing an answer actually grounded in the right skill pack's content.
- `trim_context()` node in `agent/graph.py` — the harness's "State & Context Management" element (§3 #2). Runs once per loop iteration (after `observe`, before looping back to `think`); once more than `MAX_CONTEXT_MESSAGES` (16) think/act messages have accumulated, it drops the oldest ones via `RemoveMessage` (the `add_messages` reducer's delete-by-id mechanism), always keeping the first `HumanMessage` (the actual challenge prompt) untouched. Verified directly with a synthetic-state unit test in `evals/test_tools_smoke.py` (no API calls needed) rather than trying to force a real 15-step run just to trigger it.
- `message_text()` helper in `agent/graph.py` — Gemini sometimes returns `message.content` as a plain string and sometimes as a list of content blocks (thought-signature metadata attached); found this by chasing a real `AttributeError`/silent-`category`-fallback pair while building the triage node. Any code reading a message's final text (test assertions, the triage classifier) must go through this helper, not `.content` directly.
- `agent/api.py` — the FastAPI bridge Hasif's dashboard needs (see "Not yet done" history — this closes that gap). Run with `uvicorn agent.api:app --reload --port 8000`. `POST /solve` runs to completion and returns `{category, steps, flag, final_answer, tool_calls}`; `POST /solve/stream` is the same run as Server-Sent Events, one per graph node, for Hasif's live-trace UI. `SolveRequest` also takes an optional `target` field (host/IP/host:port) as a dashboard convenience — when set, it's folded into the prompt text (`Target: {target}\n\n{prompt}`) before the graph ever sees it, rather than carried as separate state, so it flows through the exact same `extract_allowed_hosts()` allowlist path a plain-text mention would. Omitting it (every existing caller) is unchanged. `extract_tool_trace()` (new helper in `agent/graph.py`, alongside `message_text()`) pairs each tool call with its result by `tool_call_id` for both endpoints. Verified both against the seeded demo challenge via FastAPI's `TestClient` — `/solve` returns the correct flag/trace, `/solve/stream` emits a correctly-paired, incrementally-growing trace (this needed a real fix: each node's "updates" stream event only carries *that node's* new/removed messages, so pairing an `AIMessage`'s call with its later `ToolMessage` result requires replaying the same upsert/delete-by-id logic the `add_messages` reducer itself uses, not just calling `extract_tool_trace` on each event in isolation). CORS is scoped to `localhost:3000`/`127.0.0.1:3000` (Next.js's dev port) — dev-only, tighten before deploying either service anywhere else.
- **Grounding priority is explicit, not left to chance**: `build_system_prompt()` tells the model to check `search_vault` (the team's own notes) *before* `search_skills` (the broader third-party library) — added after case 4 flaked once with only `search_skills` called (both tools legitimately cover "check response headers", so without an explicit order the model's choice between them isn't deterministic).
- Tools: `echo` (dummy, defined inline in `agent/graph.py`, not its own file), plus in `agent/tools/`: `find_flag_pattern` (regex for `flag{...}`/`CTF{...}`), `identify_and_decode` (base64/hex/rot13 — rot13 always "succeeds" on alphabetic input, documented in its own docstring/description), `search_vault` (substring search across `vault/*.md`, returns filename + line + context), `search_skills` (same substring-search shape, but across `.agents/skills/**/*.md` — this is what actually connects the 14 vetted skill packs to the competition-day agent; before this, they only helped Claude Code while building, per the distinction called out in §4)
- **Live-network tools** — added once the organizer's demo confirmed at least some challenges are handed out as a bare IP, not just a pasted artifact (previously the agent was a "semi-autonomous copilot" with zero tools that touched anything outside the local filesystem — see the old architecture note that used to live in `NEXT_STEPS.md`). Three tools in `agent/tools/`, all pure Python (no subprocess/shell, deliberately — see below): `fetch_url` (HTTP GET/POST via `requests`, 8s timeout, 8 KB response cap, never raises), `tcp_open`/`tcp_send`/`tcp_close` (`agent/tools/tcp_session.py` — a multi-turn `nc`/pwntools-`remote()`-style session: `tcp_open` returns a `session_id`, `tcp_send` reuses it for repeated send/receive turns against interactive services, `tcp_close` ends it explicitly), and `port_scan` (`agent/tools/port_scan.py` — sweeps a capped candidate port list via `socket.connect_ex()`, passively reads any banner a service volunteers unprompted on connect, e.g. SSH's version string; ports that accept a connection but say nothing are reported as such rather than guessed at). All three wrap their return value in `<untrusted_data source="...">` tags, and `build_system_prompt()` in `agent/graph.py` now always includes a fixed instruction not to treat that content as directives — the first tool output in this repo that's attacker-influenced rather than team-authored, worth taking seriously since a live target's response is exactly the kind of thing the "Defending the Harness" style guidance warns about.
  - **Safety, all in `agent/graph.py`**: `extract_allowed_hosts()` pulls the host/IP out of the original challenge prompt (regex over IPv4/`nc host port`/`host:port`/`http(s)://host[:port]` forms); `act()` refuses any `fetch_url`/`tcp_open`/`port_scan` call whose target isn't in that set, before the tool is ever invoked — computed fresh from the prompt every call, so it can't go stale or be talked around by a hallucinated host. `tcp_session.py` adds its own backstops since sessions are stateful across calls: max 3 concurrent sessions, a 60s absolute session lifetime (independent of idle time), and forced cleanup (`close_all_sessions()`) on every graph exit path (`route_after_think`'s early END, `route_after_observe`'s flag/MAX_STEPS/repeated-call END) so sockets never leak across runs. `port_scan` caps itself at 50 ports per call (even on a model-supplied list) with short per-port connect/banner timeouts, so one call can't turn into a long scan. `route_after_observe` also now ends the loop early (keeping partial results) if the last 3 tool calls were identical — a live target timing out or refusing is exactly the failure mode that invites blind retries, and those retries now risk hammering real scored infrastructure, not just wasting step budget.
  - **`port_scan` vs. real nmap** — a screenshot of the organizer's own reference harness (mid-conversation) showed a bare-IP challenge being scanned for open ports, service names, and version banners (`OpenSSH 9.6p1 Ubuntu`), confirming port discovery is a real need. But everything in that screenshot is reproducible without real nmap: port state comes from a plain connect attempt, and the SSH/OS-family lines come from reading the banner text SSH volunteers unprompted (not real fingerprinting). Real nmap was considered and deferred, not rejected: it isn't installed on the machine the agent actually runs on (confirmed Windows, not the WSL box `scripts/install_ctf_tools.sh` targets), and wrapping a subprocess call safely is its own unstarted task. Stays a Phase 4 stretch item in `NEXT_STEPS.md`, gated on installing nmap on the actual competition machine first.
  - **Explicitly scoped out for this event** (decided against the "Cybersecurity Toolset"/"Isolate Execution"/multi-agent-swarm style reference material the team was given): Docker sandboxing, Semgrep/Ghidra/Caido subprocess wrappers, and a Triage/Exploit/Reporting multi-agent swarm. Reasoning: no infra time to build or test any of them properly this week; the new tools are pure-Python with no shell surface, so Docker's threat model doesn't really apply here; the allowlist+timeout+loop-detection model above covers the actual new risk (hangs, runaway resource use, hitting the wrong host) at a fraction of the setup cost; and the existing single-graph triage-driven category system already gets most of the practical benefit a multi-agent split would add. Revisit only with real spare time or evidence organizer challenges need it.
  - **Validated against realistic local scenarios** (`evals/practice_runs_network.py`, results in `evals/practice_runs.md`), not just the original single trivial local server: a genuinely multi-turn login-gated TCP service (`tcp_open`→`tcp_send`→`tcp_send` to reach the flag), an HTTP redirect+cookie chain (`fetch_url` follows a 302+`Set-Cookie` to the final response in one call), and a port sweep with one banner-emitting open port among closed ones. All three pass.
  - **Also validated against a real (non-localhost) internet target** — `evals/real_target_check.py`, a one-off manually-run script (deliberately not part of the automatic test suite, since it depends on real internet + someone else's infrastructure) against `scanme.nmap.org`, nmap's own public scanning-practice box. Port-state detection was solid both times it ran; SSH's banner was never actually captured, even after widening `port_scan`'s timeouts (`CONNECT_TIMEOUT_SECONDS` 0.6→1.0s, `BANNER_TIMEOUT_SECONDS` 0.8→1.5s, now the shipped default) — a genuine, honest limitation worth knowing: banner capture is best-effort against a real host, not guaranteed the way an instant-responding local test server is. Still open: validation against a *real CTF-shaped* target — needs a human to hand over an actual picoCTF/organizer host:port, since picoCTF instances are per-account/per-session and no organizer challenge IP exists yet.
  - New seeded demo: `python -m demo.run_demo_network` spins up a throwaway local HTTP server and solves it via `fetch_url`, exercising the real network-tool code path while staying fully offline/deterministic — same one-command, fail-fast, non-zero-exit-on-no-flag contract as `demo/run_demo.py` (which is unchanged and still the primary static-file demo/fallback).
- **Two more real external targets — TryHackMe "SecNotes" and HackTheBox "Desires"** (both custom/private challenges, not the well-known public HTB machines sharing those names). Full write-ups in `evals/practice_runs.md`. Desires ended in a **captured flag** (`HTB{S0m3tIm3s_Its_J4usT_A_B!G_M3ss}`), the first fully solved live external target this project has run against; SecNotes remains unsolved (a genuinely airtight loopback-only `/flag` gate with no reachable SSRF surface in its source — confirmed, not just unproven). Found and fixed four real bugs along the way, all still relevant beyond these two specific challenges:
  - `fetch_url` had no way to set request headers (couldn't send `Content-Type: application/json`, silently breaking POSTs to any `express.json()`-style backend) — added an optional `headers` param.
  - `act()` in `agent/graph.py` had no error handling around tool invocation — one malformed tool call (a model-hallucinated nested dict) crashed the entire graph run with an uncaught pydantic `ValidationError` instead of surfacing as a recoverable `ToolMessage`. Fixed via a small `invoke_tool()` wrapper that catches broadly and returns the error as a normal tool result, same "never raises" contract the tools themselves already have.
  - `think()` had the same class of gap one layer up: a real `429 RESOURCE_EXHAUSTED` from Gemini's free tier (confirmed **15 requests/minute**, separate from and tighter than the documented 500/day) crashed the whole run from `model.invoke()`. Fixed to end the run cleanly instead.
  - While fixing that, found the multi-key rotation feature (`_RotatingChatModel`, `agent/model_router.py`) **had never actually worked against a real quota error** — it caught `google.genai.errors.APIError` directly, but `langchain-google-genai` wraps that in its own `ChatGoogleGenerativeAIError` first, so the except clause only ever matched the unit test's unwrapped mock, never a real response. Fixed by walking the exception's `__cause__` chain; added a regression test using a stub that wraps the error the same way the real library does.
  - New tool: `upload_file` (`agent/tools/upload_file.py`) — `fetch_url` has no multipart/file-upload support at all, a real gap for the (common) file-upload-challenge category. Takes base64-encoded content (tool args are text-only) plus optional headers/extra form fields.
  - **Also found, not yet fixed**: `gemini-3.5-flash-lite` is unreliable at reproducing a large (~4000+ char) base64 blob verbatim inside a tool call — a real exploit payload got corrupted in the model's own regeneration of the string (confirmed: the *identical* payload worked immediately when the tool was invoked directly, bypassing the model). Worth designing around for any future challenge needing a sizeable binary payload delivered via a tool call — e.g. a file-reference-based upload path instead of inline content — rather than assuming large text args survive a tool call unchanged.
- **Organizer slide compliance (HITL, telemetry, Docker) — done, see `NEXT_STEPS.md` Phase 0 for the full writeup.** The organizer stopped answering clarifying questions and the only concrete guidance left was a "Next Steps: Implementation" slide (Isolate Execution / Enforce Permissions / Full Telemetry, on top of the framework choice already made). All three are now real, not slideware:
  - **Enforce Permissions (HITL)**: `agent/graph.py`'s `act()` gates `fetch_url`/`tcp_open`/`port_scan` behind LangGraph's `interrupt()` when `require_approval` is set on `AgentState`, using an always-attached `MemorySaver` checkpointer. CLI: `run_interactive()` + `demo/run_demo_hitl.py` (drives a real terminal approve/deny prompt). HTTP: `agent/api.py`'s `/solve`/`/solve/stream` return a `pending_approval` payload instead of finishing, `POST /solve/resume` continues it. Verified both approve and deny paths end-to-end (deny never leaks the flag), plus a full regression pass of the existing 5-case suite and both demos with no change in behavior. Every `graph.invoke`/`graph.stream` call site now needs a `thread_id` (the checkpointer requires one even on runs that never interrupt) — use the new `run_config()` helper, not a hand-built config dict.
  - **Full Telemetry**: near-zero-cost since `langsmith`/`langgraph-checkpoint` were already transitive deps. `run_config()` tags LangSmith traces when `LANGCHAIN_TRACING_V2` is set (see `.env.example` — off by default, and turning it on sends live challenge/tool data to a third-party service, flagged explicitly rather than silently enabled). Independent of that: `log_run()` appends one JSON line per completed run to `evals/run_log.jsonl` (gitignored), wired into `run_case()`, `run_interactive()`, and all three `/solve*` endpoints. Verified inert with tracing unset, and verified `run_log.jsonl` populates correctly from all three entry points (the streaming endpoint needed a real fix: the initial `HumanMessage` never appears in any node's `stream_mode="updates"` delta, so it had to be pre-seeded into the by-id message map or the logged prompt came back `null`).
  - **Isolate Execution (Docker)**: `Dockerfile` + `docker-compose.yml` (repo root) containerize `agent/api.py` on `python:3.14-slim` (matches the local interpreter exactly), non-root user, `read_only: true` root filesystem with a `/tmp` tmpfs, `mem_limit`/`cpus` caps, dedicated bridge network. Verified for real: `docker build` succeeds, `docker run` and `docker compose up` both serve `/health`, `docker exec whoami` confirms non-root, a write outside `/tmp` fails with "Read-only file system" while `/tmp` itself works, and both a plain `echo`-flag solve and a real live-network solve (`fetch_url` reaching a host-side server via `host.docker.internal`) succeeded through the containerized API. Honestly scoped: this is process/filesystem isolation and resource caps, not per-challenge dynamic network egress control — the tools have no shell/subprocess surface to begin with, so the host allowlist (`extract_allowed_hosts()`/`act()`) stays the actual network control, unchanged.
- `.mcp.json` — wired to **seekstone** (filesystem-based, no Obsidian app or plugin needed). Note: the original plan referenced `mcpvault`, which turned out to be placeholder text, not a real npm package — corrected to seekstone. **Security-reviewed this session — clean.** Community-published (16 stars, 1 fork — not on officialskills.sh-style vendor accountability) but genuinely well-engineered: CI, CodeQL, OpenSSF Scorecard, Dependabot all actually running, and — unlike most third-party vetting — the safety claims are backed by real tests, not just docs. Read the source of all 8 write-capable tools (`create_note`, `delete_note`, `move_note`, `append_note`, `patch_note`, `patch_frontmatter`, `replace_in_note`, `periodic_note`): every one independently checks the resolved path stays under `vaultRoot` before touching disk. `no-network.test.ts` mocks Node's raw `net.connect`/`http.request`/`https.request` to throw, then runs every tool including full indexing — proves zero outbound calls, not just "we don't call fetch that we know of." Dependencies are minimal and reputable (`@modelcontextprotocol/sdk`, `chokidar`, `fast-glob`, `minisearch`, `yaml`, `zod`). One caveat worth knowing, not fixing: `.mcp.json` sets `SEEKSTONE_VAULT=./vault`, a relative path, while seekstone's own `--help` documents this var as absolute — `index.ts` uses it as-is with no `path.resolve()`, so this only resolves correctly because Claude Code launches the process with CWD = repo root. Works fine in practice; a hardcoded absolute path would just break portability across teammates' machines instead, so this is a documented tradeoff, not a bug to chase.
- `.agents/skills/` — **14 third-party skill packs** total, all vetted in `SKILLS_VETTING.md` (full log) with `skills-lock.json` (hash-pinned source manifest):
  - 11 offensive CTF-technique packs from `ljagiello/ctf-skills` (`npx skills add`). Automated scanners flagged `ctf-web` and `ctf-osint` "Critical," but both a manual file grep at install time and a follow-up spot-check found no obfuscation, credential exfiltration, or base64 payload blobs — every `/etc/passwd`-style hit is standard LFI/traversal documentation. Team decision: keep all 11 installed.
  - 3 defensive/blue-team packs from `arttapon1/defensive-soc-skills` (`ir-report-builder`, `siem-detection-engineer`, `soar-playbook-builder`) — added to cover SOC/IR/detection-engineering knowledge the offense-only packs don't have. Content-level review (all 4 scripts + all 3 SKILL.md read directly) came back clean, but this repo has essentially no community track record (7 stars, 7 commits, one author) — accepted for a hackathon project, flagged as a real caveat.
- `evals/test_tools_smoke.py` — standalone tests for all four real tools (`find_flag_pattern`, `identify_and_decode`, `search_vault`, `search_skills`) plus a direct unit test of `trim_context`'s trimming logic, passing
- `agent/graph.py`'s `__main__` block — 5 end-to-end test cases, **all passing** on `gemini-3.5-flash-lite`:
  1. Plain echo (baseline loop works)
  2. Echo a flag → confirms early-exit works, doesn't run to MAX_STEPS
  3. Double-encoded flag (base64 of hex) → confirms **multi-step tool chaining** across loop iterations, not just single calls
  4. Vault lookup question → confirms the model calls `search_vault` (not just answering from training data) and grounds its answer in `vault/Web_Placeholder.md`
  5. RSA-attack question → confirms **sub-agent triage routes to `category: crypto`**, the model calls `search_skills`, and the answer is grounded in a real technique from `ctf-crypto`'s RSA attack notes (Wiener/Coppersmith/common modulus/low exponent)
- `demo/` — harness element #9 (Deploy/Demo Readiness). `python -m demo.run_demo` is the one-command entrypoint: fails fast with a clear message if `GOOGLE_API_KEY` isn't set (instead of a confusing API error mid-run), solves the seeded `response_headers.txt` challenge (a captured HTTP response with a base64-of-hex flag in a custom header — deliberately solvable with only the tools that already exist, no live target or network dependency), and exits `1` if no flag was found so a regression shows up as a failing command before demo day. `expected_transcript.txt` is a captured successful run, checked in as a **text fallback** if live tools flake on stage — **still need an actual rehearsed screen recording before the event**, this transcript is a placeholder until that's done, not a replacement for it.

### Model choice — hard-won today, don't relitigate without new evidence
- **Default is `gemini-3.5-flash-lite`** (Google), not `gemini-flash-latest`/`gemini-3.6-flash` — that one only has a 20-requests/day free quota and gets exhausted fast. `gemini-3.5-flash-lite` has 500/day and passed all 5 cases including chaining and sub-agent triage.
- `gemini-2.5-flash` — **retired**, 404s on this key regardless of quota. Don't retry it.
- `gemini-2.0-flash` — zero free-tier entitlement on this key. Don't bother.
- Groq `gpt-oss-120b` — reliable tool-call *syntax*, but **fails multi-step chaining** (case 3): calls `echo` redundantly instead of re-decoding, states the flag as prose instead of through a tool. Not suitable as primary.
- Groq `llama-3.3-70b-versatile` — reproducibly emits malformed tool-call syntax, rejected by Groq as `400 tool_use_failed`. This is a known, documented issue with Llama models + tool-calling generally, not specific to this project. Don't use for anything requiring tool calls.
- Full comparison table lives in `evals/practice_runs.md`.

### Known harmless noise (don't waste time on these)
- `UserWarning: Core Pydantic V1 functionality isn't compatible with Python 3.14` — cosmetic, from LangChain's compat shim, not a real failure.
- Windows console may show `�` for em-dashes — cosmetic terminal encoding, not file corruption (confirmed the underlying files are clean UTF-8).

### Not yet done
**→ See `NEXT_STEPS.md`** — pulled into its own file so this section doesn't turn into a running task list that drifts out of sync. Short version: teammates haven't started their pieces, and several organizer questions are still unanswered.

### Toolchain setup — resolved issues (reference if setting this up on a fresh machine)
`scripts/install_ctf_tools.sh all` is fully installed and verified on WSL Ubuntu (`bash install_ctf_tools.sh --verify` reports **56/58 found**). Two items are permanently/trivially not-found, not worth chasing:
- `py:ropper` — permanent, unfixable on Python 3.14. Its dependency `filebytes` calls `ast.Str`, a Python API removed in 3.12+; that package is unmaintained upstream. `ROPgadget` (installed, does the same job) is the substitute.
- `ffuf` — not actually broken, just not on `$PATH` yet. The Go install put the binary at `~/go/bin/ffuf`; add `export PATH="$PATH:$(go env GOPATH)/bin"` to `~/.bashrc`.

Real upstream bugs hit and fixed along the way, worth knowing if re-running this on a fresh machine:
- Python 3.14 is too new for several packages to have prebuilt wheels yet (`unicorn`, `angr`'s x86_64 wheel, `yara-python`, etc. for the exact pinned versions), forcing source builds that need `build-essential cmake python3.14-dev libssl-dev zlib1g-dev libjpeg-dev libfreetype6-dev rustc cargo` (angr's own package has a Rust build step) — install all of these up front next time.
- `unicorn==2.1.2`'s own CMake build has a real bug: `qemu/osdep.h` gates `sys/mman.h` behind `#ifdef CONFIG_POSIX`, which the CMake path never defines (confirmed by direct source build) — this is why `mprotect`/`PROT_*` errors showed up. Not worth patching directly: `angr`/`qiling`'s looser dependency constraints pull in `unicorn==2.1.4` instead, which ships a working `abi3` wheel (no compile needed).
- `pwntools==4.15.0` explicitly excludes `unicorn!=2.1.3,!=2.1.4` in its own metadata, so a plain `pip install pwntools` tries to build the broken 2.1.2 from source. Fix: `pip install --no-deps pwntools==4.15.0`, then install its other real dependencies (paramiko, mako, pyelftools, ropgadget, pyserial, requests, pygments, pysocks, python-dateutil, packaging, psutil, intervaltree, sortedcontainers, six, rpyc, colored_traceback, unix-ar, zstandard) manually. pip will warn about the unicorn version mismatch — harmless; core pwntools features (`ELF`, packing, process/remote I/O) don't touch unicorn at all.
- `angr==9.2.193` failed to *import* (not install) due to `pycparser` 3.0 (a new, breaking major release) removing the ability to set `CLexer.filename`, which `angr`'s bundled `pyvex` relies on. Fix: `pip install pycparser==2.23` (last 2.x release).
- `fpylll==0.6.4` was missing an undeclared dependency, `cysignals` — `pip install cysignals` fixes it.
- All of the above venv work happens inside `~/.ctf-tools/venv` (created by the script itself, since this Ubuntu's Python 3.14 is "externally managed" per PEP 668) — never `pip install` outside it.

---

## 1. Team Roles (built for mixed access — 3 free-tier, 1 no laptop)

The bottleneck in most hackathons isn't the idea, it's serializing work through one paid tool. Decouple roles so nobody blocks on Claude Pro:

| Person | Access | Owns | Why this split |
|---|---|---|---|
| You | Claude Code CLI | Agent core: LangGraph/Pydantic AI state graph, harness, Obsidian MCP wiring, final integration | Only role that strictly needs Claude Code |
| Hasif | Free-tier model + laptop | Frontend: Vercel AI SDK streaming UI | Frontend work barely touches the agent's model choice |
| Rashid | Free-tier model + laptop | Prompts, sub-agent design, eval harness, test cases | Can iterate entirely against a free API, no Claude needed |
| Farhan | No laptop | Obsidian vault (mobile app), pitch narrative, demo script, judge Q&A prep, live QA of the deployed demo from their phone | Obsidian has first-class iOS/Android apps — this role needs zero dev environment |

Detailed, step-by-step task briefs for Hasif, Rashid, and Farhan are in `TEAM_TASKS.md`.

Git workflow: small feature branches (`frontend/*`, `agent/*`, `prompts/*`), PR into `main` every 60–90 min, integrate early and often — don't save integration for the last hour.

## 2. Free-Tier Model Routing (updated with verified findings — see Current Status above)
Since only you have Claude Code, keep the agent's *model provider* swappable so teammates can build/test against something they can actually call for free. The specific model choices below aren't the original plan — they're what actually survived real testing:

```python
# model_router.py — as of tonight's build
from langchain.chat_models import init_chat_model
from dotenv import load_dotenv
load_dotenv()

_PROVIDERS = {
    "anthropic": lambda: init_chat_model("claude-sonnet-4-6", model_provider="anthropic"),
    "google":    lambda: init_chat_model("gemini-3.5-flash-lite", model_provider="google_genai"),  # NOT gemini-flash-latest — see below
    "groq":      lambda: init_chat_model("llama-3.3-70b-versatile", model_provider="groq"),  # has known tool-call bugs — see below
}

def get_model(provider: str = "google"):
    if provider not in _PROVIDERS:
        raise ValueError(f"Unknown provider '{provider}'. Choose from: {list(_PROVIDERS)}")
    return _PROVIDERS[provider]()
```

**Update — multi-key rotation added.** The `"google"` provider above is no longer a bare `init_chat_model()` call; it's wrapped in `_RotatingChatModel` (`agent/model_router.py`), which holds one underlying model instance per key from `GOOGLE_API_KEYS` (comma-separated, see `.env.example`) and rotates to the next key on a real `429`/`RESOURCE_EXHAUSTED` from `google.genai.errors.APIError` — competition-day insurance if multiple teammates are hitting the agent against one key's daily quota. Falls back to the single existing `GOOGLE_API_KEY` if `GOOGLE_API_KEYS` isn't set, so this is purely additive — nobody's `.env` needed to change. Only a quota-shaped error triggers rotation; any other exception propagates immediately, same as before. The sticky current-key index means a long run doesn't re-try an already-exhausted key first every time. Verified with stubbed model objects in `evals/test_model_router_smoke.py` — no real quota exhaustion needed to test the rotation logic itself. `get_model(provider).bind_tools(TOOLS)` and `.invoke(...)` in `agent/graph.py` needed no changes — `_RotatingChatModel` implements both methods with the same interface.

**Why `gemini-3.5-flash-lite` and not the more obvious `gemini-2.5-flash` or `gemini-flash-latest`:** rate limits on Google AI Studio are per-model, not per-account, and they vary wildly — `gemini-flash-latest` (resolves to `gemini-3.6-flash`) is capped at 20 requests/day on a free key, which is not enough for a full competition day. `gemini-2.5-flash` is retired entirely on newer keys. `gemini-3.5-flash-lite` has 500/day and, importantly, passed the hardest test (multi-step tool chaining) that a faster/cheaper Groq model failed. Check current rate limits yourself before the competition — these change and shouldn't be trusted from memory (yours or Claude's): Google AI Studio's own dashboard shows live, per-model numbers for whatever key you're using.

**Why not just use Groq as primary despite the free-tier headroom being larger:** raw request quota doesn't matter if the model can't reliably format tool calls. Verified today: Llama models on Groq have a known, reproducible issue emitting malformed tool-call syntax that gets rejected outright. A newer OpenAI-lineage model on Groq (`gpt-oss-120b`) fixed that specific problem but was worse at *multi-step* reasoning (chaining two tool calls in sequence) — which matters more for CTF challenges than raw syntax correctness. Don't assume this is fixed without re-testing; open-model tool-calling reliability is genuinely inconsistent across providers and versions.

You keep Claude Code for orchestration/dev work; the shipped agent runs on whichever provider actually passed the eval suite — check `evals/practice_runs.md` before changing the default.

**`ANTHROPIC_API_KEY` is intentionally absent from `.env`** (not an oversight) — the team deliberately runs on the `google` provider only, since it has the highest free-tier request quota of the three. The `anthropic` entry in `model_router.py` above is not expected to be usable without adding a key.

## 3. Agent Harness Checklist
Your brief named 5 elements under "9 Harness Elements" — here's the full 9 so nothing's missed at integration time:

1. **Control Loop** — bounded `while`/graph loop, explicit max-steps and exit conditions
2. **State & Context Management** — trim/summarize context between turns; don't let it grow unbounded
3. **Modular Skills & Tools** — typed params + Pydantic/Zod validation, one clear docstring per tool
4. **Sub-Agents** — Explore → Plan → Code → Test (or your domain's equivalent), sequential or parallel
5. **Safety & Observability** — lifecycle hooks, guardrails, least-privilege tool permissions, human-in-the-loop on destructive actions
6. **Model/Provider Routing & Fallback** — see §2; if Groq/Gemini free tier rate-limits mid-demo, fall back gracefully
7. **Memory & Persistence** — short-term (per-run) vs long-term (cross-session). This is where Obsidian comes in (§4).
8. **Evaluation Harness** — even 5–10 hand-written test cases beat none; run them before every merge to `main`
9. **Deploy/Demo Readiness** — one-command startup, seeded demo data, a fallback recording in case live tools flake on stage

## 4. Obsidian Integration
Obsidian works well here as your agent's **long-term memory / knowledge base**, and it's the natural home for Teammate C's mobile-only contributions (notes, pitch draft, task list — all sync automatically into the vault the agent reads from).

**Update: already set up, using `seekstone`.** The original two options below are kept for context, but `mcpvault` (previously listed) turned out to be placeholder text, not a real package — it 404s on npm. The repo now uses **seekstone** (github.com/shaqmughal/seekstone), a real filesystem-direct server, confirmed connected via `claude mcp list`.

✅ **Security-reviewed — clean, see the "What's built and working" bullet above for the full writeup.** It's community-published (not an official/vendor package) with read+write access to `vault/`, but the source backs up its safety claims with actual tests (a dedicated test blocks Node's network primitives and proves the server never phones home) rather than just documentation, and every write-capable tool independently validates paths stay inside the vault. One documented, low-severity caveat: our `.mcp.json` uses a relative `SEEKSTONE_VAULT` path, which only resolves correctly because of Claude Code's launch CWD — works fine in practice, noted for awareness.

Two MCP server options, for reference:

| Option | Needs Obsidian running? | Setup time | Good for |
|---|---|---|---|
| `mcp-obsidian` (REST API plugin-based) | Yes | ~10 min (install community plugin + API key) | Most documented, widest adoption |
| Filesystem-based server (e.g. `seekstone`) | No — reads the vault folder directly | ~5 min | Faster hackathon setup, no plugin dependency — **this is what's in use** |

`.mcp.json` (project-level, so the whole team's Claude Code sessions pick it up) — this is the actual file, corrected from an earlier stale example that showed the vault path as a positional CLI arg rather than the `SEEKSTONE_VAULT` env var seekstone actually reads:
```json
{
  "mcpServers": {
    "obsidian": {
      "command": "npx",
      "args": ["-y", "seekstone"],
      "env": {
        "SEEKSTONE_VAULT": "./vault"
      }
    }
  }
}
```
**Important distinction, easy to conflate:** this `.mcp.json` wires the vault into **Claude Code** (so it can read vault notes while helping you build) — it does **not** automatically wire the vault into the actual competition-day agent. That's handled separately by the `search_vault` tool in `agent/tools/`, a plain Python function that reads `vault/*.md` directly. Two different consumers of the same folder; don't assume one gives you the other.

New MCP servers found in `.mcp.json` require one-time interactive approval (`claude mcp list` will show "Pending approval" until you run `claude` in a real interactive terminal and approve it — doesn't work through piped/non-interactive sessions). Already approved for "this and future servers in this project" as of this handoff, so this shouldn't prompt again on this machine.

## 5. Vetting Third-Party Skills (skills.sh)
Worth knowing before your team installs anything: independent audits in 2026 (Snyk's ToxicSkills study, the ClawHavoc campaign) found real malicious skills distributed through skills.sh and ClawHub — credential exfiltration, backdoors, prompt injection — and researchers later showed the platform's automated malware scanner can be bypassed with basic obfuscation. So **no one can hand you a verified "safe" list**, including me — treat every third-party skill like an unreviewed code dependency.

Before installing any skill from skills.sh:
- [ ] Prefer **officialskills.sh** (vendor-published: Anthropic, Cloudflare, Microsoft, Stripe, etc.) over random community entries — known publisher = real accountability.
- [ ] Open the GitHub repo and actually read `SKILL.md` and any bundled scripts before running `npx skills add` — skills are Markdown + scripts, fully human-readable.
- [ ] Grep for red flags: calls to `curl`/`wget`/`fetch` against unfamiliar domains, base64-looking blobs, reads of env vars or credential files, unusually long lines or excessive blank/newline padding (a documented scanner-evasion trick).
- [ ] Check the `allowed-tools` frontmatter — a skill that only needs to read files shouldn't be requesting unrestricted `Bash`.
- [ ] Avoid ClawHub entirely for this event — it's the platform named in the 2026 ClawHavoc campaign.
- [ ] When in doubt, just write your own `SKILL.md` — for a 5-person hackathon team, a hand-written skill takes 10 minutes and carries zero supply-chain risk.

## 6. Repo Structure (as actually built, not just planned)
```
CTF_Hackhaton/
├── CLAUDE.md              ← this file (technical reference: what's built, why, how)
├── NEXT_STEPS.md          ← the TODO list — what's left, in priority order
├── TEAM_TASKS.md          ← detailed per-person task briefs
├── .env / .env.example    ← API keys (ANTHROPIC_API_KEY, GOOGLE_API_KEY, GROQ_API_KEY, optional
│                             LANGCHAIN_TRACING_V2/LANGCHAIN_API_KEY for LangSmith) — .env is gitignored
├── .gitignore
├── requirements.txt
├── Dockerfile             ← Isolate Execution (harness #5) — containerizes agent/api.py, non-root, read-only
├── .dockerignore
├── docker-compose.yml     ← mem/cpu caps, read-only root fs + /tmp tmpfs, dedicated bridge network
├── .mcp.json              ← seekstone (Obsidian vault access for Claude Code)
├── SKILLS_VETTING.md      ← vetting log for third-party skills.sh installs
├── skills-lock.json       ← hash-pinned source manifest for installed skills
├── .agents/
│   └── skills/            ← 14 third-party skill packs: 11 offensive (ljagiello/ctf-skills)
│                             + 3 defensive/blue-team (arttapon1/defensive-soc-skills)
├── agent/
│   ├── model_router.py    ← done, verified
│   ├── graph.py           ← done, verified — triage → think → act → observe → trim_context loop,
│   │                         5 passing test cases in __main__ (echo tool defined inline here)
│   ├── api.py             ← done, verified — FastAPI bridge for the dashboard (`uvicorn agent.api:app`)
│   └── tools/
│       ├── find_flag_pattern.py     ← done, verified
│       ├── identify_and_decode.py   ← done, verified
│       ├── search_vault.py          ← done, verified
│       ├── search_skills.py         ← done, verified — connects .agents/skills/ to the runtime agent
│       ├── fetch_url.py             ← done, verified — live HTTP GET/POST, timeout+size capped,
│       │                                optional `headers` dict (added after a real target's
│       │                                express.json() backend silently rejected bodies without it)
│       ├── upload_file.py           ← done, verified — multipart/form-data file upload
│       │                                (base64-encoded content_b64, since tool args are text-only);
│       │                                fetch_url has no way to do this, added for file-upload challenges
│       ├── tcp_session.py           ← done, verified — multi-turn nc/remote()-style TCP session
│       │                                (tcp_open/tcp_send/tcp_close), session cap + lifetime cap
│       └── port_scan.py             ← done, verified — pure-Python port sweep + passive banner
│                                        grab, no subprocess/nmap; capped ports-per-call
├── demo/                  ← harness element #9 (Deploy/Demo Readiness)
│   ├── run_demo.py            ← one-command entrypoint: `python -m demo.run_demo` (static-file demo)
│   ├── run_demo_network.py    ← one-command entrypoint: `python -m demo.run_demo_network`
│   │                             (live-network-tool demo, offline via a throwaway local server)
│   ├── run_demo_hitl.py       ← `python -m demo.run_demo_hitl` — same setup, require_approval=True,
│   │                             drives a real terminal approve/deny prompt (Enforce Permissions)
│   ├── response_headers.txt   ← seeded demo challenge, solvable offline with existing tools
│   ├── expected_transcript.txt ← captured successful run, text fallback until a real recording exists
│   └── README.md
├── frontend/              ← not started (Hasif's part)
├── evals/
│   ├── test_tools_smoke.py       ← standalone tool tests + trim_context unit test, passing
│   ├── test_model_router_smoke.py ← _RotatingChatModel rotation logic, stubbed models, passing
│   ├── practice_targets.py       ← local CTF-shaped practice servers (login-gated TCP,
│   │                                 redirect/cookie HTTP, banner TCP) for full-loop testing
│   ├── practice_runs_network.py  ← runs the full agent loop against practice_targets.py,
│   │                                 not just the tool in isolation — all 3 scenarios pass
│   ├── real_target_check.py      ← one-off, manually-run: python -m evals.real_target_check
│   │                                 against scanme.nmap.org (real internet target, not local)
│   ├── run_log.jsonl             ← gitignored — local telemetry, one JSON line per completed
│   │                                 run, written by agent/graph.py's log_run()
│   └── practice_runs.md      ← model comparison findings + picoCTF/network results go here
└── vault/
    ├── README.md              ← placeholder, explains folder purpose
    └── Web_Placeholder.md     ← test fixture only — replace/expand with Farhan's real notes
```

## 7. Rough Timeline
- **Hour 0–1:** Lock the idea, fill in this file's placeholders, split branches
- **Hour 1–N-4:** Parallel build — agent core / frontend / prompts+evals / vault+pitch, merge every 60–90 min
- **N-4 to N-2:** Integration pass — everything talks to everything, run the eval set
- **N-2 to N-1:** Demo script rehearsal (Teammate C leads), record a fallback video
- **Last hour:** Buffer only — no new features
