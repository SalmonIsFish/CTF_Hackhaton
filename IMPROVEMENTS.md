# Improvements — Broader Review (triage later, NOT done the night before)

> Written during the night-before reliability pass (see `git log` / the reliability fixes to
> `find_flag_pattern.py`, `graph.py`, `api.py`, `model_router.py`, `.env.example`). Those fixes
> were the safe, high-value, low-risk changes. **This file is everything else** — real
> improvements that are too invasive, too speculative, or too low-priority to touch right before
> a competition. Nothing here is urgent; it's a triage list for after the event.
>
> Ordered roughly by value-per-risk. Each item says what, why, and a concrete first step.

## Already shipped in the reliability pass (for context, don't redo)
- Configurable flag prefixes (`FLAG_PREFIXES` env + per-request `flag_prefixes`).
- `/health` recognizes `GOOGLE_API_KEYS`.
- Groq fallback model fixed (`llama-3.3-70b-versatile` → `openai/gpt-oss-120b`).
- Env-configurable CORS (`CORS_ORIGINS`).
- Per model-call timeout (`MODEL_TIMEOUT_SECONDS`, default 60s).
- radare2 smoke test skips gracefully without WSL instead of hanging the suite.

---

## 1. MemorySaver checkpoints grow unbounded over a long server day
**Where:** `agent/api.py` `get_app_for_provider()` (`@lru_cache`) + `build_graph()`'s
`MemorySaver()` (`agent/graph.py`).

**What:** The graph is compiled once per provider and cached for the whole server lifetime, and it
carries an in-memory `MemorySaver`. Every `/solve` (and `/solve/stream`) mints a fresh
`thread_id`, and `MemorySaver` keeps a checkpoint per thread **forever** — it never evicts. Over a
full competition day of many runs, memory grows monotonically. Not a crash risk in a short demo,
but a real leak for a long-lived process.

**Why it matters:** the server may be up all day; a slow leak is exactly the kind of thing that
bites hours in, mid-competition, with no obvious cause.

**First step:** after a *completed* (non-interrupted) run in `/solve` and `/solve/stream`, delete
that thread's checkpoint. Check whether the installed LangGraph exposes a
`checkpointer.delete_thread(thread_id)` (or equivalent) API; if so, call it in a `finally`. If not,
swap `MemorySaver` for a small bounded/TTL checkpointer wrapper. HITL runs must keep their thread
until resumed/abandoned, so only clean up threads that actually reached an end state.

## 2. Triage spends a full extra model call on every run
**Where:** `agent/graph.py` `triage` node.

**What:** Each run makes a separate `triage_model.invoke()` to classify the category before the
first `think` step. On Gemini's free tier (~15 requests/minute, tighter than the daily cap — see
`CLAUDE.md`), that roughly halves effective throughput at the start of every run and burns quota
faster when several teammates hit one key.

**Why it matters:** competition day is quota-constrained; a wasted call per run adds up and pushes
key rotation / overflow harder.

**First step:** try a cheap deterministic pre-filter (keyword/regex over the prompt) that only
falls back to the model call when it's genuinely ambiguous — most CTF prompts name their category
or contain an obvious tell (`RSA`, `nc host port`, `.pcap`, `disassemble`, ...). Alternatively,
fold the category ask into the first `think` system prompt and parse it from that single call.
Keep the current model-call path as the fallback so accuracy doesn't regress.

## 3. HITL multi-tool-call-in-one-turn replay caveat
**Where:** `agent/graph.py` `act()` (already documented inline).

**What:** When `require_approval` is set and a single `AIMessage` makes more than one gated tool
call, resuming the second `interrupt()` replays the node from the top, so an already-approved
earlier call in the same batch fires again. Currently safe only because the model makes one gated
call per turn in every observed case.

**Why it matters:** it's an assumption, not a guarantee. A model that batches two `fetch_url` calls
in one turn would double-fire the first on approval of the second — against real scored infra.

**First step:** cache per-`(thread, tool_call_id)` results across the replay (e.g. in state keyed
by `tool_call_id`) so an already-executed call returns its cached `ToolMessage` instead of
re-invoking. Only worth doing if you ever see multi-gated-call turns in the run logs.

## 4. Deploy hardening beyond CORS
**Where:** `agent/api.py`.

**What:** The API has no auth, no request-size limit, and its docstrings flag several "dev-only"
assumptions. Fine on a laptop; risky if the API is ever exposed beyond localhost (e.g. so a
teammate's browser or a deployed dashboard can reach it).

**Why it matters:** an open `/solve` that makes outbound network calls (gated only by the
prompt-derived host allowlist) is a small SSRF-shaped surface if reachable by anyone.

**First step:** a shared-secret header check (env var) on `/solve*`, plus a max request body size,
gated behind an env flag so local dev is unchanged. Only needed if the API leaves localhost.

## 5. `search_vault` retrieval ranking is naive substring matching
**Where:** `agent/tools/search_vault.py` (and `search_skills.py`, same shape).

**What:** Both are plain substring scans returning matching lines. In documented runs (picoCTF
"Old Session"), the single most relevant vault note (`predictable-session-id-timestamp-hash.md`)
was *not* surfaced for queries like "flask"/"cookie" because it didn't contain those exact
substrings — a retrieval miss, not a content gap. The vault is now 150+ notes, so ranking matters.

**Why it matters:** the vault is the agent's edge over base-model knowledge; if the right note
doesn't surface, that edge is lost exactly when it's needed.

**First step:** add lightweight scoring (term frequency across the note + title/heading boost + a
few hand-mapped synonyms like cookie↔session), return top-N notes ranked, and include the matched
heading for context. Keep it dependency-free (no embeddings) to avoid new install/runtime cost;
revisit embeddings only if simple scoring isn't enough.

## 6. Anthropic provider points at a model with no key expected
**Where:** `agent/model_router.py` `_PROVIDERS["anthropic"]`.

**What:** The `anthropic` provider builds `claude-sonnet-4-6`, but `.env` intentionally has no
`ANTHROPIC_API_KEY` (documented in `CLAUDE.md`). Selecting that provider fails at call time with a
key error rather than a clear "not configured" message.

**Why it matters:** minor, but a confusing failure if someone picks it in the dashboard by mistake.

**First step:** in `get_model`, if the selected provider's key env var is unset, raise a clear
`ValueError("provider 'anthropic' has no ANTHROPIC_API_KEY configured")` up front (the API already
turns `ValueError` into a clean 400).

## 7. Groq fallback model id is unverified against a live key
**Where:** `agent/model_router.py` `_PROVIDERS["groq"]`.

**What:** The reliability pass changed the Groq model to `openai/gpt-oss-120b` (the documented
better option) but couldn't live-verify the exact Groq model string without a `GROQ_API_KEY`.

**First step:** with a real Groq key, confirm `init_chat_model("openai/gpt-oss-120b",
model_provider="groq")` constructs and a trivial tool call succeeds; adjust the id if Groq's
catalog names it differently. Groq is a non-primary fallback, so this is low-priority.

## 8. `demo/expected_transcript.txt` is still a placeholder
**Where:** `demo/` (called out in `CLAUDE.md`/`NEXT_STEPS.md`).

**What:** There's no rehearsed screen recording of the demo — the text transcript is a stand-in.

**First step:** record one real end-to-end run (ideally a live network solve) as the on-stage
fallback if live tools flake. This is a demo-readiness task, not a code change.

---

## Notes for whoever picks this up
- The reliability pass left everything **additive with safe defaults** — an unconfigured system
  behaves exactly as before. Same discipline is worth keeping for anything above.
- Re-check `CLAUDE.md`'s model-choice section before touching `model_router.py` — several
  "obvious" model swaps were already tried and rejected with evidence.
- Run `python -m evals.test_tools_smoke` before and after any change here; it now runs cleanly on
  a machine without WSL.
