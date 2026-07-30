# Team Task Briefs — Hasif, Rashid, Farhan
### Event: Agentic AI-Driven CTF Hackathon 2026 (UCSI, 6 Aug 2026)
### Repo: https://github.com/SalmonIsFish/CTF_Hackhaton

Written for beginners: exact commands, exact files, in order. If a step errors out, paste the error into a free chat model (Gemini, free ChatGPT, or Claude.ai free tier) and ask "explain this error and how to fix it" — that's a normal part of the workflow.

**Important context shift:** this isn't a "build a startup demo" hackathon — it's scored on whether your agent actually solves CTF challenges (web, crypto, forensics, misc, pwn, reversing) autonomously or semi-autonomously. Everything below is written for that.

**Status update — the agent core is well past a blank scaffold now.** `agent/graph.py` runs a full **triage → think → act → observe → trim_context** loop: it classifies each challenge into a category first (web/crypto/pwn/reverse/forensics/malware/osint/misc/ai-ml/blue-team), then reasons with tools tailored to that category, and caps its own context so it doesn't grow unbounded on long runs. Tools so far: `find_flag_pattern`, `identify_and_decode`, `search_vault` (the team's own notes — this is where your `vault/` category notes and Farhan's real content matter), and `search_skills` (a much bigger addition: **14 vetted third-party technique-reference packs are already installed** under `.agents/skills/` — 11 offensive, covering web/crypto/pwn/reverse/forensics/malware/osint/misc/ai-ml, plus 3 defensive/blue-team ones (incident-response reports, SIEM detection rules, SOAR playbooks), all read directly and vetted, logged in `SKILLS_VETTING.md`). The default model is `gemini-3.5-flash-lite` (get a free key at aistudio.google.com — this is the specific one that works, not just any Gemini model, see `CLAUDE.md`'s Current Status section for why). There's also a one-command demo (`python -m demo.run_demo`) that solves a seeded challenge end to end — a good thing to look at to see exactly what the agent's input/output shape looks like.

**Important shift for Rashid specifically:** two of the four tools originally on your list (`identify_and_decode`, `find_flag_pattern`) are already built and tested — don't re-build them. Your job is now mostly: pick categories, validate the agent actually solves real picoCTF challenges in them (the skill packs give it technique knowledge, but nobody's confirmed it converts that into actually finding flags on real challenges yet), and build whatever connection tool your categories still need (`fetch_page` for web, `extract_metadata` for forensics).

**Important shift for Hasif:** the API bridge is now built — `agent/api.py`. Run it with `uvicorn agent.api:app --reload --port 8000` (add `fastapi`/`uvicorn` — already in `requirements.txt`). Two endpoints: `POST /solve` (send `{"prompt": "..."}`, get back `{category, steps, flag, final_answer, tool_calls}` once the whole run finishes) and `POST /solve/stream` (same thing, but Server-Sent Events — one event per graph node, exactly the live step-by-step trace your dashboard is meant to show). Point `app/api/agent/route.ts` at whichever fits your UI better — `/solve/stream` if you want the trace to appear incrementally, `/solve` if a single "done" state is simpler to wire up first. CORS is already open for `localhost:3000`.

**A note on how this actually gets used on the day:** this is a semi-autonomous *copilot*, not something that scans a CTF platform unattended. An operator (any of you) still looks at the challenge, copies whatever's relevant (page source, a captured request, a file's contents) and pastes it into the dashboard — the agent's job is reasoning over what it's given, decoding/grounding/spotting the flag, not independently going out and finding challenges to attack. `fetch_page` would let it fetch a URL *you hand it*, not browse on its own. Worth getting the organizers' actual autonomy requirements confirmed (still an open question) since it affects how much more "reach out and touch the target" tooling is worth building.

Everyone: install **Git** first if you don't have it, then:
```
git clone https://github.com/SalmonIsFish/CTF_Hackhaton.git
cd CTF_Hackhaton
git checkout -b hasif-frontend      # (or rashid-tools / farhan-knowledgebase)
```
Commit and push often:
```
git add .
git commit -m "what you did"
git push -u origin [your-branch-name]
```

---

## RASHID — Agent Tools & CTF Category Strategy

**Your job in one sentence:** decide which CTF categories we're realistically strong at, then build and test the specific tools the agent needs to solve challenges in those categories.

### Step 0 — Pick your categories (do this with the team first, ~20 min)
CTF challenges are usually grouped into: **Web, Crypto, Forensics, OSINT/Misc, Reversing, Pwn (binary exploitation)**. Pwn and Reversing take the longest to get good at (low-level, assembly-heavy) — for a beginner team, it's usually smarter to go deep on 2–3 categories than spread thin across all 6. A common strong beginner combo: **Web + Crypto + Forensics/Misc**. Decide this as a team before building tools — it changes everything below.

There's now also a **blue-team/defensive option** if the organizers' rules allow it or include that kind of challenge: 3 skill packs already cover incident-response report writing, SIEM detection-rule authoring, and SOAR playbook design. Worth a look even if you don't pick it as a main category — some "forensics" challenges are really disguised blue-team tasks (here's a log, what happened).

**Before you write a single new tool, check what's already covered.** `.agents/skills/` has 14 vetted technique-reference packs (11 offensive matching the categories above, one per category, plus the 3 blue-team ones) and the agent can already search them at runtime via `search_skills` — that's a lot of the "what should I try" knowledge already there, grounded and tested. Your actual gap to fill is *connection* tools (getting challenge data INTO the agent) and validating it all works end-to-end on real challenges, not re-deriving technique knowledge that already exists.

### Setup (~15 min)
1. Install Python 3.11+ (python.org). Check: `python --version`
2. Get a free API key: Google AI Studio (aistudio.google.com) or Groq (console.groq.com)
3. Create `.env` **at the repo root** (not inside `agent/` — that was a stale instruction; `load_dotenv()` looks for it at the top level):
   ```
   GOOGLE_API_KEY=your_key_here
   ```
4. Install packages:
   ```
   pip install -r requirements.txt
   ```

### Your actual task — build the remaining connection tools
`identify_and_decode` and `find_flag_pattern` are **already built and tested** (`agent/tools/`) — don't redo these. What's left, for whichever categories you picked:

**If doing Web:**
```
Tool: fetch_page
Input: { "url": string }
Output: { "html": string, "headers": object, "status": int }
(wraps a simple `requests.get()` — lets the agent inspect a challenge site you point it at)
```

**If doing Forensics/Misc:**
```
Tool: extract_metadata
Input: { "file_path": string }
Output: { "metadata": object }
(wraps exiftool or Python's `Pillow`/`exifread` to pull hidden metadata from images/files)
```

Follow the pattern already established in `agent/tools/` (a `@tool`-decorated function with a clear docstring, e.g. `agent/tools/identify_and_decode.py`) so it plugs into `agent/graph.py`'s `TOOLS` list the same way the existing ones do.

### Test each tool in isolation
`evals/test_tools_smoke.py` already does this for the existing tools (a known-good input, a known-bad input, an assertion on each) — add a matching block for whatever you build, in the same style, rather than a separate throwaway script. Run it with:
```
python -m evals.test_tools_smoke
```
Confirm it prints something sensible and no assertion fails, then wire your new tool into `agent/graph.py`'s `TOOLS` list so the loop can actually call it.

### Evals — test against real, public practice challenges
Don't invent your own test cases — pull 5–8 **beginner-level** challenges from picoCTF (picoctf.org, free, public, designed for exactly this) matching your chosen categories, and confirm your tools + agent loop can actually get to the flag on those before relying on them in the real competition. Log results in `evals/practice_runs.md`:
```
| Challenge | Category | Tool(s) used | Flag found? | Notes |
```

### Done =
Categories picked as a team, remaining connection tool(s) built and wired into `agent/graph.py`'s `TOOLS` list, each tested standalone, and at least 5 practice picoCTF challenges attempted through the *actual agent loop* (not just the tool in isolation) with results logged in `evals/practice_runs.md`.

---

## HASIF — Agent Operator Dashboard (Vercel AI SDK)

**Your job in one sentence:** build the screen where the team (and judges) watch the agent work — what it's trying, what tool it's calling, and what flag it finds. This is a live agent-execution view, not a customer chatbot.

### Setup (~15 min)
1. Install Node.js LTS (nodejs.org). Check: `node -v`
2. Scaffold the app:
   ```
   npx create-next-app@latest dashboard
   cd dashboard
   npm install ai @ai-sdk/react
   ```
   Answer: TypeScript = Yes, Tailwind = Yes, App Router = Yes.
3. `npm run dev`, open `http://localhost:3000` to confirm it runs.

### Your actual task
4. Replace `app/page.tsx` with an operator view — challenge input, a live trace of agent steps, and a flag output box:
   ```tsx
   "use client";
   import { useChat } from "@ai-sdk/react";

   export default function Dashboard() {
     const { messages, input, handleInputChange, handleSubmit } = useChat({
       api: "/api/agent",
     });

     return (
       <div className="mx-auto max-w-3xl p-4">
         <h1 className="text-xl font-bold mb-4">CTF Agent — Live Trace</h1>
         <form onSubmit={handleSubmit} className="mb-4">
           <textarea
             className="w-full border p-2 rounded"
             value={input}
             onChange={handleInputChange}
             placeholder="Paste challenge description, URL, or file path..."
           />
           <button className="mt-2 bg-black text-white px-4 py-2 rounded">
             Run Agent
           </button>
         </form>
         <div className="space-y-2">
           {messages.map((m) => (
             <div key={m.id} className="border-l-4 pl-2 text-sm">
               <b>{m.role === "user" ? "Challenge: " : "Agent step: "}</b>
               {m.content}
             </div>
           ))}
         </div>
       </div>
     );
   }
   ```
5. Stub backend to unblock yourself, `app/api/agent/route.ts`:
   ```ts
   export async function POST(req: Request) {
     const { messages } = await req.json();
     return new Response(
       `[stub] Recon step -> Decode step -> Candidate flag: flag{stub_placeholder}`
     );
   }
   ```
6. **The bridge is built** — `agent/api.py`, a FastAPI server wrapping `agent/graph.py`. Run `uvicorn agent.api:app --reload --port 8000` (from the repo root, with your `.env` set), then point `app/api/agent/route.ts` at `http://localhost:8000/solve` (single response) or `http://localhost:8000/solve/stream` (SSE — one event per graph step: `{"node": "...", "category"?, "flag"?, "tool_calls"?, "text"?}`, ending with an `event: done` line). `tool_calls` in both is already a clean list of `{name, args, result}` — no need to parse raw LangChain message objects on the frontend.

### Polish checklist
- [ ] Show which tool the agent is currently calling (even a simple label like "Calling: identify_and_decode…")
- [ ] Big, obvious "Flag found:" box with a copy button — judges/teammates should spot the result instantly
- [ ] Loading state while the agent works (some CTF tool calls take a few seconds)
- [ ] Keep it readable on a projector — large text, high contrast

Look at `demo/expected_transcript.txt` for what a real tool-call trace actually looks like (tool name, args, result, final flag) — useful for shaping your UI's fields even before the real API bridge exists.

### Done =
You can paste a challenge, hit "Run Agent," see step-by-step trace text appear, and a flag clearly displayed, pushed to your branch.

---

## FARHAN — CTF / Cybersecurity / Red-Team Knowledge Base

**Your job in one sentence:** build the reference library the whole team (and eventually the agent itself, via Obsidian) leans on during the competition — organized by CTF category, with known tools and beginner-safe study resources. No laptop needed; everything below works from your phone in Obsidian.

This isn't busywork — a well-organized knowledge base is a real competitive advantage in CTF: most challenges are solved faster by recognizing "oh, this is a classic X pattern" than by cleverness on the spot. You're building the team's pattern library.

**Your notes aren't redundant with the 14 third-party skill packs already installed** (`.agents/skills/`) — the agent checks your vault notes *first*, before the broader third-party library, specifically because team/event-specific notes (this CTF's own quirks, what actually worked in practice today) matter more than generic technique references. You're the "what we've actually learned so far" layer; the skill packs are the "general reference" layer underneath it.

### Setup (~10 min)
1. Download **Obsidian** (free) from the App Store / Play Store.
2. Create a vault named `CTF_Vault`.
3. Create one note per category the team picked (check with Rashid — likely 2–3 of these):
   - `Web.md`
   - `Crypto.md`
   - `Forensics_Misc.md`
   - `Reversing.md` (only if the team is attempting it)
   - `Pwn.md` (only if the team is attempting it)

### Structure for each category note
Use this template in every note:
```
## Key Concepts
(what this category is actually about, in plain language)

## Common Public Tools (names only — these are standard, publicly documented)
(e.g. for Web: Burp Suite, sqlmap, Gobuster/dirb, CyberChef)

## Where Flags Usually Hide In This Category
(general patterns, e.g. "check HTTP response headers and page source comments" for Web —
not a specific exploit, just where beginners forget to look)

## Beginner Study Links
(picoCTF, OverTheWire, TryHackMe, HackTheBox Academy, CTF Field Guide — pick 2-3 free ones per category)
```
Fill these in using picoCTF's own free practice write-ups and the **CTF Field Guide** (a free, well-known reference book made specifically for this — trailofbits' `ctf` repo on GitHub) as your main sources. Both are built for exactly this purpose, so you're compiling from legitimate, publicly published educational material, not improvising.

### Also create: `RedTeam_Basics.md`
A short glossary note — just definitions, no attack instructions:
```
- Recon: gathering public info about a target before testing it
- Enumeration: systematically listing what's exposed (ports, files, endpoints)
- Privilege escalation: going from limited access to fuller access
- OSINT: gathering information from public sources
```
This is here so the whole team (including non-security people) can follow what's happening without Googling terms mid-competition.

### "Just in case" one-pager — `Pitch_Backup.md`
Since we don't yet know if there's a presentation component, spend only ~15 minutes on this — just enough that we're not scrambling if there is one:
```
## What we built
(1-2 sentences: an agent that autonomously solves CTF challenges in [categories])

## How it works
(1-2 sentences: recon -> analyze -> tool-assisted decode/exploit -> flag extraction)

## What we'd add with more time
(1-2 sentences)
```

### During the competition
- Keep `Web.md` / `Crypto.md` / etc. open and be the person who says "wait, that error looks like a classic X" — you'll often recognize patterns faster than teammates heads-down in code.
- Share vault notes into the team chat periodically (select note text → Share) so whoever's on a laptop can paste into the repo's `vault/` folder — this is already wired up: the agent searches `vault/*.md` itself via `search_vault` (checked before the generic skill packs), so anything you add there is live, retrievable reference material as soon as it's committed, not just team reading material.

### Done =
2–3 category notes fully filled in (not placeholders), `RedTeam_Basics.md` done, `Pitch_Backup.md` done as insurance, all shared with the team at least once before the competition day.
