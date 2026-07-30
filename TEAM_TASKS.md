# Team Task Briefs — Hasif, Rashid, Farhan
### Event: Agentic AI-Driven CTF Hackathon 2026 (UCSI, 6 Aug 2026)
### Repo: https://github.com/SalmonIsFish/CTF_Hackhaton

Written for beginners: exact commands, exact files, in order. If a step errors out, paste the error into a free chat model (Gemini, free ChatGPT, or Claude.ai free tier) and ask "explain this error and how to fix it" — that's a normal part of the workflow.

**Important context shift:** this isn't a "build a startup demo" hackathon — it's scored on whether your agent actually solves CTF challenges (web, crypto, forensics, misc, pwn, reversing) autonomously or semi-autonomously. Everything below is written for that.

**Status update — the agent core is no longer a blank scaffold.** `agent/graph.py` has a working, tested ReAct loop with two real generic tools (`find_flag_pattern`, `identify_and_decode`) plus vault search (`search_vault`), verified end-to-end including multi-step tool chaining. The default model is `gemini-3.5-flash-lite` (get a free key at aistudio.google.com — this is the specific one that works, not just any Gemini model, see `CLAUDE.md`'s Current Status section for why). Rashid: you're adding tools *into* a proven loop now, not building the loop. Hasif: there's a real backend to point your dashboard at instead of the stub.

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

### Setup (~15 min)
1. Install Python 3.11+ (python.org). Check: `python --version`
2. Get a free API key: Google AI Studio (aistudio.google.com) or Groq (console.groq.com)
3. Create `agent/.env`:
   ```
   GOOGLE_API_KEY=your_key_here
   ```
4. Install packages:
   ```
   pip install langchain langchain-google-genai python-dotenv requests
   ```

### Your actual task — define the agent's tools
For whichever categories you picked, write a tool spec (what it takes in, what it returns) for each. These are standard, publicly documented CTF technique categories — not attack code against real systems, just wrappers/parsers around well-known open tools:

**If doing Web:**
```
Tool: fetch_page
Input: { "url": string }
Output: { "html": string, "headers": object, "status": int }
(wraps a simple `requests.get()` — lets the agent inspect a challenge site)
```

**If doing Crypto:**
```
Tool: identify_and_decode
Input: { "text": string }
Output: { "likely_encoding": string, "decoded": string }
(tries common encodings — base64, hex, rot13 — and reports what worked;
CyberChef's "Magic" feature is the well-known reference implementation of this idea)
```

**If doing Forensics/Misc:**
```
Tool: extract_metadata
Input: { "file_path": string }
Output: { "metadata": object }
(wraps exiftool or Python's `Pillow`/`exifread` to pull hidden metadata from images/files)
```

**All categories need this one:**
```
Tool: find_flag_pattern
Input: { "text": string }
Output: { "candidates": [string] }
(regex search for the flag format the organizers announce, e.g. flag{...} or CTF{...})
```

### Test each tool in isolation
Write a small script per tool, e.g. `agent/tools/test_decode.py`:
```python
from dotenv import load_dotenv
load_dotenv()

def identify_and_decode(text: str) -> dict:
    import base64
    try:
        decoded = base64.b64decode(text).decode()
        return {"likely_encoding": "base64", "decoded": decoded}
    except Exception:
        pass
    return {"likely_encoding": "unknown", "decoded": text}

print(identify_and_decode("SGVsbG8gQ1RG"))
```
Run with `python agent/tools/test_decode.py`, confirm it prints something sensible, then move to the next tool.

### Evals — test against real, public practice challenges
Don't invent your own test cases — pull 5–8 **beginner-level** challenges from picoCTF (picoctf.org, free, public, designed for exactly this) matching your chosen categories, and confirm your tools + agent loop can actually get to the flag on those before relying on them in the real competition. Log results in `evals/practice_runs.md`:
```
| Challenge | Category | Tool(s) used | Flag found? | Notes |
```

### Done =
Tool specs written for your chosen categories, each tested standalone, and at least 5 practice picoCTF challenges attempted with results logged.

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
6. Once Rashid's real tool-calling agent is ready, swap the `api:` URL to point at it — no other UI changes needed.

### Polish checklist
- [ ] Show which tool the agent is currently calling (even a simple label like "Calling: identify_and_decode…")
- [ ] Big, obvious "Flag found:" box with a copy button — judges/teammates should spot the result instantly
- [ ] Loading state while the agent works (some CTF tool calls take a few seconds)
- [ ] Keep it readable on a projector — large text, high contrast

### Done =
You can paste a challenge, hit "Run Agent," see step-by-step trace text appear, and a flag clearly displayed, pushed to your branch.

---

## FARHAN — CTF / Cybersecurity / Red-Team Knowledge Base

**Your job in one sentence:** build the reference library the whole team (and eventually the agent itself, via Obsidian) leans on during the competition — organized by CTF category, with known tools and beginner-safe study resources. No laptop needed; everything below works from your phone in Obsidian.

This isn't busywork — a well-organized knowledge base is a real competitive advantage in CTF: most challenges are solved faster by recognizing "oh, this is a classic X pattern" than by cleverness on the spot. You're building the team's pattern library.

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
- Share vault notes into the team chat periodically (select note text → Share) so whoever's on a laptop can paste into the repo's `vault/` folder, where they're available to the team and, once wired up, to the agent itself as retrievable reference material.

### Done =
2–3 category notes fully filled in (not placeholders), `RedTeam_Basics.md` done, `Pitch_Backup.md` done as insurance, all shared with the team at least once before the competition day.
