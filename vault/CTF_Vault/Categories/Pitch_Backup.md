# Pitch Backup

## What we built

An AI agent that solves [[CTF]] challenges — Web, Crypto, and Forensics/Misc, with broader
reference coverage for Pwn, Reverse Engineering, Malware, OSINT, AI/ML, and Blue Team on top —
semi-autonomously, plus a live dashboard where the team and judges can watch it reason and act
in real time.

## How it works

Each challenge first gets triaged into a category, then the agent runs a bounded
[[Recon]] → analyze → tool-assisted decode/exploit → [[Flag]]-extraction loop: it reaches for
[[Payload]]-free decoding tools, live network tools (HTTP, TCP sessions, port scanning,
directory enumeration), and image [[Metadata]] extraction, grounding each step in a searchable
knowledge base — the team's own vault notes first, then a library of 14 vetted technique
packs — before falling back to general reasoning. Live-target actions (touching a real
[[Recon|host/IP]]) can be gated behind an explicit human approve/deny step rather than firing
unattended, and every run is logged for review afterward.

## What we'd add with more time

Real `nmap` integration for deeper service fingerprinting, a rehearsed recorded demo of a live
network solve as an on-stage fallback, and picoCTF-validated results logged for every category
the skill packs already support, not just the three we've gone deepest on.

## Talking points / judging notes

- Lead with the live dashboard, not a slide — watching the agent pick a tool and reason through
  a step is more convincing than describing it.
- If asked "is it fully autonomous?": no, and that's deliberate — destructive or live-target
  actions can require a human approve/deny, matching how the organizer's own guidance leaned
  (permission enforcement, not unattended execution).
- If a live solve flakes on stage, fall back to the recorded demo transcript rather than
  debugging live in front of judges.

## Related Notes

- [[CTF]]
- [[CTF Basics]]
- [[Cybersecurity Ethics]]
- [[Web]]
- [[Crypto]]
- [[Forensics_Misc]]
