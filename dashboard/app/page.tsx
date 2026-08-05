"use client";

import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport, type UIMessage } from "ai";
import { useState } from "react";
import { ChallengeInput } from "@/components/challenge-input";
import { FlagDisplay } from "@/components/flag-display";
import { StatusIndicator } from "@/components/status-indicator";
import { TraceView } from "@/components/trace-view";

// Mirrors agent/tools/find_flag_pattern.py's FLAG_PATTERN -- keep the two in sync. A bare
// "flag{...}" literal (the original version of this regex) misses picoCTF's own format
// entirely: picoCTF{...} has no "flag" substring in it at all.
const FLAG_PATTERN = /\b(?:flag|ctf|htb|picoctf)\{[^{}]{1,300}\}/i;

function extractFlag(message: UIMessage): string {
  const text = message.parts
    .filter((part) => part.type === "text")
    .map((part) => part.text)
    .join("");
  return text.match(FLAG_PATTERN)?.[0] ?? "";
}

export default function Dashboard() {
  const [input, setInput] = useState("");
  const [isRunning, setIsRunning] = useState(false);
  const [flag, setFlag] = useState("");
  // Enforce Permissions (harness element #5): when on, a live-target tool call
  // (fetch_url/tcp_open/port_scan) pauses on the backend and this dashboard renders
  // Approve/Deny controls instead of letting it fire immediately. See agent/api.py's
  // require_approval / /solve/resume for the backend half of this.
  const [requireApproval, setRequireApproval] = useState(false);

  const { messages, sendMessage } = useChat({
    transport: new DefaultChatTransport({ api: "/api/agent" }),
    onFinish({ message }) {
      setIsRunning(false);
      const found = extractFlag(message);
      if (found) setFlag(found);
    },
    onError(error) {
      setIsRunning(false);
      setFlag("");
      console.error("Agent request failed:", error);
    },
  });

  async function submitHandler(e: React.FormEvent) {
    e.preventDefault();
    setFlag("");
    setIsRunning(true);
    await sendMessage({ text: input }, { body: { requireApproval } });
    setInput("");
  }

  // Sends a literal "approve"/"deny" chat message -- route.ts recognizes this as a
  // response to the most recent pending-approval turn (see findPendingApproval there)
  // rather than a new challenge prompt.
  async function respondToApproval(decision: "approve" | "deny") {
    setIsRunning(true);
    await sendMessage({ text: decision }, { body: { requireApproval } });
  }

  return (
    <main className="mx-auto max-w-4xl px-6 py-10">
      <h1 className="mb-8 text-2xl font-semibold">CTF Agent — Live Trace</h1>

      <ChallengeInput
        value={input}
        onValueChange={setInput}
        onSubmit={submitHandler}
        requireApproval={requireApproval}
        onRequireApprovalChange={setRequireApproval}
        isRunning={isRunning}
      />

      <StatusIndicator isRunning={isRunning} />

      <FlagDisplay flag={flag} />

      <section>
        <h2 className="mb-4 text-sm font-medium tracking-wide text-muted-foreground uppercase">
          Execution Trace
        </h2>
        <TraceView
          messages={messages}
          isRunning={isRunning}
          onApprove={() => respondToApproval("approve")}
          onDeny={() => respondToApproval("deny")}
        />
      </section>
    </main>
  );
}
