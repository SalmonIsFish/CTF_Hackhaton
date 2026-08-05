"use client";

import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport, type UIMessage } from "ai";
import { useState } from "react";
import { ChallengeInput } from "@/components/challenge-input";
import { FlagDisplay } from "@/components/flag-display";
import { StatusIndicator } from "@/components/status-indicator";
import { TraceView } from "@/components/trace-view";

// Read the backend-verified flag off a "data-flag" part (written by route.ts only when
// agent/graph.py's observe() actually matched a flag in a real tool result), never by regexing
// the model's own free-text answer for anything flag-shaped. The regex approach this replaced
// was a real, observed bug: on a challenge needing a manual byte-cipher decode, the model gave
// up partway through and typed a fabricated flag-shaped string into its prose -- the backend
// correctly never verified it, but a shape-only check lit the flag box up with it anyway.
function extractFlag(message: UIMessage): string {
  const flagPart = message.parts.find(
    (part): part is { type: "data-flag"; data: { flag: string } } => part.type === "data-flag"
  );
  return flagPart?.data.flag ?? "";
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
