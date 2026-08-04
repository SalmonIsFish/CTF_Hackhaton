import { createUIMessageStream, createUIMessageStreamResponse, type UIMessage } from "ai";

// Proxies the dashboard chat UI to the Python agent (agent/api.py), started
// separately with `uvicorn agent.api:app --reload --port 8000`. Override with
// AGENT_API_URL in dashboard/.env.local if the FastAPI bridge runs elsewhere.
const AGENT_API_URL = process.env.AGENT_API_URL ?? "http://localhost:8000";

// Shape written into a "data-approval" message part (see below) so the pending
// interrupt survives the round trip: useChat resends the full message history
// (including parts) on every request, so this is how the *next* POST learns
// which thread_id/tool call it's approving or denying.
type PendingApproval = {
  threadId: string;
  interrupt: { tool: string; args: Record<string, unknown>; target: string };
};

function textOf(message: UIMessage): string {
  return (message.parts ?? [])
    .filter((part): part is { type: "text"; text: string } => part.type === "text")
    .map((part) => part.text)
    .join("");
}

// Enforce Permissions (harness element #5), dashboard side: find a pending approval
// left on the most recent assistant turn, if any. Only that turn counts -- an older
// approval further back in history is stale (either already resolved, or superseded
// by a newer prompt).
function findPendingApproval(priorMessages: UIMessage[]): PendingApproval | null {
  for (let i = priorMessages.length - 1; i >= 0; i--) {
    const message = priorMessages[i];
    if (message.role !== "assistant") continue;
    const part = (message.parts ?? []).find(
      (p): p is { type: "data-approval"; data: PendingApproval } => p.type === "data-approval"
    );
    return part ? part.data : null;
  }
  return null;
}

export async function POST(req: Request) {
  const { messages, requireApproval } = (await req.json()) as {
    messages: UIMessage[];
    requireApproval?: boolean;
  };
  const lastMessage = messages[messages.length - 1];
  const lastText = textOf(lastMessage).trim();
  const decision =
    lastText.toLowerCase() === "approve" ? "approve" : lastText.toLowerCase() === "deny" ? "deny" : null;
  const pending = decision ? findPendingApproval(messages.slice(0, -1)) : null;

  const stream = createUIMessageStream({
    execute: async ({ writer }) => {
      const id = crypto.randomUUID();
      writer.write({ type: "text-start", id });

      let text: string;
      let approval: PendingApproval | null = null;

      try {
        const res = pending
          ? await fetch(`${AGENT_API_URL}/solve/resume`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ thread_id: pending.threadId, decision }),
            })
          : await fetch(`${AGENT_API_URL}/solve`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ prompt: lastText, require_approval: Boolean(requireApproval) }),
            });

        if (!res.ok) {
          const detail = await res.text();
          text = `Agent API error (${res.status}): ${detail}`;
        } else {
          const result = await res.json();
          if (result.status === "pending_approval") {
            const { tool, args, target } = result.interrupt;
            approval = { threadId: result.thread_id, interrupt: result.interrupt };
            text = [
              "Approval needed before the agent contacts a live target.",
              "",
              `Tool: ${tool}`,
              `Target: ${target}`,
              `Args: ${JSON.stringify(args)}`,
              "",
              'Use the Approve / Deny buttons below (or reply "approve" / "deny").',
            ].join("\n");
          } else {
            text = [
              `Category: ${result.category ?? "unknown"}`,
              `Steps: ${result.steps}`,
              "",
              result.final_answer ?? "",
              result.flag ? `\nFlag: ${result.flag}` : "",
            ].join("\n");
          }
        }
      } catch (err) {
        text = `Could not reach agent API at ${AGENT_API_URL} — is \`uvicorn agent.api:app --port 8000\` running? (${
          err instanceof Error ? err.message : String(err)
        })`;
      }

      writer.write({ type: "text-delta", id, delta: text });
      writer.write({ type: "text-end", id });

      if (approval) {
        writer.write({ type: "data-approval", id: crypto.randomUUID(), data: approval });
      }
    },
  });

  return createUIMessageStreamResponse({ stream });
}
