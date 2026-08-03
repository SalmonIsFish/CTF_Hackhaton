import { createUIMessageStream, createUIMessageStreamResponse } from "ai";

// Proxies the dashboard chat UI to the Python agent (agent/api.py), started
// separately with `uvicorn agent.api:app --reload --port 8000`. Override with
// AGENT_API_URL in dashboard/.env.local if the FastAPI bridge runs elsewhere.
const AGENT_API_URL = process.env.AGENT_API_URL ?? "http://localhost:8000";

export async function POST(req: Request) {
  const { messages } = await req.json();
  const lastMessage = messages[messages.length - 1];

  const prompt = (lastMessage?.parts ?? [])
    .filter((part: { type: string }) => part.type === "text")
    .map((part: { text: string }) => part.text)
    .join("");

  const stream = createUIMessageStream({
    execute: async ({ writer }) => {
      const id = crypto.randomUUID();
      writer.write({ type: "text-start", id });

      let text: string;
      try {
        const res = await fetch(`${AGENT_API_URL}/solve`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ prompt }),
        });

        if (!res.ok) {
          const detail = await res.text();
          text = `Agent API error (${res.status}): ${detail}`;
        } else {
          const result = await res.json();
          text = [
            `Category: ${result.category ?? "unknown"}`,
            `Steps: ${result.steps}`,
            "",
            result.final_answer ?? "",
            result.flag ? `\nFlag: ${result.flag}` : "",
          ].join("\n");
        }
      } catch (err) {
        text = `Could not reach agent API at ${AGENT_API_URL} — is \`uvicorn agent.api:app --port 8000\` running? (${
          err instanceof Error ? err.message : String(err)
        })`;
      }

      writer.write({ type: "text-delta", id, delta: text });
      writer.write({ type: "text-end", id });
    },
  });

  return createUIMessageStreamResponse({ stream });
}
