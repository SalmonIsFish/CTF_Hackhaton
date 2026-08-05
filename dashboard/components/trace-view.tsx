import type { UIMessage } from "ai";
import { Badge } from "@/components/ui/badge";
import { ApprovalPrompt } from "@/components/approval-prompt";
import { ToolCallItem } from "@/components/tool-call-item";

type PendingApproval = {
  threadId: string;
  interrupt: { tool: string; args: Record<string, unknown>; target: string };
};
type ToolCallTrace = { name: string; args: Record<string, unknown>; result: string | null };
type RunTrace = { category: string | null; steps: number; toolCalls: ToolCallTrace[] };

function isApprovalPart(part: UIMessage["parts"][number]): part is { type: "data-approval"; data: PendingApproval } {
  return part.type === "data-approval";
}
function isTracePart(part: UIMessage["parts"][number]): part is { type: "data-trace"; data: RunTrace } {
  return part.type === "data-trace";
}

type TraceViewProps = {
  messages: UIMessage[];
  isRunning: boolean;
  onApprove: () => void;
  onDeny: () => void;
};

export function TraceView({ messages, isRunning, onApprove, onDeny }: TraceViewProps) {
  const latestId = messages[messages.length - 1]?.id;

  return (
    <div className="flex flex-col gap-4">
      {messages.map((m) => {
        const isLatest = m.id === latestId;
        return (
          <div key={m.id} className="border-l-2 border-border pl-4">
            <div className="mb-1 text-xs font-medium tracking-wide text-muted-foreground uppercase">
              {m.role === "user" ? "Challenge" : "Agent"}
            </div>

            {m.parts.map((part, index) => {
              if (part.type === "text" && part.text) {
                return (
                  <p key={index} className="text-sm whitespace-pre-wrap">
                    {part.text}
                  </p>
                );
              }
              if (isApprovalPart(part)) {
                return (
                  <ApprovalPrompt
                    key={index}
                    approval={part.data}
                    disabled={!isLatest || isRunning}
                    onApprove={onApprove}
                    onDeny={onDeny}
                  />
                );
              }
              if (isTracePart(part)) {
                const { category, steps, toolCalls } = part.data;
                return (
                  <div key={index} className="mt-2 flex flex-col gap-2">
                    <div className="flex items-center gap-2">
                      {category && <Badge variant="secondary">{category}</Badge>}
                      <span className="text-xs text-muted-foreground">
                        {steps} step{steps === 1 ? "" : "s"}
                      </span>
                    </div>
                    {toolCalls.length > 0 && (
                      <div className="flex flex-col gap-1.5">
                        {toolCalls.map((call, i) => (
                          <ToolCallItem key={i} call={call} index={i} />
                        ))}
                      </div>
                    )}
                  </div>
                );
              }
              return null;
            })}
          </div>
        );
      })}
    </div>
  );
}
