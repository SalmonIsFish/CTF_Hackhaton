import { WrenchIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";

type ToolCallTrace = { name: string; args: Record<string, unknown>; result: string | null };

export function ToolCallItem({ call, index }: { call: ToolCallTrace; index: number }) {
  return (
    <details className="group rounded-lg border border-border px-3 py-2 open:pb-3">
      <summary className="flex cursor-pointer list-none items-center gap-2 text-sm">
        <Badge variant="outline" className="font-mono">
          #{index + 1}
        </Badge>
        <WrenchIcon className="size-3.5 text-muted-foreground" />
        <span className="font-mono font-medium">{call.name}</span>
        <span className="ml-auto text-xs text-muted-foreground group-open:hidden">
          {call.result === null ? "pending" : "show details"}
        </span>
      </summary>

      <div className="mt-2 flex flex-col gap-2 text-xs">
        <div>
          <div className="mb-1 text-muted-foreground">args</div>
          <pre className="max-h-40 overflow-auto rounded-md bg-muted px-2 py-1.5 font-mono whitespace-pre-wrap break-all">
            {JSON.stringify(call.args, null, 2)}
          </pre>
        </div>
        {call.result !== null && (
          <div>
            <div className="mb-1 text-muted-foreground">result</div>
            <pre className="max-h-40 overflow-auto rounded-md bg-muted px-2 py-1.5 font-mono whitespace-pre-wrap break-all">
              {call.result}
            </pre>
          </div>
        )}
      </div>
    </details>
  );
}
