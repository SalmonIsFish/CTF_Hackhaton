import { Loader2Icon } from "lucide-react";

export function StatusIndicator({ isRunning }: { isRunning: boolean }) {
  if (!isRunning) return null;

  return (
    <div className="mb-6 flex items-center gap-2 text-sm font-medium text-muted-foreground">
      <Loader2Icon className="size-4 animate-spin" />
      Agent running — calling tools...
    </div>
  );
}
