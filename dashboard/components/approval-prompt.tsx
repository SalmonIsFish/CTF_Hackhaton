import { ShieldAlertIcon } from "lucide-react";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";

type PendingApproval = {
  threadId: string;
  interrupt: { tool: string; args: Record<string, unknown>; target: string };
};

type ApprovalPromptProps = {
  approval: PendingApproval;
  disabled: boolean;
  onApprove: () => void;
  onDeny: () => void;
};

export function ApprovalPrompt({ approval, disabled, onApprove, onDeny }: ApprovalPromptProps) {
  const { tool, args, target } = approval.interrupt;

  return (
    <Alert className="mt-3">
      <ShieldAlertIcon />
      <AlertTitle>Approval needed before contacting a live target</AlertTitle>
      <AlertDescription>
        <dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 font-mono text-xs">
          <dt className="text-muted-foreground">tool</dt>
          <dd>{tool}</dd>
          <dt className="text-muted-foreground">target</dt>
          <dd>{target}</dd>
          <dt className="text-muted-foreground">args</dt>
          <dd className="break-all">{JSON.stringify(args)}</dd>
        </dl>
        <div className="mt-3 flex gap-2">
          <Button size="sm" disabled={disabled} onClick={onApprove}>
            Approve
          </Button>
          <Button size="sm" variant="destructive" disabled={disabled} onClick={onDeny}>
            Deny
          </Button>
        </div>
      </AlertDescription>
    </Alert>
  );
}
