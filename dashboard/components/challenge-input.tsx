import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";

type ChallengeInputProps = {
  value: string;
  onValueChange: (value: string) => void;
  onSubmit: (e: React.FormEvent) => void;
  requireApproval: boolean;
  onRequireApprovalChange: (checked: boolean) => void;
  isRunning: boolean;
};

export function ChallengeInput({
  value,
  onValueChange,
  onSubmit,
  requireApproval,
  onRequireApprovalChange,
  isRunning,
}: ChallengeInputProps) {
  return (
    <form onSubmit={onSubmit} className="mb-8 flex flex-col gap-4">
      <Textarea
        className="min-h-32 text-base"
        value={value}
        onChange={(e) => onValueChange(e.target.value)}
        placeholder="Paste challenge description, URL, or file path..."
      />

      <label className="flex items-center gap-2 text-sm text-muted-foreground">
        <Checkbox
          checked={requireApproval}
          onCheckedChange={(checked) => onRequireApprovalChange(checked === true)}
        />
        Require approval before live network calls (HITL)
      </label>

      <Button
        type="submit"
        size="lg"
        disabled={!value.trim() || isRunning}
        className="self-start"
      >
        {isRunning ? "Running..." : "Run Agent"}
      </Button>
    </form>
  );
}
