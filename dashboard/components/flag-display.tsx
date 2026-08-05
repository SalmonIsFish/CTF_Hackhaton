"use client";

import { useState } from "react";
import { FlagIcon, CheckIcon, CopyIcon } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export function FlagDisplay({ flag }: { flag: string }) {
  const [copied, setCopied] = useState(false);

  async function copyFlag() {
    await navigator.clipboard.writeText(flag);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <Card className="mb-8 border-2 border-primary/20 bg-primary/5">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-lg">
          <FlagIcon className="size-5" />
          Flag
        </CardTitle>
      </CardHeader>
      <CardContent>
        {flag ? (
          <div className="flex flex-wrap items-center gap-3">
            <code className="rounded-md bg-muted px-3 py-1.5 text-base font-semibold">
              {flag}
            </code>
            <Button variant="outline" size="sm" onClick={copyFlag}>
              {copied ? (
                <CheckIcon data-icon="inline-start" />
              ) : (
                <CopyIcon data-icon="inline-start" />
              )}
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">Waiting for agent result...</p>
        )}
      </CardContent>
    </Card>
  );
}
