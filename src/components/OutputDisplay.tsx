
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Copy, Check } from "lucide-react";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";
import { SanitizationResult } from "@/types/sanitization";

interface OutputDisplayProps {
  result: SanitizationResult;
}

export const OutputDisplay = ({ result }: OutputDisplayProps) => {
  const [copiedOriginal, setCopiedOriginal] = useState(false);
  const [copiedSanitized, setCopiedSanitized] = useState(false);
  const { toast } = useToast();

  const handleCopy = async (content: string, type: 'original' | 'sanitized') => {
    try {
      await navigator.clipboard.writeText(content);
      if (type === 'original') {
        setCopiedOriginal(true);
        setTimeout(() => setCopiedOriginal(false), 2000);
      } else {
        setCopiedSanitized(true);
        setTimeout(() => setCopiedSanitized(false), 2000);
      }
      
      toast({
        title: "COPY_SUCCESS",
        description: `${type === 'sanitized' ? 'Clean' : 'Original'} payload copied to buffer.`,
      });
    } catch (error) {
      toast({
        title: "COPY_FAILED",
        description: "Unable to access system clipboard. Manual selection required.",
        variant: "destructive",
      });
    }
  };

  return (
    <div className="space-y-4">
      {/* Original Input */}
      {result.originalInput && (
        <Card className="border-red-500/50 bg-red-950/10">
          <CardContent className="pt-4">
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm font-mono font-bold text-terminal-green">
                [RAW_BUFFER]
              </span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => handleCopy(result.originalInput || '', 'original')}
                className="h-8 px-2 font-mono text-xs hover:bg-terminal-green/20 hover:text-terminal-green border border-terminal-green/30"
              >
                {copiedOriginal ? (
                  <Check className="h-3 w-3 text-terminal-green" />
                ) : (
                  <Copy className="h-3 w-3" />
                )}
              </Button>
            </div>
            <div className="rounded border p-3 max-h-60 overflow-auto bg-red-950/20 border-red-500/30">
              <pre className="text-xs font-mono whitespace-pre-wrap break-words text-terminal-green">
                {result.originalInput || '// Buffer empty'}
              </pre>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Sanitized Output */}
      <Card className="border-terminal-green/50 bg-terminal-green/5">
        <CardContent className="pt-4">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm font-mono font-bold text-terminal-green">
              [CLEAN_BUFFER]
            </span>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => handleCopy(result.sanitizedOutput, 'sanitized')}
              className="h-8 px-2 font-mono text-xs hover:bg-terminal-green/20 hover:text-terminal-green border border-terminal-green/30"
            >
              {copiedSanitized ? (
                <Check className="h-3 w-3 text-terminal-green" />
              ) : (
                <Copy className="h-3 w-3" />
              )}
            </Button>
          </div>
          <div className="rounded border p-3 max-h-60 overflow-auto bg-terminal-bg border-terminal-green/30">
            <pre className="text-xs font-mono whitespace-pre-wrap break-words text-terminal-green">
              {result.sanitizedOutput || '// Buffer empty'}
            </pre>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
