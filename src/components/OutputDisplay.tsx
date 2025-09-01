
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Copy, Check } from "lucide-react";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";

interface OutputDisplayProps {
  content: string;
  type: 'original' | 'sanitized';
}

export const OutputDisplay = ({ content, type }: OutputDisplayProps) => {
  const [copied, setCopied] = useState(false);
  const { toast } = useToast();

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(content);
      setCopied(true);
      toast({
        title: "COPY_SUCCESS",
        description: `${type === 'sanitized' ? 'Clean' : 'Original'} payload copied to buffer.`,
      });
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      toast({
        title: "COPY_FAILED",
        description: "Unable to access system clipboard. Manual selection required.",
        variant: "destructive",
      });
    }
  };

  return (
    <Card className={`border ${
      type === 'original' 
        ? 'border-red-500/50 bg-red-950/10' 
        : 'border-terminal-green/50 bg-terminal-green/5'
    }`}>
      <CardContent className="pt-4">
        <div className="flex items-center justify-between mb-3">
          <span className="text-sm font-mono font-bold text-terminal-green">
            {type === 'sanitized' ? '[CLEAN_BUFFER]' : '[RAW_BUFFER]'}
          </span>
          <Button
            variant="ghost"
            size="sm"
            onClick={handleCopy}
            className="h-8 px-2 font-mono text-xs hover:bg-terminal-green/20 hover:text-terminal-green border border-terminal-green/30"
          >
            {copied ? (
              <Check className="h-3 w-3 text-terminal-green" />
            ) : (
              <Copy className="h-3 w-3" />
            )}
          </Button>
        </div>
        <div className={`rounded border p-3 max-h-60 overflow-auto ${
          type === 'original' 
            ? 'bg-red-950/20 border-red-500/30' 
            : 'bg-terminal-bg border-terminal-green/30'
        }`}>
          <pre className="text-xs font-mono whitespace-pre-wrap break-words text-terminal-green">
            {content || '// Buffer empty'}
          </pre>
        </div>
      </CardContent>
    </Card>
  );
};
