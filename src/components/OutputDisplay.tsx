
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
        title: "Copied to clipboard",
        description: `${type === 'sanitized' ? 'Sanitized' : 'Original'} content copied successfully.`,
      });
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      toast({
        title: "Copy failed",
        description: "Unable to copy to clipboard. Please try selecting and copying manually.",
        variant: "destructive",
      });
    }
  };

  return (
    <Card className={`${
      type === 'original' 
        ? 'border-red-200 bg-red-50' 
        : 'border-green-200 bg-green-50'
    }`}>
      <CardContent className="pt-4">
        <div className="flex items-center justify-between mb-3">
          <span className="text-sm font-medium">
            {type === 'sanitized' ? 'Safe Output' : 'Original Input'}
          </span>
          <Button
            variant="ghost"
            size="sm"
            onClick={handleCopy}
            className="h-8 px-2"
          >
            {copied ? (
              <Check className="h-3 w-3 text-green-600" />
            ) : (
              <Copy className="h-3 w-3" />
            )}
          </Button>
        </div>
        <div className="bg-white rounded border p-3 max-h-60 overflow-auto">
          <pre className="text-xs font-mono whitespace-pre-wrap break-words">
            {content || '(Empty output)'}
          </pre>
        </div>
      </CardContent>
    </Card>
  );
};
