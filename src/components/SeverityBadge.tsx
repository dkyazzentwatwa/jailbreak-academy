
import { Badge } from "@/components/ui/badge";
import { SeverityLevel } from "@/types/sanitization";

interface SeverityBadgeProps {
  severity: SeverityLevel;
}

export const SeverityBadge = ({ severity }: SeverityBadgeProps) => {
  const getBadgeColor = (severity: SeverityLevel) => {
    switch (severity) {
      case 'high':
        return 'bg-red-900/80 text-red-200 border-red-500/50 font-mono tracking-wider';
      case 'moderate':
        return 'bg-yellow-900/80 text-yellow-200 border-yellow-500/50 font-mono tracking-wider';
      case 'low':
        return 'bg-blue-900/80 text-blue-200 border-blue-500/50 font-mono tracking-wider';
      default:
        return 'bg-terminal-green/20 text-terminal-green border-terminal-green/50 font-mono tracking-wider';
    }
  };

  const getSeverityText = (severity: SeverityLevel) => {
    switch (severity) {
      case 'high':
        return '[CRITICAL]';
      case 'moderate':
        return '[WARNING]';
      case 'low':
        return '[INFO]';
      default:
        return '[SECURE]';
    }
  };

  return (
    <Badge 
      variant="outline"
      className={`${getBadgeColor(severity)} text-xs font-bold`}
    >
      {getSeverityText(severity)}
    </Badge>
  );
};
