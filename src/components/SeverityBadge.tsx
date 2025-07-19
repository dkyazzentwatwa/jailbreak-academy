
import { Badge } from "@/components/ui/badge";
import { SeverityLevel } from "@/types/sanitization";

interface SeverityBadgeProps {
  severity: SeverityLevel;
}

export const SeverityBadge = ({ severity }: SeverityBadgeProps) => {
  const getBadgeVariant = (severity: SeverityLevel) => {
    switch (severity) {
      case 'high':
        return 'destructive';
      case 'moderate':
        return 'secondary';
      case 'low':
        return 'outline';
      default:
        return 'default';
    }
  };

  const getBadgeColor = (severity: SeverityLevel) => {
    switch (severity) {
      case 'high':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'moderate':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low':
        return 'bg-blue-100 text-blue-800 border-blue-200';
      default:
        return 'bg-green-100 text-green-800 border-green-200';
    }
  };

  const getSeverityText = (severity: SeverityLevel) => {
    switch (severity) {
      case 'high':
        return 'High Risk';
      case 'moderate':
        return 'Moderate Risk';
      case 'low':
        return 'Low Risk';
      default:
        return 'Safe';
    }
  };

  return (
    <Badge 
      variant={getBadgeVariant(severity)}
      className={getBadgeColor(severity)}
    >
      {getSeverityText(severity)}
    </Badge>
  );
};
