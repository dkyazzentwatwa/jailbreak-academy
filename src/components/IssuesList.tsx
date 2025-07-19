
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, Info, CheckCircle, Bug } from "lucide-react";
import { SanitizationIssue } from "@/types/sanitization";

interface IssuesListProps {
  issues: SanitizationIssue[];
  expertMode: boolean;
}

export const IssuesList = ({ issues, expertMode }: IssuesListProps) => {
  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'high':
        return <AlertTriangle className="h-4 w-4 text-red-400" />;
      case 'moderate':
        return <Info className="h-4 w-4 text-yellow-400" />;
      case 'low':
        return <Bug className="h-4 w-4 text-blue-400" />;
      default:
        return <CheckCircle className="h-4 w-4 text-terminal-green" />;
    }
  };

  const getSeverityBadge = (severity: string) => {
    const colors = {
      high: 'bg-red-900/80 text-red-200 border-red-500/50',
      moderate: 'bg-yellow-900/80 text-yellow-200 border-yellow-500/50',
      low: 'bg-blue-900/80 text-blue-200 border-blue-500/50'
    };
    
    return (
      <Badge variant="outline" className={`${colors[severity as keyof typeof colors] || ''} text-xs font-mono tracking-wider`}>
        [{severity.toUpperCase()}]
      </Badge>
    );
  };

  if (!expertMode && issues.length === 0) {
    return null;
  }

  return (
    <Card className="border-terminal-green/30 bg-card">
      <CardHeader className="pb-3 border-b border-terminal-green/20">
        <CardTitle className="text-sm font-mono text-terminal-green flex items-center gap-2">
          <Bug className="h-4 w-4" />
          THREAT_ANALYSIS_LOG
          <Badge variant="outline" className="bg-terminal-green/20 text-terminal-green border-terminal-green/50 font-mono text-xs">
            {issues.length}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="pt-4">
        {issues.length === 0 ? (
          <div className="text-center py-4 text-muted-foreground font-mono text-xs">
            <CheckCircle className="h-8 w-8 mx-auto mb-2 text-terminal-green" />
            // NO_THREATS_DETECTED
            <br />
            // All security protocols passed
          </div>
        ) : (
          <div className="space-y-3">
            {issues.map((issue, index) => (
              <div 
                key={index} 
                className="flex items-start gap-3 p-3 rounded bg-terminal-bg border border-terminal-green/20"
              >
                {getSeverityIcon(issue.severity)}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    {getSeverityBadge(issue.severity)}
                    <span className="font-mono text-xs text-terminal-green font-bold">
                      {issue.type.replace(/_/g, '_').toUpperCase()}
                    </span>
                  </div>
                  <p className="text-xs font-mono text-muted-foreground leading-relaxed">
                    // {issue.message}
                  </p>
                  {issue.details && expertMode && (
                    <div className="mt-2 p-2 bg-terminal-bg/50 rounded border border-terminal-green/10">
                      <pre className="text-xs font-mono text-terminal-green/80 whitespace-pre-wrap">
                        {issue.details}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
};
