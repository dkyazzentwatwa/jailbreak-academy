
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { ChevronDown, AlertTriangle, Info, Shield, Database, Terminal, Brain, Eye, Code } from "lucide-react";
import { SecurityIssue } from "@/types/sanitization";
import { useState } from "react";

interface IssuesListProps {
  issues: SecurityIssue[];
  expertMode: boolean;
}

export const IssuesList = ({ issues, expertMode }: IssuesListProps) => {
  const [expandedIssues, setExpandedIssues] = useState<Set<string>>(new Set());

  const toggleIssue = (issueId: string) => {
    const newExpanded = new Set(expandedIssues);
    if (newExpanded.has(issueId)) {
      newExpanded.delete(issueId);
    } else {
      newExpanded.add(issueId);
    }
    setExpandedIssues(newExpanded);
  };

  const getIssueIcon = (type: SecurityIssue['type']) => {
    switch (type) {
      case 'xss':
      case 'script_injection':
      case 'html_injection':
        return <Code className="h-4 w-4" />;
      case 'sql_injection':
        return <Database className="h-4 w-4" />;
      case 'command_injection':
        return <Terminal className="h-4 w-4" />;
      case 'prompt_injection':
        return <Brain className="h-4 w-4" />;
      case 'data_exposure':
        return <Eye className="h-4 w-4" />;
      default:
        return <Shield className="h-4 w-4" />;
    }
  };

  const getSeverityColor = (severity: SecurityIssue['severity']) => {
    switch (severity) {
      case 'high':
        return 'text-red-600';
      case 'moderate':
        return 'text-yellow-600';
      case 'low':
        return 'text-blue-600';
      default:
        return 'text-green-600';
    }
  };

  if (issues.length === 0) {
    return (
      <Card className="border-green-200 bg-green-50">
        <CardContent className="pt-6">
          <div className="flex items-center gap-2 text-green-700">
            <Shield className="h-5 w-5" />
            <span className="font-medium">No Security Issues Detected</span>
          </div>
          <p className="text-sm text-green-600 mt-1">
            The AI output appears to be safe and free of common security threats.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm">
          <AlertTriangle className="h-4 w-4" />
          Security Issues Found ({issues.length})
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {issues.map((issue) => (
          <Collapsible
            key={issue.id}
            open={expertMode || expandedIssues.has(issue.id)}
            onOpenChange={() => !expertMode && toggleIssue(issue.id)}
          >
            <CollapsibleTrigger asChild>
              <div className={`flex items-center justify-between p-3 rounded-lg border cursor-pointer hover:bg-muted/50 ${
                issue.severity === 'high' ? 'border-red-200 bg-red-50' :
                issue.severity === 'moderate' ? 'border-yellow-200 bg-yellow-50' :
                'border-blue-200 bg-blue-50'
              }`}>
                <div className="flex items-center gap-2">
                  <div className={getSeverityColor(issue.severity)}>
                    {getIssueIcon(issue.type)}
                  </div>
                  <div>
                    <p className="font-medium text-sm">{issue.description}</p>
                    {!expertMode && (
                      <p className="text-xs text-muted-foreground">{issue.recommendation}</p>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge 
                    variant="outline" 
                    className={`text-xs ${getSeverityColor(issue.severity)}`}
                  >
                    {issue.severity.toUpperCase()}
                  </Badge>
                  {!expertMode && <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                </div>
              </div>
            </CollapsibleTrigger>
            
            {expertMode && (
              <CollapsibleContent className="px-3 pb-3">
                <div className="space-y-2 text-sm text-muted-foreground">
                  {issue.technicalDetails && (
                    <div>
                      <strong>Technical Details:</strong> {issue.technicalDetails}
                    </div>
                  )}
                  {issue.location && (
                    <div>
                      <strong>Location:</strong> <code className="bg-muted px-1 rounded text-xs">{issue.location}</code>
                    </div>
                  )}
                  <div>
                    <strong>Recommendation:</strong> {issue.recommendation}
                  </div>
                </div>
              </CollapsibleContent>
            )}
          </Collapsible>
        ))}
      </CardContent>
    </Card>
  );
};
