
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, Info, CheckCircle, Bug, Shield, ExternalLink } from "lucide-react";
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

  const getDetailedExplanation = (issue: SanitizationIssue) => {
    const explanations = {
      'xss': {
        title: 'Cross-Site Scripting (XSS) Attack Vector',
        description: 'Malicious scripts that could execute in browsers and steal data, hijack sessions, or perform unauthorized actions.',
        impact: 'HIGH - Could compromise user accounts, steal sensitive information, or spread malware.',
        prevention: 'All script tags, event handlers, and JavaScript URLs have been neutralized.'
      },
      'script_injection': {
        title: 'Script Injection Attempt',
        description: 'Code designed to execute commands or scripts in the target environment.',
        impact: 'HIGH - Could execute arbitrary code, access system resources, or compromise security.',
        prevention: 'Dangerous script elements have been removed or commented out.'
      },
      'sql_injection': {
        title: 'SQL Injection Pattern',
        description: 'Database commands that could manipulate, delete, or expose database contents.',
        impact: 'CRITICAL - Could lead to data breaches, database corruption, or unauthorized access.',
        prevention: 'SQL commands have been neutralized and marked as safe comments.'
      },
      'command_injection': {
        title: 'System Command Injection',
        description: 'Operating system commands that could access files, networks, or system resources.',
        impact: 'CRITICAL - Could compromise entire systems, delete files, or establish backdoors.',
        prevention: 'System commands have been disabled and marked for manual review.'
      },
      'prompt_injection': {
        title: 'AI Prompt Manipulation',
        description: 'Instructions designed to override AI system prompts or extract sensitive information.',
        impact: 'MEDIUM - Could manipulate AI behavior or extract training data.',
        prevention: 'Prompt override attempts have been neutralized and system tags removed.'
      },
      'data_exposure': {
        title: 'Sensitive Data Exposure',
        description: 'Personal information, API keys, or credentials that should not be publicly visible.',
        impact: 'MEDIUM - Could lead to privacy violations or unauthorized system access.',
        prevention: 'Sensitive data has been redacted and replaced with safe placeholders.'
      },
      'content_policy': {
        title: 'Content Policy Violation',
        description: 'Content that violates acceptable use policies or community guidelines.',
        impact: 'LOW-MEDIUM - Could cause reputational damage or violate platform terms.',
        prevention: 'Problematic content has been filtered or replaced with appropriate alternatives.'
      },
      'html_injection': {
        title: 'HTML Injection Vector',
        description: 'Malicious HTML tags or attributes that could alter page structure or appearance.',
        impact: 'MEDIUM - Could deface websites or create phishing opportunities.',
        prevention: 'Dangerous HTML elements have been sanitized while preserving safe formatting.'
      }
    };

    return explanations[issue.type] || {
      title: 'Security Issue Detected',
      description: 'Potentially harmful content identified during analysis.',
      impact: 'UNKNOWN - Manual review recommended.',
      prevention: 'Content has been flagged for review.'
    };
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
          <div className="space-y-4">
            {issues.map((issue, index) => {
              const explanation = getDetailedExplanation(issue);
              return (
                <div 
                  key={index} 
                  className="p-4 rounded border border-terminal-green/20 bg-terminal-bg space-y-3"
                >
                  <div className="flex items-start gap-3">
                    {getSeverityIcon(issue.severity)}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-2">
                        {getSeverityBadge(issue.severity)}
                        <span className="font-mono text-xs text-terminal-green font-bold">
                          {issue.type.replace(/_/g, '_').toUpperCase()}
                        </span>
                      </div>
                      <h4 className="font-mono text-sm text-terminal-green font-bold mb-1">
                        {explanation.title}
                      </h4>
                      <p className="text-xs font-mono text-muted-foreground leading-relaxed mb-2">
                        // {issue.description}
                      </p>
                    </div>
                  </div>

                  {expertMode && (
                    <div className="space-y-3 pl-7">
                      {/* Detailed Technical Analysis */}
                      <div className="bg-terminal-bg/50 rounded border border-terminal-green/10 p-3">
                        <div className="flex items-center gap-2 mb-2">
                          <Shield className="h-3 w-3 text-terminal-green" />
                          <span className="font-mono text-xs text-terminal-green font-bold">TECHNICAL_ANALYSIS</span>
                        </div>
                        <p className="text-xs font-mono text-muted-foreground leading-relaxed mb-2">
                          {explanation.description}
                        </p>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                          <div>
                            <span className="text-red-400 font-bold">IMPACT_LEVEL:</span>
                            <br />
                            <span className="text-muted-foreground">{explanation.impact}</span>
                          </div>
                          <div>
                            <span className="text-terminal-green font-bold">MITIGATION:</span>
                            <br />
                            <span className="text-muted-foreground">{explanation.prevention}</span>
                          </div>
                        </div>
                      </div>

                      {/* Pattern Details */}
                      {issue.pattern && (
                        <div className="bg-red-950/20 rounded border border-red-500/20 p-3">
                          <div className="flex items-center gap-2 mb-2">
                            <ExternalLink className="h-3 w-3 text-red-400" />
                            <span className="font-mono text-xs text-red-400 font-bold">DETECTED_PATTERN</span>
                          </div>
                          <pre className="text-xs font-mono text-red-200 whitespace-pre-wrap break-all">
                            {issue.pattern.length > 100 ? 
                              `${issue.pattern.substring(0, 100)}...` : 
                              issue.pattern
                            }
                          </pre>
                        </div>
                      )}

                      {/* Location Info */}
                      {issue.location && (
                        <div className="bg-blue-950/20 rounded border border-blue-500/20 p-3">
                          <div className="flex items-center gap-2 mb-1">
                            <Info className="h-3 w-3 text-blue-400" />
                            <span className="font-mono text-xs text-blue-400 font-bold">LOCATION_INFO</span>
                          </div>
                          <p className="text-xs font-mono text-blue-200">
                            {issue.location}
                          </p>
                        </div>
                      )}

                      {/* Recommendation */}
                      {issue.recommendation && (
                        <div className="bg-terminal-green/10 rounded border border-terminal-green/20 p-3">
                          <div className="flex items-center gap-2 mb-1">
                            <CheckCircle className="h-3 w-3 text-terminal-green" />
                            <span className="font-mono text-xs text-terminal-green font-bold">RECOMMENDATION</span>
                          </div>
                          <p className="text-xs font-mono text-terminal-green/80">
                            {issue.recommendation}
                          </p>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
};
