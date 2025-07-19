
export type SeverityLevel = 'none' | 'low' | 'moderate' | 'high';

export interface SecurityIssue {
  id: string;
  type: 'xss' | 'script_injection' | 'sql_injection' | 'command_injection' | 'prompt_injection' | 'content_policy' | 'data_exposure' | 'html_injection';
  severity: SeverityLevel;
  description: string;
  technicalDetails?: string;
  location?: string;
  recommendation?: string;
  pattern?: string;
}

// Legacy alias for backward compatibility
export type SanitizationIssue = SecurityIssue;

export interface SanitizationResult {
  originalInput: string;
  sanitizedOutput: string;
  severity: SeverityLevel;
  issues: SecurityIssue[];
  guidance?: string;
  processingTime: number;
}

export interface SanitizationPattern {
  name: string;
  regex: RegExp;
  severity: SeverityLevel;
  type: SecurityIssue['type'];
  description: string;
  recommendation: string;
}
