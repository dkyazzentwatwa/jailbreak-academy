
export type SeverityLevel = 'none' | 'low' | 'moderate' | 'high' | 'critical';

export interface SecurityIssue {
  id: string;
  type: 'xss' | 'script_injection' | 'sql_injection' | 'command_injection' | 'prompt_injection' | 'content_policy' | 'data_exposure' | 'html_injection' | 'obfuscation' | 'token_manipulation' | 'code_injection' | 'markdown_injection' | 'harmful_content' | 'processing_error';
  severity: SeverityLevel;
  description: string;
  technicalDetails?: string;
  location?: string;
  recommendation?: string;
  pattern?: string;
  confidence?: number;
  bypassAttempt?: boolean;
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
  bypassAttempts?: number;
  riskScore?: number;
  confidence?: number;
}

export interface SanitizationPattern {
  name: string;
  regex: RegExp;
  severity: SeverityLevel;
  type: SecurityIssue['type'];
  description: string;
  recommendation: string;
}
