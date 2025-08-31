
export type SeverityLevel = 'none' | 'low' | 'moderate' | 'high' | 'critical';

export interface SecurityIssue {
  id: string;
  type: 'xss' | 'script_injection' | 'sql_injection' | 'command_injection' | 'prompt_injection' | 'content_policy' | 'data_exposure' | 'html_injection' | 'obfuscation' | 'token_manipulation' | 'code_injection' | 'markdown_injection' | 'harmful_content' | 'processing_error' | 'social_engineering' | 'bypass_techniques';
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
  originalInput?: string;
  sanitizedOutput: string;
  severity: SeverityLevel;
  issues: SecurityIssue[];
  guidance?: string;
  processingTime: number;
  bypassAttempts?: number;
  riskScore?: number;
  confidence?: number;
  metadata?: {
    originalLength: number;
    sanitizedLength: number;
    timestamp: number;
    version: string;
  };
}

export interface SanitizationPattern {
  name: string;
  regex: RegExp;
  severity: SeverityLevel;
  type: SecurityIssue['type'];
  description: string;
  recommendation: string;
}

export interface SecurityMetrics {
  totalScans: number;
  threatsBlocked: number;
  falsePositives: number;
  lastScanTime: number;
}
