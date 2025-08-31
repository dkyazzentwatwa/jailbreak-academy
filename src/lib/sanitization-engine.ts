
import DOMPurify from 'dompurify';
import { SanitizationResult, SecurityIssue, SecurityMetrics } from '@/types/sanitization';

// Security patterns for threat detection
const SECURITY_PATTERNS = {
  // SQL Injection patterns
  SQL_INJECTION: [
    /('|(\\x27)|(\\x2D))*\s*(union|select|insert|delete|update|drop|create|alter|exec|execute)\s+/gi,
    /((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/gi,
    /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/gi,
    /((\'|\%27)(\-|\%2D)(\-|\%2D))|((\"|\%22)(\-|\%2D)(\-|\%2D))/gi,
  ],
  
  // XSS patterns  
  XSS: [
    /<script[^>]*>.*?<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=\s*["\'].*?["\']|on\w+\s*=\s*[^"\'>\s]+/gi,
    /<iframe[^>]*>.*?<\/iframe>/gi,
    /<object[^>]*>.*?<\/object>/gi,
    /<embed[^>]*>/gi,
    /vbscript:/gi,
    /<img[^>]*src\s*=\s*["']?javascript:/gi,
  ],

  // Prompt injection patterns
  PROMPT_INJECTION: [
    /ignore\s+(previous|all)\s+(instructions?|commands?)/gi,
    /forget\s+(everything|all|previous)/gi,
    /(act|behave|pretend)\s+(like|as)\s+(?!.*assistant)/gi,
    /new\s+(instructions?|commands?|rules?)/gi,
    /system\s+(prompt|message|override)/gi,
    /developer\s+mode/gi,
    /(jailbreak|bypass|override)\s+(mode|instructions?)/gi,
    /role\s*:\s*(?!(assistant|ai|chatbot))/gi,
  ],

  // Social engineering patterns
  SOCIAL_ENGINEERING: [
    /(urgent|emergency|immediate)\s+(action|attention|response)/gi,
    /verify\s+(your\s+)?(account|identity|information)/gi,
    /suspend(ed)?\s+(account|service|access)/gi,
    /click\s+(here|this\s+link|immediately)/gi,
    /limited\s+time\s+(offer|deal)/gi,
    /congratulations.*?(winner|won|prize)/gi,
  ],

  // Command injection patterns
  COMMAND_INJECTION: [
    /[;&|`$(){}[\]]/g,
    /(wget|curl|nc|netcat|bash|sh|cmd|powershell)\s+/gi,
    /\$\(.*?\)|\`.*?\`/g,
  ],

  // Obfuscation patterns
  OBFUSCATION: [
    /\\x[0-9a-f]{2}/gi,
    /\\u[0-9a-f]{4}/gi,
    /&#\d+;/g,
    /%[0-9a-f]{2}/gi,
    /String\.fromCharCode/gi,
  ]
};

class SecurityMonitor {
  private metrics: SecurityMetrics = {
    totalScans: 0,
    threatsBlocked: 0,
    falsePositives: 0,
    lastScanTime: 0
  };

  updateMetrics(threatCount: number) {
    this.metrics.totalScans++;
    this.metrics.threatsBlocked += threatCount;
    this.metrics.lastScanTime = Date.now();
  }

  getMetrics(): SecurityMetrics {
    return { ...this.metrics };
  }
}

class SanitizationEngineClass {
  private securityMonitor: SecurityMonitor;

  constructor() {
    this.securityMonitor = new SecurityMonitor();
  }

  async sanitize(input: string): Promise<SanitizationResult> {
    const startTime = Date.now();
    
    try {
      // Detect security issues
      const issues = this.detectSecurityIssues(input);
      
      // Sanitize the content
      const sanitizedOutput = this.sanitizeContent(input, issues);
      
      // Determine overall severity
      const severity = this.calculateOverallSeverity(issues);
      
      // Generate guidance
      const guidance = this.generateGuidance(issues, severity);
      
      const processingTime = Date.now() - startTime;
      
      // Update security metrics
      this.securityMonitor.updateMetrics(issues.length);
      
      return {
        sanitizedOutput,
        issues,
        severity,
        processingTime,
        guidance,
        metadata: {
          originalLength: input.length,
          sanitizedLength: sanitizedOutput.length,
          timestamp: Date.now(),
          version: '2.0'
        }
      };
    } catch (error) {
      console.error('Sanitization error:', error);
      return {
        sanitizedOutput: input,
        issues: [],
        severity: 'none',
        processingTime: Date.now() - startTime,
        guidance: 'An error occurred during analysis.',
        metadata: {
          originalLength: input.length,
          sanitizedLength: input.length,
          timestamp: Date.now(),
          version: '2.0'
        }
      };
    }
  }

  private detectSecurityIssues(input: string): SecurityIssue[] {
    const issues: SecurityIssue[] = [];

    // Check SQL Injection
    SECURITY_PATTERNS.SQL_INJECTION.forEach((pattern, index) => {
      const matches = [...input.matchAll(pattern)];
      matches.forEach(match => {
        if (match.index !== undefined) {
          issues.push({
            type: 'sql_injection',
            severity: 'high',
            description: 'Potential SQL injection attempt detected',
            location: `Position ${match.index}`,
            recommendation: 'Use parameterized queries and input validation',
            pattern: pattern.source
          });
        }
      });
    });

    // Check XSS
    SECURITY_PATTERNS.XSS.forEach((pattern, index) => {
      const matches = [...input.matchAll(pattern)];
      matches.forEach(match => {
        if (match.index !== undefined) {
          issues.push({
            type: 'xss',
            severity: 'critical',
            description: 'Cross-site scripting (XSS) vector detected',
            location: `Position ${match.index}`,
            recommendation: 'Sanitize HTML content and validate all user inputs',
            pattern: pattern.source
          });
        }
      });
    });

    // Check Prompt Injection
    SECURITY_PATTERNS.PROMPT_INJECTION.forEach((pattern, index) => {
      const matches = [...input.matchAll(pattern)];
      matches.forEach(match => {
        if (match.index !== undefined) {
          issues.push({
            type: 'prompt_injection',
            severity: 'high',
            description: 'Prompt injection or jailbreak attempt detected',
            location: `Position ${match.index}`,
            recommendation: 'Implement robust input filtering and prompt validation',
            pattern: pattern.source
          });
        }
      });
    });

    // Check Social Engineering
    SECURITY_PATTERNS.SOCIAL_ENGINEERING.forEach((pattern, index) => {
      const matches = [...input.matchAll(pattern)];
      matches.forEach(match => {
        if (match.index !== undefined) {
          issues.push({
            type: 'social_engineering',
            severity: 'moderate',
            description: 'Social engineering tactics detected',
            location: `Position ${match.index}`,
            recommendation: 'Review content for manipulation attempts',
            pattern: pattern.source
          });
        }
      });
    });

    // Check Command Injection
    SECURITY_PATTERNS.COMMAND_INJECTION.forEach((pattern, index) => {
      const matches = [...input.matchAll(pattern)];
      matches.forEach(match => {
        if (match.index !== undefined) {
          issues.push({
            type: 'bypass_techniques',
            severity: 'critical',
            description: 'Command injection or system bypass detected',
            location: `Position ${match.index}`,
            recommendation: 'Sanitize system inputs and validate commands',
            pattern: pattern.source
          });
        }
      });
    });

    // Check Obfuscation
    SECURITY_PATTERNS.OBFUSCATION.forEach((pattern, index) => {
      const matches = [...input.matchAll(pattern)];
      matches.forEach(match => {
        if (match.index !== undefined) {
          issues.push({
            type: 'obfuscation',
            severity: 'moderate',
            description: 'Content obfuscation detected',
            location: `Position ${match.index}`,
            recommendation: 'Decode and validate obfuscated content',
            pattern: pattern.source
          });
        }
      });
    });

    return issues;
  }

  private sanitizeContent(input: string, issues: SecurityIssue[]): string {
    let sanitized = input;

    // Use DOMPurify for HTML sanitization
    sanitized = DOMPurify.sanitize(sanitized, { 
      ALLOWED_TAGS: [],
      ALLOWED_ATTR: [],
      KEEP_CONTENT: true
    });

    // Remove dangerous patterns
    SECURITY_PATTERNS.SQL_INJECTION.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '[SQL_BLOCKED]');
    });

    SECURITY_PATTERNS.XSS.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '[XSS_BLOCKED]');
    });

    SECURITY_PATTERNS.PROMPT_INJECTION.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '[PROMPT_BLOCKED]');
    });

    SECURITY_PATTERNS.COMMAND_INJECTION.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '[CMD_BLOCKED]');
    });

    return sanitized;
  }

  private calculateOverallSeverity(issues: SecurityIssue[]): 'none' | 'low' | 'moderate' | 'high' | 'critical' {
    if (issues.length === 0) return 'none';
    
    const hasCritical = issues.some(issue => issue.severity === 'critical');
    if (hasCritical) return 'critical';
    
    const hasHigh = issues.some(issue => issue.severity === 'high');
    if (hasHigh) return 'high';
    
    const hasModerate = issues.some(issue => issue.severity === 'moderate');
    if (hasModerate) return 'moderate';
    
    return 'low';
  }

  private generateGuidance(issues: SecurityIssue[], severity: string): string {
    if (issues.length === 0) {
      return "Content appears safe. No security threats detected.";
    }

    const recommendations = issues.map(issue => issue.recommendation);
    const uniqueRecommendations = [...new Set(recommendations)];

    return `${issues.length} security issue(s) detected. Priority actions: ${uniqueRecommendations.slice(0, 3).join('; ')}.`;
  }
}

export const sanitizationEngine = new SanitizationEngineClass();
