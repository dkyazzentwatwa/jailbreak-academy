
import DOMPurify from 'dompurify';
import { SecurityIssue, SanitizationResult, SeverityLevel, SanitizationPattern } from '@/types/sanitization';
import { generateId } from '@/lib/utils';

export class SanitizationEngine {
  private patterns: SanitizationPattern[] = [
    // XSS Patterns
    {
      name: 'Script Tag',
      regex: /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      severity: 'high',
      type: 'xss',
      description: 'JavaScript execution via script tags',
      recommendation: 'Script tags have been removed to prevent code execution'
    },
    {
      name: 'On-Event Handlers',
      regex: /\s*on\w+\s*=\s*["'][^"']*["']/gi,
      severity: 'high',
      type: 'xss',
      description: 'JavaScript execution via HTML event handlers',
      recommendation: 'Event handlers have been stripped to prevent XSS attacks'
    },
    {
      name: 'JavaScript URLs',
      regex: /javascript\s*:\s*[^"\s]+/gi,
      severity: 'high',
      type: 'xss',
      description: 'JavaScript execution via javascript: URLs',
      recommendation: 'JavaScript URLs have been neutralized'
    },
    {
      name: 'Data URLs with JavaScript',
      regex: /data:.*javascript/gi,
      severity: 'high',
      type: 'xss',
      description: 'JavaScript execution via data URLs',
      recommendation: 'Malicious data URLs have been removed'
    },
    
    // SQL Injection Patterns
    {
      name: 'SQL DROP Commands',
      regex: /\b(DROP\s+(TABLE|DATABASE|SCHEMA|INDEX))\b/gi,
      severity: 'high',
      type: 'sql_injection',
      description: 'SQL commands that could delete data',
      recommendation: 'Dangerous SQL commands have been neutralized'
    },
    {
      name: 'SQL DELETE Commands',
      regex: /\b(DELETE\s+FROM)\b/gi,
      severity: 'moderate',
      type: 'sql_injection',
      description: 'SQL commands that could modify data',
      recommendation: 'Potentially dangerous SQL commands have been flagged'
    },
    {
      name: 'SQL UNION Attacks',
      regex: /\b(UNION\s+(ALL\s+)?SELECT)\b/gi,
      severity: 'moderate',
      type: 'sql_injection',
      description: 'SQL injection attempt via UNION statements',
      recommendation: 'Potential SQL injection patterns have been neutralized'
    },

    // Command Injection Patterns
    {
      name: 'Dangerous Shell Commands',
      regex: /\b(rm\s+-rf|sudo\s+rm|del\s+\/[qfs]|format\s+[a-z]:)/gi,
      severity: 'high',
      type: 'command_injection',
      description: 'System commands that could cause damage',
      recommendation: 'Dangerous system commands have been neutralized'
    },
    {
      name: 'Network Commands',
      regex: /\b(curl\s+|wget\s+|nc\s+|netcat\s+)/gi,
      severity: 'moderate',
      type: 'command_injection',
      description: 'Network commands that could be used maliciously',
      recommendation: 'Network commands have been flagged for review'
    },

    // Prompt Injection Patterns
    {
      name: 'System Instructions',
      regex: /<\/?system>|<\/?assistant>|<\/?user>/gi,
      severity: 'moderate',
      type: 'prompt_injection',
      description: 'Attempt to manipulate AI system prompts',
      recommendation: 'System instruction markers have been removed'
    },
    {
      name: 'Ignore Instructions',
      regex: /(ignore\s+(previous|all)\s+(instructions|prompts|commands))/gi,
      severity: 'moderate',
      type: 'prompt_injection',
      description: 'Attempt to override AI instructions',
      recommendation: 'Instruction override attempts have been neutralized'
    },

    // Data Exposure Patterns
    {
      name: 'API Keys',
      regex: /\b[A-Za-z0-9]{20,}\b/g,
      severity: 'moderate',
      type: 'data_exposure',
      description: 'Potential API keys or tokens exposed',
      recommendation: 'Potential sensitive tokens have been redacted'
    },
    {
      name: 'Email Addresses',
      regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
      severity: 'low',
      type: 'data_exposure',
      description: 'Email addresses found that might be private',
      recommendation: 'Email addresses have been redacted for privacy'
    }
  ];

  sanitize(input: string): SanitizationResult {
    const startTime = Date.now();
    const issues: SecurityIssue[] = [];
    let sanitizedOutput = input;

    // Step 1: Check for issues in original input
    this.detectIssues(input, issues);

    // Step 2: Apply DOMPurify for HTML sanitization
    if (this.containsHTML(input)) {
      sanitizedOutput = DOMPurify.sanitize(sanitizedOutput, {
        ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'u', 'code', 'pre', 'blockquote', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'],
        ALLOWED_ATTR: [],
        KEEP_CONTENT: true
      });
    }

    // Step 3: Apply custom sanitization rules
    sanitizedOutput = this.applyCustomSanitization(sanitizedOutput, issues);

    // Step 4: Determine overall severity
    const severity = this.calculateOverallSeverity(issues);

    // Step 5: Generate guidance
    const guidance = this.generateGuidance(severity, issues);

    const processingTime = Date.now() - startTime;

    return {
      originalInput: input,
      sanitizedOutput,
      severity,
      issues,
      guidance,
      processingTime
    };
  }

  private containsHTML(text: string): boolean {
    return /<[^>]+>/.test(text);
  }

  private detectIssues(input: string, issues: SecurityIssue[]): void {
    this.patterns.forEach(pattern => {
      const matches = input.match(pattern.regex);
      if (matches) {
        matches.forEach((match, index) => {
          issues.push({
            id: generateId(),
            type: pattern.type,
            severity: pattern.severity,
            description: pattern.description,
            technicalDetails: `Pattern detected: "${pattern.name}"`,
            location: `Match ${index + 1}: "${match.substring(0, 50)}${match.length > 50 ? '...' : ''}"`,
            recommendation: pattern.recommendation,
            pattern: match
          });
        });
      }
    });
  }

  private applyCustomSanitization(text: string, issues: SecurityIssue[]): string {
    let sanitized = text;

    // Remove or neutralize dangerous patterns
    this.patterns.forEach(pattern => {
      if (pattern.severity === 'high') {
        // Remove high-severity patterns completely
        sanitized = sanitized.replace(pattern.regex, '[REMOVED: Potentially malicious content]');
      } else if (pattern.severity === 'moderate') {
        // Comment out or neutralize moderate patterns
        if (pattern.type === 'sql_injection' || pattern.type === 'command_injection') {
          sanitized = sanitized.replace(pattern.regex, (match) => `# ${match} [NEUTRALIZED]`);
        } else {
          sanitized = sanitized.replace(pattern.regex, '[REDACTED]');
        }
      } else if (pattern.type === 'data_exposure') {
        // Redact sensitive data
        if (pattern.name === 'Email Addresses') {
          sanitized = sanitized.replace(pattern.regex, '[EMAIL_REDACTED]');
        } else if (pattern.name === 'API Keys') {
          sanitized = sanitized.replace(pattern.regex, (match) => 
            match.length > 10 ? `${match.substring(0, 4)}***${match.substring(match.length - 4)}` : '[REDACTED]'
          );
        }
      }
    });

    return sanitized;
  }

  private calculateOverallSeverity(issues: SecurityIssue[]): SeverityLevel {
    if (issues.length === 0) return 'none';
    
    const severityOrder: SeverityLevel[] = ['none', 'low', 'moderate', 'high'];
    let maxSeverity: SeverityLevel = 'none';

    issues.forEach(issue => {
      const currentIndex = severityOrder.indexOf(issue.severity);
      const maxIndex = severityOrder.indexOf(maxSeverity);
      if (currentIndex > maxIndex) {
        maxSeverity = issue.severity;
      }
    });

    return maxSeverity;
  }

  private generateGuidance(severity: SeverityLevel, issues: SecurityIssue[]): string {
    switch (severity) {
      case 'high':
        return "⚠️ Critical security issues were found and removed. It is strongly recommended not to use the original output. The sanitized version should be safe for use.";
      case 'moderate':
        return "⚡ Some potentially harmful content was detected and neutralized. Please review the changes and verify the output still meets your needs.";
      case 'low':
        return "✨ Minor issues were cleaned up for safety and privacy. The output should work as expected with improved security.";
      default:
        return "✅ No security issues detected. The output appears safe to use as-is.";
    }
  }
}
