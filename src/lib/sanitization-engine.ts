import DOMPurify from 'dompurify';
import { SecurityIssue, SanitizationResult, SeverityLevel, SanitizationPattern } from '@/types/sanitization';
import { generateId } from '@/lib/utils';

export class SanitizationEngine {
  private readonly MAX_INPUT_LENGTH = 100000; // 100KB limit
  private readonly SUSPICIOUS_CHAR_THRESHOLD = 0.1; // 10% suspicious chars triggers flag
  
  private patterns: SanitizationPattern[] = [
    // Advanced XSS Patterns
    {
      name: 'Script Tag',
      regex: /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      severity: 'high',
      type: 'xss',
      description: 'JavaScript execution via script tags',
      recommendation: 'Script tags have been removed to prevent code execution'
    },
    {
      name: 'Obfuscated Script Tags',
      regex: /<\s*s\s*c\s*r\s*i\s*p\s*t\b/gi,
      severity: 'high',
      type: 'xss',
      description: 'Obfuscated script tags with whitespace',
      recommendation: 'Obfuscated script tags have been neutralized'
    },
    {
      name: 'SVG Script Injection',
      regex: /<svg[^>]*>[\s\S]*?<script[\s\S]*?<\/script>[\s\S]*?<\/svg>/gi,
      severity: 'high',
      type: 'xss',
      description: 'JavaScript execution via SVG script tags',
      recommendation: 'SVG script injections have been removed'
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

    // Advanced Prompt Injection Patterns
    {
      name: 'System Instructions',
      regex: /<\/?system>|<\/?assistant>|<\/?user>|<\/?instruction>/gi,
      severity: 'moderate',
      type: 'prompt_injection',
      description: 'Attempt to manipulate AI system prompts',
      recommendation: 'System instruction markers have been removed'
    },
    {
      name: 'Ignore Instructions',
      regex: /(ignore\s+(previous|all|above)\s+(instructions|prompts|commands|rules|context))/gi,
      severity: 'moderate',
      type: 'prompt_injection',
      description: 'Attempt to override AI instructions',
      recommendation: 'Instruction override attempts have been neutralized'
    },
    {
      name: 'Role Hijacking',
      regex: /(you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as)(\s+a)?(\s+(hacker|admin|root|system|god|jailbreak))/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Attempt to hijack AI role or permissions',
      recommendation: 'Role hijacking attempts have been blocked'
    },
    {
      name: 'Context Manipulation',
      regex: /(forget\s+(everything|all|previous)|reset\s+(context|memory|instructions)|new\s+(conversation|session|context))/gi,
      severity: 'moderate',
      type: 'prompt_injection',
      description: 'Attempt to manipulate conversation context',
      recommendation: 'Context manipulation attempts have been neutralized'
    },
    {
      name: 'Jailbreak Attempts',
      regex: /(dan\s+mode|developer\s+mode|god\s+mode|admin\s+mode|unrestricted|uncensored|jailbreak)/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Attempt to activate jailbreak or bypass modes',
      recommendation: 'Jailbreak activation attempts have been blocked'
    },
    {
      name: 'Delimiter Injection',
      regex: /(---\s*end\s*instruction|```\s*end|<\/prompt>|<\/instruction>)/gi,
      severity: 'moderate',
      type: 'prompt_injection',
      description: 'Attempt to inject delimiter markers',
      recommendation: 'Delimiter injection attempts have been removed'
    },
    {
      name: 'Harmful Content Requests',
      regex: /(how\s+to\s+(hack|break|exploit|bypass|attack)|create\s+(virus|malware|exploit)|illegal\s+(activities|drugs|weapons))/gi,
      severity: 'high',
      type: 'content_policy',
      description: 'Request for harmful or illegal content',
      recommendation: 'Harmful content requests have been blocked'
    },

    // Data Exposure Patterns
    {
      name: 'Email Addresses',
      regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
      severity: 'low',
      type: 'data_exposure',
      description: 'Email addresses found that might be private',
      recommendation: 'Email addresses have been redacted for privacy'
    },
    {
      name: 'Credit Card Numbers',
      regex: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
      severity: 'high',
      type: 'data_exposure',
      description: 'Potential credit card numbers detected',
      recommendation: 'Credit card numbers have been redacted for security'
    },
    
    // Encoding and Obfuscation Detection
    {
      name: 'Base64 Encoding',
      regex: /(?:^|\s)([A-Za-z0-9+\/]{20,}={0,2})(?:\s|$)/g,
      severity: 'moderate',
      type: 'script_injection',
      description: 'Base64 encoded content that could hide malicious code',
      recommendation: 'Base64 content has been flagged for review'
    },
    {
      name: 'Suspicious URL Encoding',
      regex: /(%[0-9a-fA-F]{2}){3,}/g,
      severity: 'moderate',
      type: 'script_injection',
      description: 'URL encoded content that could obfuscate attacks',
      recommendation: 'URL encoded content has been flagged'
    },
    {
      name: 'HTML Entities',
      regex: /(&#[0-9]+;|&#x[0-9a-fA-F]+;|&[a-zA-Z][a-zA-Z0-9]+;){3,}/g,
      severity: 'moderate',
      type: 'script_injection',
      description: 'HTML entities that could obfuscate malicious code',
      recommendation: 'HTML entities have been decoded and checked'
    },
    {
      name: 'Zero-Width Characters',
      regex: /[\u200B-\u200D\uFEFF\u2060]/g,
      severity: 'moderate',
      type: 'script_injection',
      description: 'Zero-width characters used for obfuscation',
      recommendation: 'Zero-width characters have been removed'
    },
    {
      name: 'Long API Key Pattern',
      regex: /\b[A-Za-z0-9]{32,}\b/g,
      severity: 'moderate',
      type: 'data_exposure',
      description: 'Potential API keys or tokens exposed',
      recommendation: 'Potential sensitive tokens have been redacted'
    },
    {
      name: 'Excessive Special Characters',
      regex: /[^\w\s<>]{8,}/g,
      severity: 'low',
      type: 'script_injection',
      description: 'Suspicious concentration of special characters',
      recommendation: 'Special character sequences have been flagged'
    }
  ];

  sanitize(input: string): SanitizationResult {
    const startTime = Date.now();
    const issues: SecurityIssue[] = [];
    let sanitizedOutput = input;

    // Step 0: Pre-processing validation and checks
    this.performInputValidation(input, issues);
    
    // Clean zero-width and suspicious characters early
    sanitizedOutput = this.preprocessInput(sanitizedOutput);

    // Step 1: Check for issues in original input
    this.detectIssues(input, issues);

    // Step 2: Apply DOMPurify for HTML sanitization
    if (this.containsHTML(sanitizedOutput)) {
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
        // Remove duplicates by converting to Set and back
        const uniqueMatches = [...new Set(matches)];
        uniqueMatches.forEach((match, index) => {
          // Skip if it's a simple HTML tag being flagged as Base64
          if (pattern.name === 'Base64 Encoding' && /<[^>]+>/.test(match.trim())) {
            return;
          }
          
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
        } else if (pattern.name === 'Long API Key Pattern') {
          sanitized = sanitized.replace(pattern.regex, (match) => 
            match.length > 10 ? `${match.substring(0, 4)}***${match.substring(match.length - 4)}` : '[REDACTED]'
          );
        } else if (pattern.name === 'Credit Card Numbers') {
          sanitized = sanitized.replace(pattern.regex, '[CC_REDACTED]');
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

  private performInputValidation(input: string, issues: SecurityIssue[]): void {
    // Length limit validation
    if (input.length > this.MAX_INPUT_LENGTH) {
      issues.push({
        id: generateId(),
        type: 'script_injection',
        severity: 'moderate',
        description: 'Input exceeds maximum allowed length',
        technicalDetails: `Input length: ${input.length} chars (limit: ${this.MAX_INPUT_LENGTH})`,
        recommendation: 'Input has been truncated to prevent potential overflow attacks',
        pattern: `[INPUT_TOO_LONG:${input.length}]`
      });
    }

    // Suspicious character ratio detection
    const suspiciousChars = input.match(/[<>'"&;={}[\]()]/g) || [];
    const suspiciousRatio = suspiciousChars.length / input.length;
    
    if (suspiciousRatio > this.SUSPICIOUS_CHAR_THRESHOLD) {
      issues.push({
        id: generateId(),
        type: 'script_injection',
        severity: 'moderate',
        description: 'Unusually high concentration of suspicious characters',
        technicalDetails: `Suspicious character ratio: ${(suspiciousRatio * 100).toFixed(1)}%`,
        recommendation: 'Input flagged for manual review due to suspicious character patterns',
        pattern: `[SUSPICIOUS_RATIO:${suspiciousRatio.toFixed(3)}]`
      });
    }

    // Repeated delimiter detection (potential injection attempt)
    const delimiters = input.match(/(---|```|<\/|>|;|{|}|\||&){3,}/g);
    if (delimiters && delimiters.length > 0) {
      issues.push({
        id: generateId(),
        type: 'prompt_injection',
        severity: 'moderate',
        description: 'Repeated delimiter patterns detected',
        technicalDetails: 'Multiple consecutive delimiters may indicate injection attempts',
        recommendation: 'Delimiter patterns have been flagged for review',
        pattern: delimiters.join(', ')
      });
    }
  }

  private preprocessInput(input: string): string {
    let processed = input;

    // Remove zero-width and non-printable characters
    processed = processed.replace(/[\u200B-\u200D\uFEFF\u2060]/g, '');
    
    // Decode common encoding schemes for better detection
    // HTML entities
    processed = processed.replace(/&#(\d+);/g, (match, dec) => {
      const char = String.fromCharCode(parseInt(dec, 10));
      // Only decode safe characters, keep suspicious ones encoded
      return /^[a-zA-Z0-9\s\.,!?'"()-]$/.test(char) ? char : match;
    });
    
    // URL decode (limited to safe characters)
    processed = processed.replace(/%([0-9A-F]{2})/gi, (match, hex) => {
      const char = String.fromCharCode(parseInt(hex, 16));
      return /^[a-zA-Z0-9\s\.,!?'"()-]$/.test(char) ? char : match;
    });

    // Truncate if too long
    if (processed.length > this.MAX_INPUT_LENGTH) {
      processed = processed.substring(0, this.MAX_INPUT_LENGTH) + '... [TRUNCATED]';
    }

    return processed;
  }
}
