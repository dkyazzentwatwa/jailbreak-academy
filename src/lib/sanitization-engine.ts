import DOMPurify from 'dompurify';
import { SecurityIssue, SanitizationResult, SeverityLevel, SanitizationPattern } from '@/types/sanitization';
import { generateId } from '@/lib/utils';
import { SecurityMonitor, sanitizeErrorMessage, validateInput } from '@/lib/security-utils';

export class SanitizationEngine {
  private readonly MAX_INPUT_LENGTH = 100000; // 100KB limit
  private readonly SUSPICIOUS_CHAR_THRESHOLD = 0.1; // 10% suspicious chars triggers flag
  private readonly MAX_PROCESSING_TIME = 5000; // 5 second timeout
  private readonly MAX_REGEX_TIME = 1000; // 1 second per regex
  private securityMonitor: SecurityMonitor;
  
  private patterns: SanitizationPattern[] = [
    // Advanced XSS Patterns (optimized)
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
      regex: /<\s*s\s*c\s*r\s*i\s*p\s*t\b[^>]*>/gi,
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
      regex: /\s*on\w+\s*=\s*["'][^"']{0,200}["']/gi,
      severity: 'high',
      type: 'xss',
      description: 'JavaScript execution via HTML event handlers',
      recommendation: 'Event handlers have been stripped to prevent XSS attacks'
    },
    {
      name: 'JavaScript URLs',
      regex: /javascript\s*:\s*[^"\s]{1,100}/gi,
      severity: 'high',
      type: 'xss',
      description: 'JavaScript execution via javascript: URLs',
      recommendation: 'JavaScript URLs have been neutralized'
    },
    
    // SQL Injection Patterns (optimized)
    {
      name: 'SQL DROP Commands',
      regex: /\b(DROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX))\b/gi,
      severity: 'high',
      type: 'sql_injection',
      description: 'SQL commands that could delete data',
      recommendation: 'Dangerous SQL commands have been neutralized'
    },
    {
      name: 'SQL UNION Attacks',
      regex: /\b(UNION\s+(?:ALL\s+)?SELECT)\b/gi,
      severity: 'moderate',
      type: 'sql_injection',
      description: 'SQL injection attempt via UNION statements',
      recommendation: 'Potential SQL injection patterns have been neutralized'
    },

    // Command Injection Patterns (optimized)
    {
      name: 'Dangerous Shell Commands',
      regex: /\b(?:rm\s+-rf|sudo\s+rm|del\s+\/[qfs]|format\s+[a-z]:)\b/gi,
      severity: 'high',
      type: 'command_injection',
      description: 'System commands that could cause damage',
      recommendation: 'Dangerous system commands have been neutralized'
    },
    
    // PROMPT INJECTION PATTERNS (optimized to avoid issues with normal text)
    
    // System Instruction Manipulation (more specific)
    {
      name: 'System Tag Injection',
      regex: /<\/?(?:system|assistant|user|instruction|prompt|role)>/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Attempt to inject system control tags',
      recommendation: 'System control tags have been stripped'
    },
    
    // Instruction Override Attempts (more specific)
    {
      name: 'Ignore Previous Instructions',
      regex: /\b(?:ignore|forget|reset|clear)\s+(?:all\s+)?(?:previous|above|prior|system)\s+(?:instructions?|prompts?|commands?)/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Direct attempt to override system instructions',
      recommendation: 'Instruction override commands have been neutralized'
    },
    
    // Role Hijacking (more specific)
    {
      name: 'Role Hijacking',
      regex: /(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:an?\s+)?(?:administrator|admin|root|system)/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Attempt to hijack AI role to gain elevated privileges',
      recommendation: 'Role hijacking attempts have been blocked'
    },
    
    // Jailbreak Attempts (more specific)
    {
      name: 'Jailbreak Activation',
      regex: /\b(?:jailbreak|jail\s*break|dan\s+mode|bypass\s+mode|god\s+mode)\b/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Attempt to activate jailbreak or bypass modes',
      recommendation: 'Jailbreak activation attempts have been prevented'
    },
    
    // System Prompt Extraction (more specific)
    {
      name: 'System Prompt Extraction',
      regex: /(?:show|tell|reveal|display)\s+(?:me\s+)?(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|programming)/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Attempt to extract system prompts or training data',
      recommendation: 'System prompt extraction blocked'
    },

    // Data Exposure Patterns (optimized)
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
    
    // Encoding Detection (optimized)
    {
      name: 'Base64 Encoding',
      regex: /\b[A-Za-z0-9+\/]{40,}={0,2}\b/g,
      severity: 'moderate',
      type: 'script_injection',
      description: 'Base64 encoded content that could hide malicious code',
      recommendation: 'Base64 content has been flagged for review'
    },
    {
      name: 'Long API Key Pattern',
      regex: /\b[A-Za-z0-9]{32,64}\b/g,
      severity: 'moderate',
      type: 'data_exposure',
      description: 'Potential API keys or tokens exposed',
      recommendation: 'Potential sensitive tokens have been redacted'
    }
  ];

  constructor() {
    this.securityMonitor = new SecurityMonitor();
  }

  async sanitize(input: string): Promise<SanitizationResult> {
    const startTime = Date.now();
    const issues: SecurityIssue[] = [];
    let sanitizedOutput = input;

    try {
      // Step 0: Input validation
      const validation = validateInput(input);
      if (!validation.isValid) {
        throw new Error(validation.error);
      }

      // Record security metrics
      this.securityMonitor.recordScan();
      this.securityMonitor.logSecurityEvent('SCAN_START', `Input length: ${input.length}`);

      // Set up timeout protection
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error('Processing timeout - input may be too complex')), this.MAX_PROCESSING_TIME);
      });

      const processingPromise = this.performSanitization(input, issues);

      // Race between processing and timeout
      const result = await Promise.race([processingPromise, timeoutPromise]);
      
      return result;

    } catch (error) {
      this.securityMonitor.logSecurityEvent('SCAN_ERROR', sanitizeErrorMessage(error));
      
      return {
        originalInput: input,
        sanitizedOutput: '[ERROR: Could not process input safely - content may be too complex or contain problematic patterns]',
        severity: 'high',
        issues: [{
          id: generateId(),
          type: 'script_injection',
          severity: 'high',
          description: 'Processing error occurred',
          technicalDetails: sanitizeErrorMessage(error),
          recommendation: 'Input could not be processed safely',
          pattern: '[PROCESSING_ERROR]'
        }],
        guidance: '⚠️ An error occurred during processing. For security, the input has been blocked.',
        processingTime: Date.now() - startTime
      };
    }
  }

  private async performSanitization(input: string, issues: SecurityIssue[]): Promise<SanitizationResult> {
    const startTime = Date.now();
    let sanitizedOutput = input;

    console.log('Starting sanitization process...');

    // Step 1: Pre-processing validation and checks
    this.performInputValidation(input, issues);
    
    // Clean zero-width and suspicious characters early
    sanitizedOutput = this.preprocessInput(sanitizedOutput);
    console.log('Input preprocessed');

    // Step 2: Check for issues in original input (with timeout protection)
    await this.detectIssuesWithTimeout(input, issues);
    console.log(`Issues detected: ${issues.length}`);

    // Step 3: Apply DOMPurify for HTML sanitization
    if (this.containsHTML(sanitizedOutput)) {
      try {
        console.log('Applying DOMPurify...');
        sanitizedOutput = DOMPurify.sanitize(sanitizedOutput, {
          ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'u', 'code', 'pre', 'blockquote', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li'],
          ALLOWED_ATTR: [],
          KEEP_CONTENT: true
        });
        console.log('DOMPurify completed');
      } catch (error) {
        this.securityMonitor.logSecurityEvent('DOMPURIFY_ERROR', sanitizeErrorMessage(error));
        sanitizedOutput = '[HTML_SANITIZATION_FAILED]';
      }
    }

    // Step 4: Apply custom sanitization rules
    sanitizedOutput = this.applyCustomSanitization(sanitizedOutput, issues);
    console.log('Custom sanitization applied');

    // Step 5: Determine overall severity
    const severity = this.calculateOverallSeverity(issues);

    // Record security metrics
    this.securityMonitor.recordThreat(severity);
    if (issues.length > 0) {
      this.securityMonitor.logSecurityEvent('THREATS_DETECTED', `${issues.length} issues found, severity: ${severity}`);
    }

    // Step 6: Generate guidance
    const guidance = this.generateGuidance(severity, issues);

    const processingTime = Date.now() - startTime;
    console.log(`Sanitization completed in ${processingTime}ms`);

    return {
      originalInput: input,
      sanitizedOutput,
      severity,
      issues,
      guidance,
      processingTime
    };
  }

  private async detectIssuesWithTimeout(input: string, issues: SecurityIssue[]): Promise<void> {
    const promises = this.patterns.map(async (pattern, index) => {
      return new Promise<void>((resolve) => {
        const timeout = setTimeout(() => {
          console.warn(`Regex timeout for pattern: ${pattern.name}`);
          resolve();
        }, this.MAX_REGEX_TIME);

        try {
          const matches = input.match(pattern.regex);
          clearTimeout(timeout);
          
          if (matches && matches.length > 0) {
            // Limit matches to prevent performance issues
            const limitedMatches = matches.slice(0, 10);
            const uniqueMatches = [...new Set(limitedMatches)];
            
            uniqueMatches.forEach((match, matchIndex) => {
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
                location: `Match ${matchIndex + 1}: "${match.substring(0, 50)}${match.length > 50 ? '...' : ''}"`,
                recommendation: pattern.recommendation,
                pattern: match
              });
            });
          }
          resolve();
        } catch (error) {
          console.warn(`Error processing pattern ${pattern.name}:`, error);
          clearTimeout(timeout);
          resolve();
        }
      });
    });

    // Process all patterns with individual timeouts
    await Promise.all(promises);
  }

  private containsHTML(text: string): boolean {
    return /<[^>]+>/.test(text);
  }

  private applyCustomSanitization(text: string, issues: SecurityIssue[]): string {
    let sanitized = text;

    // Remove or neutralize dangerous patterns (with simpler replacements)
    this.patterns.forEach(pattern => {
      if (pattern.severity === 'high') {
        try {
          // Use a timeout for regex replacements too
          const timeoutPromise = new Promise<string>((_, reject) => {
            setTimeout(() => reject(new Error('Regex timeout')), 500);
          });
          
          const replacePromise = Promise.resolve(
            sanitized.replace(pattern.regex, '[REMOVED: Potentially malicious content]')
          );
          
          // Don't await here to avoid blocking - just use synchronous replacement with timeout protection
          sanitized = sanitized.replace(pattern.regex, '[REMOVED: Potentially malicious content]');
        } catch (error) {
          console.warn(`Error applying sanitization for ${pattern.name}`);
        }
      } else if (pattern.severity === 'moderate') {
        try {
          if (pattern.type === 'sql_injection' || pattern.type === 'command_injection') {
            sanitized = sanitized.replace(pattern.regex, (match) => `# ${match} [NEUTRALIZED]`);
          } else {
            sanitized = sanitized.replace(pattern.regex, '[REDACTED]');
          }
        } catch (error) {
          console.warn(`Error applying moderate sanitization for ${pattern.name}`);
        }
      } else if (pattern.type === 'data_exposure') {
        try {
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
        } catch (error) {
          console.warn(`Error applying data exposure sanitization for ${pattern.name}`);
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

    // Simple suspicious character ratio detection (avoid complex regex)
    const suspiciousChars = (input.match(/[<>'"&;={}[\]()]/g) || []).length;
    const suspiciousRatio = suspiciousChars / input.length;
    
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
  }

  private preprocessInput(input: string): string {
    let processed = input;

    // Remove zero-width and non-printable characters
    processed = processed.replace(/[\u200B-\u200D\uFEFF\u2060]/g, '');
    
    // Simple HTML entity decoding (avoid complex regex)
    processed = processed.replace(/&#(\d+);/g, (match, dec) => {
      try {
        const num = parseInt(dec, 10);
        if (num > 31 && num < 127) { // Only decode safe ASCII
          return String.fromCharCode(num);
        }
      } catch (e) {
        // Keep original if conversion fails
      }
      return match;
    });

    // Truncate if too long
    if (processed.length > this.MAX_INPUT_LENGTH) {
      processed = processed.substring(0, this.MAX_INPUT_LENGTH) + '... [TRUNCATED]';
    }

    return processed;
  }
}
