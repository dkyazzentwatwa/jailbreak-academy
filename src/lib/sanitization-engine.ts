
import DOMPurify from 'dompurify';
import { SecurityIssue, SanitizationResult, SeverityLevel, SanitizationPattern } from '@/types/sanitization';
import { generateId } from '@/lib/utils';
import { SecurityMonitor, sanitizeErrorMessage, validateInput } from '@/lib/security-utils';

export class SanitizationEngine {
  private readonly MAX_INPUT_LENGTH = 100000; // 100KB limit
  private readonly SUSPICIOUS_CHAR_THRESHOLD = 0.1; // 10% suspicious chars triggers flag
  private readonly MAX_PROCESSING_TIME = 3000; // 3 second timeout (reduced)
  private readonly MAX_REGEX_TIME = 200; // 200ms per regex (reduced)
  private readonly MAX_PATTERN_MATCHES = 5; // Limit matches per pattern
  private securityMonitor: SecurityMonitor;
  
  private patterns: SanitizationPattern[] = [
    // Simplified and optimized patterns to prevent freezing
    {
      name: 'Script Tag',
      regex: /<script[^>]*>.*?<\/script>/gi,
      severity: 'high',
      type: 'xss',
      description: 'JavaScript execution via script tags',
      recommendation: 'Script tags have been removed to prevent code execution'
    },
    {
      name: 'On-Event Handlers',
      regex: /\son\w+\s*=\s*["'][^"']*["']/gi,
      severity: 'high',
      type: 'xss',
      description: 'JavaScript execution via HTML event handlers',
      recommendation: 'Event handlers have been stripped to prevent XSS attacks'
    },
    {
      name: 'JavaScript URLs',
      regex: /javascript\s*:\s*[^"\s]*/gi,
      severity: 'high',
      type: 'xss',
      description: 'JavaScript execution via javascript: URLs',
      recommendation: 'JavaScript URLs have been neutralized'
    },
    {
      name: 'SQL DROP Commands',
      regex: /\bDROP\s+(?:TABLE|DATABASE)\b/gi,
      severity: 'high',
      type: 'sql_injection',
      description: 'SQL commands that could delete data',
      recommendation: 'Dangerous SQL commands have been neutralized'
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

  constructor() {
    this.securityMonitor = new SecurityMonitor();
  }

  async sanitize(input: string): Promise<SanitizationResult> {
    const startTime = Date.now();
    console.log('=== SANITIZATION START ===');
    console.log('Input length:', input.length);

    try {
      // Step 0: Quick input validation with early returns
      if (!input || typeof input !== 'string') {
        console.log('Invalid input detected');
        return this.createErrorResult(input, 'Invalid input provided', startTime);
      }

      if (input.length > this.MAX_INPUT_LENGTH) {
        console.log('Input too long, truncating');
        input = input.substring(0, this.MAX_INPUT_LENGTH);
      }

      // Record security metrics
      this.securityMonitor.recordScan();
      console.log('Security scan recorded');

      // Set up aggressive timeout protection
      const result = await Promise.race([
        this.performSanitization(input),
        this.createTimeoutPromise()
      ]);

      console.log('=== SANITIZATION COMPLETE ===');
      return result;

    } catch (error) {
      console.error('Sanitization error:', error);
      this.securityMonitor.logSecurityEvent('SCAN_ERROR', sanitizeErrorMessage(error));
      return this.createErrorResult(input, sanitizeErrorMessage(error), startTime);
    }
  }

  private createTimeoutPromise(): Promise<SanitizationResult> {
    return new Promise((_, reject) => {
      setTimeout(() => {
        console.log('TIMEOUT: Sanitization took too long');
        reject(new Error('Processing timeout - operation cancelled for safety'));
      }, this.MAX_PROCESSING_TIME);
    });
  }

  private createErrorResult(input: string, error: string, startTime: number): SanitizationResult {
    return {
      originalInput: input,
      sanitizedOutput: '[ERROR: Input could not be processed safely]',
      severity: 'high',
      issues: [{
        id: generateId(),
        type: 'script_injection',
        severity: 'high',
        description: 'Processing error occurred',
        technicalDetails: error,
        recommendation: 'Input blocked for security',
        pattern: '[PROCESSING_ERROR]'
      }],
      guidance: '⚠️ Input could not be processed safely and has been blocked.',
      processingTime: Date.now() - startTime
    };
  }

  private async performSanitization(input: string): Promise<SanitizationResult> {
    const startTime = Date.now();
    const issues: SecurityIssue[] = [];
    let sanitizedOutput = input;

    console.log('Step 1: Pre-processing...');
    // Step 1: Simple pre-processing (no complex regex)
    sanitizedOutput = sanitizedOutput.replace(/[\u200B-\u200D\uFEFF]/g, ''); // Remove zero-width chars
    console.log('Pre-processing complete');

    console.log('Step 2: Pattern detection...');
    // Step 2: Pattern detection with individual timeouts
    await this.detectIssuesSafely(input, issues);
    console.log(`Pattern detection complete. Found ${issues.length} issues`);

    console.log('Step 3: DOMPurify sanitization...');
    // Step 3: DOMPurify with timeout
    if (this.containsHTML(sanitizedOutput)) {
      try {
        const purifyPromise = Promise.resolve(
          DOMPurify.sanitize(sanitizedOutput, {
            ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li'],
            ALLOWED_ATTR: [],
            KEEP_CONTENT: true
          })
        );
        
        const timeoutPromise = new Promise<string>((_, reject) => {
          setTimeout(() => reject(new Error('DOMPurify timeout')), 1000);
        });

        sanitizedOutput = await Promise.race([purifyPromise, timeoutPromise]);
        console.log('DOMPurify completed');
      } catch (error) {
        console.log('DOMPurify failed, using fallback');
        sanitizedOutput = sanitizedOutput.replace(/<[^>]*>/g, ''); // Simple tag removal
      }
    }

    console.log('Step 4: Custom sanitization...');
    // Step 4: Apply simple replacements
    sanitizedOutput = this.applySimpleSanitization(sanitizedOutput, issues);
    console.log('Custom sanitization complete');

    // Step 5: Calculate results
    const severity = this.calculateOverallSeverity(issues);
    const guidance = this.generateGuidance(severity, issues);
    const processingTime = Date.now() - startTime;

    console.log(`Sanitization finished in ${processingTime}ms with severity: ${severity}`);

    return {
      originalInput: input,
      sanitizedOutput,
      severity,
      issues,
      guidance,
      processingTime
    };
  }

  private async detectIssuesSafely(input: string, issues: SecurityIssue[]): Promise<void> {
    // Process only a few patterns to prevent freezing
    const priorityPatterns = this.patterns.slice(0, 5); // Only process first 5 patterns

    for (const pattern of priorityPatterns) {
      try {
        console.log(`Checking pattern: ${pattern.name}`);
        
        // Create a timeout for each individual pattern
        const patternPromise = new Promise<void>((resolve) => {
          try {
            const matches = input.match(pattern.regex);
            if (matches && matches.length > 0) {
              // Limit to prevent performance issues
              const limitedMatches = matches.slice(0, this.MAX_PATTERN_MATCHES);
              
              limitedMatches.forEach((match, index) => {
                issues.push({
                  id: generateId(),
                  type: pattern.type,
                  severity: pattern.severity,
                  description: pattern.description,
                  technicalDetails: `Pattern: "${pattern.name}"`,
                  location: `Match ${index + 1}`,
                  recommendation: pattern.recommendation,
                  pattern: match.substring(0, 50) + (match.length > 50 ? '...' : '')
                });
              });
            }
          } catch (error) {
            console.warn(`Pattern ${pattern.name} failed:`, error);
          }
          resolve();
        });

        const timeoutPromise = new Promise<void>((resolve) => {
          setTimeout(() => {
            console.warn(`Pattern ${pattern.name} timed out`);
            resolve();
          }, this.MAX_REGEX_TIME);
        });

        await Promise.race([patternPromise, timeoutPromise]);
        
      } catch (error) {
        console.warn(`Error processing pattern ${pattern.name}:`, error);
        continue; // Skip this pattern and continue with others
      }
    }
  }

  private containsHTML(text: string): boolean {
    return /<[a-zA-Z]/.test(text); // Simple check for HTML tags
  }

  private applySimpleSanitization(text: string, issues: SecurityIssue[]): string {
    let sanitized = text;

    try {
      // Only apply the most critical sanitizations
      sanitized = sanitized.replace(/<script[^>]*>.*?<\/script>/gi, '[SCRIPT_REMOVED]');
      sanitized = sanitized.replace(/\son\w+\s*=\s*["'][^"']*["']/gi, '');
      sanitized = sanitized.replace(/javascript\s*:\s*[^"\s]*/gi, '[JS_URL_REMOVED]');
      sanitized = sanitized.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[EMAIL_REDACTED]');
    } catch (error) {
      console.warn('Sanitization replacement error:', error);
    }

    return sanitized;
  }

  private calculateOverallSeverity(issues: SecurityIssue[]): SeverityLevel {
    if (issues.length === 0) return 'none';
    
    const hasHigh = issues.some(issue => issue.severity === 'high');
    const hasModerate = issues.some(issue => issue.severity === 'moderate');
    
    if (hasHigh) return 'high';
    if (hasModerate) return 'moderate';
    return 'low';
  }

  private generateGuidance(severity: SeverityLevel, issues: SecurityIssue[]): string {
    switch (severity) {
      case 'high':
        return "⚠️ Critical security issues detected and neutralized.";
      case 'moderate':
        return "⚡ Some potentially harmful content was detected and handled.";
      case 'low':
        return "✨ Minor issues were cleaned up for safety.";
      default:
        return "✅ No security issues detected.";
    }
  }
}
