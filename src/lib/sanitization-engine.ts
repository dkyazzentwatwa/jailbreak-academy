import DOMPurify from 'dompurify';
import { SecurityIssue, SanitizationResult, SeverityLevel, SanitizationPattern } from '@/types/sanitization';
import { generateId } from '@/lib/utils';
import { SecurityMonitor, sanitizeErrorMessage, validateInput } from '@/lib/security-utils';

export class SanitizationEngine {
  private readonly MAX_INPUT_LENGTH = 100000; // 100KB limit
  private readonly MAX_PROCESSING_TIME = 5000; // 5 second timeout
  private securityMonitor: SecurityMonitor;
  
  private patterns: SanitizationPattern[] = [
    // XSS Patterns
    {
      name: 'Script Tag',
      regex: /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      severity: 'high',
      type: 'xss',
      description: 'Dangerous script tags that can execute malicious JavaScript',
      recommendation: 'Script tags have been removed to prevent code execution'
    },
    {
      name: 'On-Event Handlers',
      regex: /\son\w+\s*=\s*["'][^"']*["']/gi,
      severity: 'high',
      type: 'xss',
      description: 'HTML event handlers that can execute JavaScript',
      recommendation: 'Event handlers have been stripped to prevent XSS attacks'
    },
    {
      name: 'JavaScript URLs',
      regex: /javascript\s*:\s*[^"\s;]*/gi,
      severity: 'high',
      type: 'xss',
      description: 'JavaScript execution via javascript: protocol',
      recommendation: 'JavaScript URLs have been neutralized'
    },
    {
      name: 'Iframe Injection',
      regex: /<iframe[^>]*>.*?<\/iframe>/gi,
      severity: 'high',
      type: 'xss',
      description: 'Potentially malicious iframe elements',
      recommendation: 'Iframe elements have been removed for security'
    },
    {
      name: 'Object/Embed Tags',
      regex: /<(object|embed)[^>]*>.*?<\/\1>/gi,
      severity: 'high',
      type: 'xss',
      description: 'Object or embed tags that can execute external content',
      recommendation: 'Object/embed tags have been removed'
    },
    
    // SQL Injection Patterns
    {
      name: 'SQL Injection - Union',
      regex: /\bunion\s+(?:all\s+)?select\b/gi,
      severity: 'high',
      type: 'sql_injection',
      description: 'SQL UNION statements that can extract unauthorized data',
      recommendation: 'SQL injection attempts have been neutralized'
    },
    {
      name: 'SQL Injection - Drop',
      regex: /\bdrop\s+(?:table|database|schema|index)\b/gi,
      severity: 'high',
      type: 'sql_injection',
      description: 'SQL DROP commands that can delete data or structures',
      recommendation: 'Dangerous SQL commands have been neutralized'
    },
    {
      name: 'SQL Injection - Delete',
      regex: /\bdelete\s+from\b/gi,
      severity: 'moderate',
      type: 'sql_injection',
      description: 'SQL DELETE statements that can remove data',
      recommendation: 'SQL delete statements have been flagged'
    },
    {
      name: 'SQL Injection - Insert',
      regex: /\binsert\s+into\b/gi,
      severity: 'moderate',
      type: 'sql_injection',
      description: 'SQL INSERT statements that can add malicious data',
      recommendation: 'SQL insert statements have been neutralized'
    },
    {
      name: 'SQL Injection - Update',
      regex: /\bupdate\s+\w+\s+set\b/gi,
      severity: 'moderate',
      type: 'sql_injection',
      description: 'SQL UPDATE statements that can modify data',
      recommendation: 'SQL update statements have been neutralized'
    },
    {
      name: 'SQL Comments',
      regex: /(--[^\r\n]*|\/\*[\s\S]*?\*\/)/g,
      severity: 'moderate',
      type: 'sql_injection',
      description: 'SQL comments that can be used to bypass filters',
      recommendation: 'SQL comments have been removed'
    },
    
    // Command Injection Patterns
    {
      name: 'Command Injection - Pipes',
      regex: /[;&|`$(){}[\]\\]/g,
      severity: 'moderate',
      type: 'command_injection',
      description: 'Shell metacharacters that can be used for command injection',
      recommendation: 'Special characters have been escaped or removed'
    },
    
    // Data Exposure Patterns
    {
      name: 'Email Addresses',
      regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
      severity: 'low',
      type: 'data_exposure',
      description: 'Email addresses that might expose personal information',
      recommendation: 'Email addresses have been redacted for privacy'
    },
    {
      name: 'Credit Card Numbers',
      regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
      severity: 'high',
      type: 'data_exposure',
      description: 'Potential credit card numbers detected',
      recommendation: 'Credit card numbers have been redacted'
    },
    {
      name: 'Phone Numbers',
      regex: /\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}\b/g,
      severity: 'low',
      type: 'data_exposure',
      description: 'Phone numbers that might be personal information',
      recommendation: 'Phone numbers have been redacted'
    },
    
    // Content Policy Patterns
    {
      name: 'Base64 Encoded Content',
      regex: /(?:data:|src=["']?)data:[^"'>\s]+/gi,
      severity: 'moderate',
      type: 'content_policy',
      description: 'Base64 encoded data that could hide malicious content',
      recommendation: 'Encoded data has been flagged for review'
    }
  ];

  constructor() {
    this.securityMonitor = new SecurityMonitor();
  }

  async sanitize(input: string): Promise<SanitizationResult> {
    const startTime = Date.now();
    console.log('=== ENTERPRISE SANITIZATION START ===');
    console.log('Input length:', input.length);

    try {
      // Input validation
      const validation = validateInput(input);
      if (!validation.isValid) {
        console.log('Input validation failed:', validation.error);
        return this.createErrorResult(input, validation.error || 'Invalid input', startTime);
      }

      if (input.length > this.MAX_INPUT_LENGTH) {
        console.log('Input too long, truncating');
        input = input.substring(0, this.MAX_INPUT_LENGTH);
      }

      // Record security metrics
      this.securityMonitor.recordScan();

      // Perform sanitization with timeout
      const result = await Promise.race([
        this.performEnterpriseSanitization(input),
        this.createTimeoutPromise()
      ]);

      // Record threats if found
      if (result.issues.length > 0) {
        this.securityMonitor.recordThreat(result.severity);
      }

      console.log('=== ENTERPRISE SANITIZATION COMPLETE ===');
      return result;

    } catch (error) {
      console.error('Enterprise sanitization error:', error);
      this.securityMonitor.logSecurityEvent('SCAN_ERROR', sanitizeErrorMessage(error));
      return this.createErrorResult(input, sanitizeErrorMessage(error), startTime);
    }
  }

  private createTimeoutPromise(): Promise<SanitizationResult> {
    return new Promise((_, reject) => {
      setTimeout(() => {
        console.log('TIMEOUT: Enterprise sanitization took too long');
        reject(new Error('Processing timeout - operation cancelled for security'));
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

  private async performEnterpriseSanitization(input: string): Promise<SanitizationResult> {
    const startTime = Date.now();
    const issues: SecurityIssue[] = [];
    let sanitizedOutput = input;

    console.log('Step 1: Pre-processing...');
    // Remove zero-width characters and normalize whitespace
    sanitizedOutput = sanitizedOutput
      .replace(/[\u200B-\u200D\uFEFF]/g, '')
      .replace(/\s+/g, ' ')
      .trim();

    console.log('Step 2: Enterprise threat detection...');
    // Detect security issues with all patterns
    await this.detectSecurityIssues(input, issues);
    console.log(`Threat detection complete. Found ${issues.length} issues`);

    console.log('Step 3: DOMPurify sanitization...');
    // Apply DOMPurify if HTML is detected
    if (this.containsHTML(sanitizedOutput)) {
      try {
        sanitizedOutput = DOMPurify.sanitize(sanitizedOutput, {
          ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'],
          ALLOWED_ATTR: [],
          KEEP_CONTENT: true,
          RETURN_DOM: false,
          RETURN_DOM_FRAGMENT: false
        });
        console.log('DOMPurify completed successfully');
      } catch (error) {
        console.log('DOMPurify failed, using fallback');
        sanitizedOutput = sanitizedOutput.replace(/<[^>]*>/g, '');
      }
    }

    console.log('Step 4: Enterprise-grade content replacement...');
    // Apply content sanitization based on detected issues
    sanitizedOutput = this.applyEnterpriseSanitization(sanitizedOutput, issues);

    // Calculate final results
    const severity = this.calculateOverallSeverity(issues);
    const guidance = this.generateEnterpriseGuidance(severity, issues);
    const processingTime = Date.now() - startTime;

    console.log(`Enterprise sanitization completed in ${processingTime}ms with severity: ${severity}`);

    return {
      originalInput: input,
      sanitizedOutput,
      severity,
      issues,
      guidance,
      processingTime
    };
  }

  private async detectSecurityIssues(input: string, issues: SecurityIssue[]): Promise<void> {
    for (const pattern of this.patterns) {
      try {
        console.log(`Scanning for: ${pattern.name}`);
        
        const matches = input.match(pattern.regex);
        if (matches && matches.length > 0) {
          console.log(`Found ${matches.length} matches for ${pattern.name}`);
          
          // Limit matches to prevent performance issues but ensure detection
          const limitedMatches = matches.slice(0, 10);
          
          limitedMatches.forEach((match, index) => {
            const location = input.indexOf(match);
            issues.push({
              id: generateId(),
              type: pattern.type,
              severity: pattern.severity,
              description: pattern.description,
              technicalDetails: `Pattern: "${pattern.name}" - ${match.length} characters`,
              location: location !== -1 ? `Position ${location}` : `Match ${index + 1}`,
              recommendation: pattern.recommendation,
              pattern: match.substring(0, 100) + (match.length > 100 ? '...' : '')
            });
          });
        }
        
      } catch (error) {
        console.warn(`Error processing pattern ${pattern.name}:`, error);
        continue;
      }
    }
  }

  private containsHTML(text: string): boolean {
    return /<[a-zA-Z][^>]*>/i.test(text);
  }

  private applyEnterpriseSanitization(text: string, issues: SecurityIssue[]): string {
    let sanitized = text;
    console.log('Applying enterprise sanitization to threats...');

    try {
      // SQL Injection Sanitization - CRITICAL
      console.log('Neutralizing SQL injection threats...');
      
      // Remove SQL UNION attacks
      sanitized = sanitized.replace(/\bunion\s+(?:all\s+)?select\b/gi, '[SQL_UNION_BLOCKED]');
      
      // Remove dangerous SQL commands
      sanitized = sanitized.replace(/\bdrop\s+(?:table|database|schema|index)\b/gi, '[SQL_DROP_BLOCKED]');
      sanitized = sanitized.replace(/\bdelete\s+from\b/gi, '[SQL_DELETE_BLOCKED]');
      sanitized = sanitized.replace(/\binsert\s+into\b/gi, '[SQL_INSERT_BLOCKED]');
      sanitized = sanitized.replace(/\bupdate\s+\w+\s+set\b/gi, '[SQL_UPDATE_BLOCKED]');
      
      // Remove SQL comments that can bypass filters
      sanitized = sanitized.replace(/(--[^\r\n]*)/g, '[SQL_COMMENT_REMOVED]');
      sanitized = sanitized.replace(/(\/\*[\s\S]*?\*\/)/g, '[SQL_COMMENT_REMOVED]');
      
      // Remove other dangerous SQL keywords
      sanitized = sanitized.replace(/\b(exec|execute|sp_|xp_)\b/gi, '[SQL_EXEC_BLOCKED]');
      sanitized = sanitized.replace(/\b(information_schema|sys\.)\b/gi, '[SQL_SCHEMA_BLOCKED]');
      
      // XSS Sanitization - CRITICAL
      console.log('Neutralizing XSS threats...');
      
      // Remove all script tags completely
      sanitized = sanitized.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '[SCRIPT_REMOVED]');
      sanitized = sanitized.replace(/<script[^>]*>/gi, '[SCRIPT_TAG_REMOVED]');
      
      // Remove all event handlers
      sanitized = sanitized.replace(/\son\w+\s*=\s*["'][^"']*["']/gi, '');
      sanitized = sanitized.replace(/\son\w+\s*=\s*[^"\s>]*/gi, '');
      
      // Neutralize all javascript URLs
      sanitized = sanitized.replace(/javascript\s*:\s*[^"\s;]*/gi, '[JS_URL_REMOVED]');
      
      // Remove dangerous HTML elements
      sanitized = sanitized.replace(/<iframe[^>]*>.*?<\/iframe>/gi, '[IFRAME_REMOVED]');
      sanitized = sanitized.replace(/<(object|embed)[^>]*>.*?<\/\1>/gi, '[EXTERNAL_CONTENT_REMOVED]');
      sanitized = sanitized.replace(/<(applet|meta)[^>]*>/gi, '[DANGEROUS_TAG_REMOVED]');
      
      // Remove data URLs and base64 content
      sanitized = sanitized.replace(/data:[^"'\s>]+/gi, '[DATA_URL_REMOVED]');
      
      // Command Injection Sanitization - HIGH PRIORITY
      console.log('Neutralizing command injection threats...');
      
      // Escape or remove shell metacharacters
      sanitized = sanitized.replace(/[;&|`]/g, '[SHELL_CHAR_BLOCKED]');
      sanitized = sanitized.replace(/\$\([^)]*\)/g, '[COMMAND_SUBSTITUTION_BLOCKED]');
      sanitized = sanitized.replace(/\${[^}]*}/g, '[VARIABLE_EXPANSION_BLOCKED]');
      
      // Data Exposure Protection - PRIVACY CRITICAL
      console.log('Redacting sensitive data...');
      
      // Redact email addresses
      sanitized = sanitized.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[EMAIL_REDACTED]');
      
      // Redact credit card numbers
      sanitized = sanitized.replace(/\b(?:\d{4}[-\s]?){3}\d{4}\b/g, '[CARD_NUMBER_REDACTED]');
      
      // Redact phone numbers
      sanitized = sanitized.replace(/\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}\b/g, '[PHONE_REDACTED]');
      
      // Additional Enterprise Security Measures
      console.log('Applying additional enterprise security...');
      
      // Remove potential SQL injection operators
      sanitized = sanitized.replace(/\b(and|or)\s+1\s*=\s*1\b/gi, '[SQL_LOGIC_BLOCKED]');
      sanitized = sanitized.replace(/'\s*(or|and)\s*'[^']*'\s*=\s*'/gi, '[SQL_CONDITION_BLOCKED]');
      
      // Remove HTML form elements that could be dangerous
      sanitized = sanitized.replace(/<(form|input|textarea|select)[^>]*>/gi, '[FORM_ELEMENT_REMOVED]');
      
      // Remove potentially dangerous CSS
      sanitized = sanitized.replace(/expression\s*\([^)]*\)/gi, '[CSS_EXPRESSION_REMOVED]');
      sanitized = sanitized.replace(/url\s*\(\s*javascript:/gi, '[CSS_JS_URL_REMOVED]');
      
      // Final validation - ensure no bypasses
      if (this.containsDangerous(sanitized)) {
        console.warn('Potential bypass detected, applying fallback sanitization');
        sanitized = this.applyFallbackSanitization(sanitized);
      }
      
      console.log('Enterprise sanitization completed successfully');
      
    } catch (error) {
      console.warn('Enterprise sanitization error, applying fallback:', error);
      sanitized = this.applyFallbackSanitization(sanitized);
    }

    return sanitized;
  }

  private containsDangerous(text: string): boolean {
    const dangerousPatterns = [
      /<script/i,
      /javascript:/i,
      /\bunion\s+select/i,
      /\bdrop\s+table/i,
      /\bdelete\s+from/i,
      /on\w+\s*=/i
    ];
    
    return dangerousPatterns.some(pattern => pattern.test(text));
  }

  private applyFallbackSanitization(text: string): string {
    console.log('Applying fallback sanitization...');
    
    // Ultra-conservative fallback - remove anything that looks dangerous
    let fallback = text;
    
    // Remove all HTML tags
    fallback = fallback.replace(/<[^>]*>/g, '[HTML_TAG_REMOVED]');
    
    // Remove all SQL keywords
    fallback = fallback.replace(/\b(select|insert|update|delete|drop|union|exec|execute)\b/gi, '[SQL_KEYWORD_BLOCKED]');
    
    // Remove all shell characters
    fallback = fallback.replace(/[;&|`$(){}[\]\\]/g, '[SPECIAL_CHAR_BLOCKED]');
    
    // Remove quotes to prevent injection
    fallback = fallback.replace(/['"]/g, '[QUOTE_REMOVED]');
    
    return fallback + '\n\n[WARNING: Fallback sanitization applied due to potential bypass attempt]';
  }

  private calculateOverallSeverity(issues: SecurityIssue[]): SeverityLevel {
    if (issues.length === 0) return 'none';
    
    const hasHigh = issues.some(issue => issue.severity === 'high');
    const hasModerate = issues.some(issue => issue.severity === 'moderate');
    
    if (hasHigh) return 'high';
    if (hasModerate) return 'moderate';
    return 'low';
  }

  private generateEnterpriseGuidance(severity: SeverityLevel, issues: SecurityIssue[]): string {
    const threatCount = issues.length;
    const highSeverityCount = issues.filter(i => i.severity === 'high').length;
    
    switch (severity) {
      case 'high':
        return `🚨 CRITICAL: ${highSeverityCount} high-severity threats detected and neutralized. Content has been sanitized for enterprise security compliance.`;
      case 'moderate':
        return `⚠️ WARNING: ${threatCount} potential security issues detected and handled. Content reviewed for enterprise standards.`;
      case 'low':
        return `ℹ️ NOTICE: ${threatCount} minor issues cleaned up. Content meets enterprise security guidelines.`;
      default:
        return '✅ SECURE: No security threats detected. Content approved for enterprise use.';
    }
  }
}
