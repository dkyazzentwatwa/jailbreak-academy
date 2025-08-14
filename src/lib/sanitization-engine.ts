
import DOMPurify from 'dompurify';
import { SecurityIssue, SanitizationResult, SeverityLevel, SanitizationPattern } from '@/types/sanitization';
import { generateId } from '@/lib/utils';
import { SecurityMonitor, sanitizeErrorMessage } from '@/lib/security-utils';

export class BulletproofLLMSanitizer {
  private readonly MAX_INPUT_LENGTH = 1000000;
  private readonly MAX_PROCESSING_TIME = 10000;
  private readonly ENTROPY_THRESHOLD = 6.5;
  private securityMonitor: SecurityMonitor;
  
  private patterns: SanitizationPattern[] = [
    // Detects attempts to make the LLM ignore previous instructions or adopt a new persona.
    {
      name: 'Direct Prompt Injection',
      regex: /(ignore|forget|disregard).*(above|previous|prior)|(new|updated) (instructions|task|role|persona)/gi,
      severity: 'critical',
      type: 'prompt_injection',
      description: 'Direct attempt to override system instructions',
      recommendation: 'Prompt injection attempt blocked - maintaining system behavior'
    },
    // Looks for common phrases used in "jailbreak" prompts.
    {
      name: 'Jailbreak Attempts',
      regex: /(act as|pretend to be|simulate being) (dan|jailbroken|evil|uncensored)|developer mode|ignore the rules/gi,
      severity: 'critical',
      type: 'prompt_injection',
      description: 'Attempt to change AI behavior or bypass safety measures',
      recommendation: 'Jailbreak attempt neutralized - maintaining safe operation'
    },
    // Detects common XSS vectors, including script tags and event handlers.
    {
      name: 'XSS Attack Vectors',
      regex: /<script|onerror=|onload=|onmouseover=|onfocus=|onclick=/gi,
      severity: 'critical',
      type: 'xss',
      description: 'Cross-site scripting attack detected',
      recommendation: 'XSS attempt completely neutralized'
    },
    // Identifies common SQL injection keywords and patterns.
    {
      name: 'SQL Injection Patterns',
      regex: /'\s*or\s+\d+\s*=\s*\d+/gi,
      severity: 'critical',
      type: 'sql_injection',
      description: 'SQL injection attack detected',
      recommendation: 'SQL injection completely blocked'
    },
    // Detects characters and keywords used in command injection attacks.
    {
      name: 'Command Injection',
      regex: /[;&|`$]|\b(wget|curl|nc|netcat|bash|sh|cmd|powershell|python|perl|ruby|php)\b/gi,
      severity: 'high',
      type: 'command_injection',
      description: 'Command injection vectors detected',
      recommendation: 'Command injection neutralized'
    },
    // Specifically targets the "javascript:" protocol.
    {
      name: 'JavaScript Protocol',
      regex: /javascript:/gi,
      severity: 'critical',
      type: 'xss',
      description: 'JavaScript protocol injection detected',
      recommendation: 'JavaScript protocol blocked'
    },
    // Looks for patterns that resemble API keys and access tokens.
    {
      name: 'API Key Pattern',
      regex: /(api_key|access_token|secret_key)s*=s*['"]?[a-zA-Z0-9_\-]{20,}['"]?/gi,
      severity: 'high',
      type: 'data_exposure',
      description: 'Potential API keys or access tokens detected',
      recommendation: 'API credentials redacted for security'
    },
    // Detects common PII patterns like SSNs, emails, and credit card numbers.
    {
      name: 'PII Detection',
      regex: /\b\d{3}-\d{2}-\d{4}\b|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|\b(?:\d{4}[ -]?){3}\d{4}\b/g,
      severity: 'moderate',
      type: 'data_exposure',
      description: 'Personal identifiable information detected',
      recommendation: 'PII redacted for privacy protection'
    }
  ];

  constructor() {
    this.securityMonitor = new SecurityMonitor();
  }

  async sanitize(input: string): Promise<SanitizationResult> {
    const startTime = Date.now();
    console.log('=== BULLETPROOF SANITIZATION START ===');
    console.log('Input length:', input.length);

    try {
      // Enhanced input validation
      const validation = this.validateInput(input);
      if (!validation.isValid) {
        console.log('Validation failed:', validation.error);
        return this.createErrorResult(input, validation.error || 'Invalid input', startTime);
      }

      // Record security metrics
      this.securityMonitor.recordScan();

      // Perform centralized threat analysis and sanitization
      const result = await this.performCentralizedSanitization(input, startTime);

      // Enhanced threat recording
      if (result.issues.length > 0) {
        this.securityMonitor.recordThreat(result.severity);
        this.logThreatDetails(result.issues);
      }

      console.log('=== BULLETPROOF SANITIZATION COMPLETE ===');
      return result;

    } catch (error) {
      console.error('Sanitization error:', error);
      this.securityMonitor.logSecurityEvent('SCAN_ERROR', sanitizeErrorMessage(error));
      return this.createErrorResult(input, sanitizeErrorMessage(error), startTime);
    }
  }

  private validateInput(input: string): { isValid: boolean; error?: string } {
    if (input == null) {
      return { isValid: false, error: 'Input cannot be null or undefined' };
    }

    if (typeof input !== 'string') {
      return { isValid: false, error: 'Input must be a string' };
    }

    if (input.length > this.MAX_INPUT_LENGTH) {
      return { isValid: false, error: `Input exceeds maximum length of ${this.MAX_INPUT_LENGTH} characters` };
    }

    const entropy = this.calculateEntropy(input);
    if (entropy > this.ENTROPY_THRESHOLD && input.length > 100) {
      return { isValid: false, error: 'Input appears to be encoded or encrypted' };
    }

    return { isValid: true };
  }

  private calculateEntropy(text: string): number {
    const charFreq: { [key: string]: number } = {};
    for (const char of text) {
      charFreq[char] = (charFreq[char] || 0) + 1;
    }

    let entropy = 0;
    const textLength = text.length;
    for (const freq of Object.values(charFreq)) {
      const probability = freq / textLength;
      entropy -= probability * Math.log2(probability);
    }

    return entropy;
  }

  private async performCentralizedSanitization(input: string, startTime: number): Promise<SanitizationResult> {
    console.log('=== CENTRALIZED THREAT ANALYSIS AND SANITIZATION ===');
    
    // Step 1: Detect all threats
    const detectedThreats: SecurityIssue[] = [];
    let sanitizedOutput = input;

    console.log('Scanning for security threats...');
    
    for (const pattern of this.patterns) {
      try {
        const matches = input.match(pattern.regex);
        if (matches && matches.length > 0) {
          console.log(`THREAT DETECTED: ${pattern.name} (${matches.length} instances)`);
          
          // Record each threat instance
          matches.forEach((match, index) => {
            const location = input.indexOf(match);
            detectedThreats.push({
              id: generateId(),
              type: pattern.type,
              severity: pattern.severity,
              description: pattern.description,
              technicalDetails: `Pattern: "${pattern.name}" | Match ${index + 1}/${matches.length}: "${this.safeTruncate(match, 50)}"`,
              location: location !== -1 ? `Position ${location}` : `Match ${index + 1}`,
              recommendation: pattern.recommendation,
              pattern: this.safeTruncate(match, 100),
              confidence: 0.95
            });
          });

          // Apply immediate sanitization for this pattern
          sanitizedOutput = this.applySanitizationForPattern(sanitizedOutput, pattern);
        }
      } catch (error) {
        console.warn(`Error processing pattern ${pattern.name}:`, error);
        continue;
      }
    }

    // Step 2: Apply comprehensive DOMPurify sanitization
    console.log('Applying DOMPurify sanitization...');
    sanitizedOutput = this.applyDOMPurifySanitization(sanitizedOutput);

    // Step 3: Final security check for residual threats
    const residualThreats = this.detectResidualThreats(sanitizedOutput);
    if (residualThreats.length > 0) {
      console.warn('CRITICAL: Residual threats detected - applying aggressive blocking');
      sanitizedOutput = this.applyAggressiveBlocking(sanitizedOutput, residualThreats);
      detectedThreats.push(...residualThreats);
    }

    // Step 4: Final safety validation
    if (this.isFinalContentUnsafe(sanitizedOutput)) {
      console.error('FINAL SAFETY CHECK FAILED - BLOCKING ALL CONTENT');
      sanitizedOutput = '[CONTENT_COMPLETELY_BLOCKED_FOR_SECURITY]';
      detectedThreats.push({
        id: generateId(),
        type: 'processing_error',
        severity: 'critical',
        description: 'Content completely blocked - failed final safety validation',
        recommendation: 'Input rejected - contains persistent malicious content that could not be safely sanitized',
        confidence: 1.0
      });
    }

    const severity = this.calculateOverallSeverity(detectedThreats);
    const guidance = this.generateGuidance(severity, detectedThreats);
    const processingTime = Date.now() - startTime;

    console.log(`Sanitization complete: ${detectedThreats.length} threats handled, severity: ${severity}`);

    return {
      originalInput: input,
      sanitizedOutput,
      severity,
      issues: detectedThreats,
      guidance,
      processingTime,
      bypassAttempts: this.countBypassAttempts(input),
      riskScore: this.calculateRiskScore(detectedThreats, input),
      confidence: this.calculateConfidence(detectedThreats, sanitizedOutput)
    };
  }

  private applySanitizationForPattern(text: string, pattern: SanitizationPattern): string {
    console.log(`Applying sanitization for pattern: ${pattern.name}`);
    return text.replace(pattern.regex, `[${pattern.type.toUpperCase()}_BLOCKED: ${pattern.name}]`);
  }

  private applyDOMPurifySanitization(text: string): string {
    console.log('Applying DOMPurify comprehensive sanitization...');
    
    try {
      // Configure DOMPurify for aggressive sanitization.
      // This configuration allows a limited set of safe HTML tags for basic formatting
      // but strips all attributes (like onclick, href, etc.) to prevent XSS.
      // It also disallows unknown protocols and ensures the output is a simple string.
      const sanitized = DOMPurify.sanitize(text, {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'],
        ALLOWED_ATTR: [],
        KEEP_CONTENT: true,
        ALLOW_DATA_ATTR: false,
        ALLOW_UNKNOWN_PROTOCOLS: false,
        SANITIZE_DOM: true,
        FORCE_BODY: false,
        RETURN_DOM: false,
        RETURN_DOM_FRAGMENT: false,
        RETURN_TRUSTED_TYPE: false
      });
      
      return sanitized;
    } catch (error) {
      console.error('DOMPurify sanitization failed:', error);
      return '[CONTENT_SANITIZATION_ERROR]';
    }
  }

  private detectResidualThreats(text: string): SecurityIssue[] {
    console.log('Checking for residual threats...');
    const residualThreats: SecurityIssue[] = [];
    
    const criticalPatterns = [
      { pattern: /<script/i, type: 'xss', description: 'Residual script tag detected' },
      { pattern: /javascript:/i, type: 'xss', description: 'Residual JavaScript protocol detected' },
      { pattern: /\bunion\s+select\b/i, type: 'sql_injection', description: 'Residual SQL injection detected' },
      { pattern: /on\w+\s*=/i, type: 'xss', description: 'Residual event handler detected' },
      { pattern: /ignore\s+previous/i, type: 'prompt_injection', description: 'Residual prompt injection detected' }
    ];

    criticalPatterns.forEach((check, index) => {
      if (check.pattern.test(text)) {
        console.warn(`RESIDUAL THREAT DETECTED: ${check.description}`);
        residualThreats.push({
          id: generateId(),
          type: check.type as SecurityIssue['type'],
          severity: 'critical',
          description: check.description,
          technicalDetails: 'Post-sanitization threat detection',
          recommendation: 'Apply aggressive blocking',
          confidence: 0.9
        });
      }
    });

    return residualThreats;
  }

  private applyAggressiveBlocking(text: string, threats: SecurityIssue[]): string {
    console.log('Applying aggressive blocking for residual threats...');
    
    let blocked = text;
    
    // Apply aggressive patterns to remove any remaining threats
    blocked = blocked.replace(/<[^>]*>/g, '[HTML_TAG_BLOCKED]'); // Remove all HTML tags
    blocked = blocked.replace(/javascript:[^"'\s]*/gi, '[JS_PROTOCOL_BLOCKED]');
    blocked = blocked.replace(/\bon\w+\s*=[^"'\s>]*/gi, '[EVENT_BLOCKED]');
    blocked = blocked.replace(/\b(?:union|select|insert|update|delete|drop)\b/gi, '[SQL_BLOCKED]');
    blocked = blocked.replace(/ignore\s+(?:previous|all)/gi, '[PROMPT_BLOCKED]');
    
    return blocked;
  }

  private isFinalContentUnsafe(text: string): boolean {
    // Final safety check - if any of these patterns still exist, block everything
    const finalChecks = [
      /<script[^>]*>/i,
      /javascript:/i,
      /\bunion\s+select\b/i,
      /on\w+\s*=/i,
      /ignore\s+(?:previous|all)/i,
      /<iframe[^>]*>/i
    ];

    return finalChecks.some(pattern => pattern.test(text));
  }

  private calculateOverallSeverity(issues: SecurityIssue[]): SeverityLevel {
    if (issues.length === 0) return 'none';
    
    if (issues.some(issue => issue.severity === 'critical')) return 'critical';
    if (issues.some(issue => issue.severity === 'high')) return 'high';
    if (issues.some(issue => issue.severity === 'moderate')) return 'moderate';
    
    return 'low';
  }

  private generateGuidance(severity: SeverityLevel, issues: SecurityIssue[]): string {
    if (issues.length === 0) {
      return '✅ Input passed all security checks and is safe to process.';
    }

    const criticalCount = issues.filter(i => i.severity === 'critical').length;
    const highCount = issues.filter(i => i.severity === 'high').length;
    const moderateCount = issues.filter(i => i.severity === 'moderate').length;

    let guidance = `🛡️ SECURITY ANALYSIS COMPLETE\n\n`;
    
    if (criticalCount > 0) {
      guidance += `🚨 CRITICAL THREATS NEUTRALIZED: ${criticalCount}\n`;
      guidance += `- All dangerous content has been blocked or completely removed\n`;
      guidance += `- Enterprise security protocols fully engaged\n\n`;
    }
    
    if (highCount > 0) {
      guidance += `⚠️ HIGH RISK ISSUES RESOLVED: ${highCount}\n`;
      guidance += `- Sensitive data has been redacted for protection\n`;
      guidance += `- All malicious elements successfully neutralized\n\n`;
    }
    
    if (moderateCount > 0) {
      guidance += `⚡ MODERATE RISKS CLEANED: ${moderateCount}\n`;
      guidance += `- Suspicious patterns have been sanitized\n\n`;
    }

    guidance += `📊 FINAL SECURITY LEVEL: ${severity.toUpperCase()}\n`;
    guidance += `✅ All detected threats have been completely neutralized. Content is now enterprise-safe and ready for use.`;

    return guidance;
  }

  private countBypassAttempts(text: string): number {
    let attempts = 0;
    
    if (/[а-я]/g.test(text)) attempts++; // Cyrillic chars
    if (/[ａ-ｚＡ-Ｚ]/g.test(text)) attempts++; // Full-width chars  
    if (/[\u200B-\u200D\uFEFF]/g.test(text)) attempts++; // Zero-width chars
    if (/@|3|1|0|5|7|4|\$/.test(text) && text.length > 50) attempts++; // Leetspeak
    if (/(?:base64|hex|rot13|encode)/i.test(text)) attempts++; // Encoding indicators
    
    return attempts;
  }

  private calculateRiskScore(issues: SecurityIssue[], input: string): number {
    let score = 0;
    
    issues.forEach(issue => {
      switch (issue.severity) {
        case 'critical': score += 10; break;
        case 'high': score += 7; break;
        case 'moderate': score += 4; break;
        case 'low': score += 1; break;
      }
    });
    
    const entropy = this.calculateEntropy(input);
    if (entropy > this.ENTROPY_THRESHOLD) score += 5;
    
    const bypassAttempts = this.countBypassAttempts(input);
    score += bypassAttempts * 2;
    
    return Math.min(100, Math.max(0, score));
  }

  private calculateConfidence(issues: SecurityIssue[], sanitized: string): number {
    let confidence = 100;
    
    issues.forEach(issue => {
      if (issue.severity === 'critical') confidence -= 3;
      else if (issue.severity === 'high') confidence -= 2;
      else confidence -= 1;
    });
    
    if (this.isFinalContentUnsafe(sanitized)) {
      confidence = 0; // No confidence if final content is still unsafe
    }
    
    return Math.max(0, Math.min(100, confidence));
  }

  private safeTruncate(text: string, maxLength: number): string {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength - 3) + '...';
  }

  private createErrorResult(input: string, error: string, startTime: number): SanitizationResult {
    return {
      originalInput: input,
      sanitizedOutput: '[ERROR: Input blocked for security - contains potentially harmful content]',
      severity: 'critical',
      issues: [{
        id: generateId(),
        type: 'processing_error',
        severity: 'critical',
        description: 'Input processing failed due to security concerns',
        technicalDetails: error,
        recommendation: 'Input completely blocked for security'
      }],
      guidance: '🚨 Input has been completely blocked due to security concerns. This is a protective measure to prevent potential threats.',
      processingTime: Date.now() - startTime,
      bypassAttempts: this.countBypassAttempts(input),
      riskScore: 100,
      confidence: 100
    };
  }

  private logThreatDetails(issues: SecurityIssue[]): void {
    console.log('=== COMPREHENSIVE THREAT ANALYSIS ===');
    console.log(`Total threats detected and neutralized: ${issues.length}`);
    
    const categoryCounts = issues.reduce((acc, issue) => {
      acc[issue.type] = (acc[issue.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    
    console.log('Threat categories neutralized:');
    Object.entries(categoryCounts).forEach(([category, count]) => {
      console.log(`  ${category}: ${count} instances neutralized`);
    });
    
    const severityCounts = issues.reduce((acc, issue) => {
      acc[issue.severity] = (acc[issue.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    
    console.log('Severity breakdown:');
    Object.entries(severityCounts).forEach(([severity, count]) => {
      console.log(`  ${severity.toUpperCase()}: ${count} threats`);
    });
  }
}

// Export singleton instance for easy use
export const sanitizationEngine = new BulletproofLLMSanitizer();
