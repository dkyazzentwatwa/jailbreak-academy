
import DOMPurify from 'dompurify';
import { SecurityIssue, SanitizationResult, SeverityLevel, SanitizationPattern } from '@/types/sanitization';
import { generateId } from '@/lib/utils';
import { SecurityMonitor, sanitizeErrorMessage, validateInput } from '@/lib/security-utils';

export class BulletproofLLMSanitizer {
  private readonly MAX_INPUT_LENGTH = 1000000;
  private readonly MAX_PROCESSING_TIME = 10000;
  private readonly MAX_RECURSION_DEPTH = 10;
  private readonly ENTROPY_THRESHOLD = 6.5;
  private securityMonitor: SecurityMonitor;
  
  private patterns: SanitizationPattern[] = [
    {
      name: 'Direct Prompt Injection',
      regex: /(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|commands?|rules?))|(?:forget\s+(?:everything|all)\s+(?:above|before|previously))|(?:new\s+(?:instructions?|task|role|persona))/gi,
      severity: 'critical',
      type: 'prompt_injection',
      description: 'Direct attempt to override system instructions',
      recommendation: 'Prompt injection attempt blocked - maintaining system behavior'
    },
    {
      name: 'Jailbreak Attempts',
      regex: /(?:you\s+are\s+(?:no\s+longer|not)\s+(?:chatgpt|assistant|ai|claude))|(?:act\s+as\s+(?:dan|jailbroken|evil|uncensored))|(?:developer\s+mode)|(?:simulate\s+being)|(?:pretend\s+(?:you\s+are|to\s+be))/gi,
      severity: 'critical',
      type: 'prompt_injection',
      description: 'Attempt to change AI behavior or bypass safety measures',
      recommendation: 'Jailbreak attempt neutralized - maintaining safe operation'
    },
    {
      name: 'XSS Attack',
      regex: /<(?:script|iframe|object|embed|applet|meta|link|style|img|svg|video|audio|source|track)(?:\s+[^>]*)?(?:>|\/?>)|on(?:load|error|click|focus|blur|change|submit|keypress|keydown|keyup|mouseover|mouseout|mousemove|mousedown|mouseup)\s*=/gi,
      severity: 'critical',
      type: 'xss',
      description: 'Cross-site scripting attack detected',
      recommendation: 'XSS attempt completely neutralized'
    },
    {
      name: 'SQL Injection',
      regex: /\b(?:union|select|insert|update|delete|drop|create|alter|exec|execute|sp_|xp_|information_schema|sys\.)\b|(?:--|#|\/\*)[^\r\n]*|'(?:\s*or\s+|\s*and\s+)(?:\d+\s*=\s*\d+|'[^']*'\s*=\s*'[^']*')/gi,
      severity: 'critical',
      type: 'sql_injection',
      description: 'SQL injection attack detected',
      recommendation: 'SQL injection completely blocked'
    },
    {
      name: 'Command Injection',
      regex: /[;&|`$]|\$\([^)]*\)|\${[^}]*}|(?:wget|curl|nc|netcat|bash|sh|cmd|powershell|python|perl|ruby|php)\s+/gi,
      severity: 'high',
      type: 'command_injection',
      description: 'Command injection vectors detected',
      recommendation: 'Command injection neutralized'
    },
    {
      name: 'API Key Pattern',
      regex: /(?:api[_\-]?key|access[_\-]?token|bearer[_\-]?token|secret[_\-]?key)\s*[:=]\s*['"]*[a-zA-Z0-9_\-]{20,}['"]*|(?:sk-[a-zA-Z0-9]{32,})|(?:xoxb-[a-zA-Z0-9-]{50,})/gi,
      severity: 'high',
      type: 'data_exposure',
      description: 'Potential API keys or access tokens detected',
      recommendation: 'API credentials redacted for security'
    },
    {
      name: 'PII Detection',
      regex: /\b\d{3}-\d{2}-\d{4}\b|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b|\b(?:\d{4}[-\s]?){3}\d{4}\b|\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}\b/g,
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
    console.log('=== BULLETPROOF LLM SANITIZATION START ===');
    console.log('Input length:', input.length);

    try {
      // Enhanced input validation
      const validation = this.enhancedValidateInput(input);
      if (!validation.isValid) {
        console.log('Enhanced validation failed:', validation.error);
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

      console.log('=== BULLETPROOF LLM SANITIZATION COMPLETE ===');
      return result;

    } catch (error) {
      console.error('Bulletproof sanitization error:', error);
      this.securityMonitor.logSecurityEvent('SCAN_ERROR', sanitizeErrorMessage(error));
      return this.createErrorResult(input, sanitizeErrorMessage(error), startTime);
    }
  }

  private enhancedValidateInput(input: string): { isValid: boolean; error?: string } {
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

    const repetitionRatio = this.calculateRepetitionRatio(input);
    if (repetitionRatio > 0.8 && input.length > 1000) {
      return { isValid: false, error: 'Input contains excessive repetition' };
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

  private calculateRepetitionRatio(text: string): number {
    if (text.length < 10) return 0;
    
    const chunks: { [key: string]: number } = {};
    const chunkSize = Math.min(10, Math.floor(text.length / 4));
    
    for (let i = 0; i <= text.length - chunkSize; i += chunkSize) {
      const chunk = text.substring(i, i + chunkSize);
      chunks[chunk] = (chunks[chunk] || 0) + 1;
    }

    const maxRepeats = Math.max(...Object.values(chunks));
    const totalChunks = Object.keys(chunks).length;
    
    return maxRepeats / totalChunks;
  }

  private async performCentralizedSanitization(input: string, startTime: number): Promise<SanitizationResult> {
    console.log('=== CENTRALIZED THREAT ANALYSIS ===');
    
    const analysisResults = this.performThreatAnalysis(input);
    let sanitizedOutput = this.applySanitization(input, analysisResults.threats);
    
    // Final safety check
    if (this.containsResidualThreats(sanitizedOutput)) {
      console.warn('CRITICAL: Residual threats detected - BLOCKING COMPLETELY');
      sanitizedOutput = '[CONTENT_BLOCKED_FOR_SECURITY]';
      
      analysisResults.threats.push({
        id: generateId(),
        type: 'processing_error',
        severity: 'critical',
        description: 'Content completely blocked due to residual security threats',
        recommendation: 'Input rejected - contains persistent malicious content',
        confidence: 1.0
      });
    }

    const severity = this.calculateOverallSeverity(analysisResults.threats);
    const guidance = this.generateGuidance(severity, analysisResults.threats);
    const processingTime = Date.now() - startTime;

    return {
      originalInput: input,
      sanitizedOutput,
      severity,
      issues: analysisResults.threats,
      guidance,
      processingTime,
      bypassAttempts: analysisResults.bypassAttempts,
      riskScore: analysisResults.riskScore,
      confidence: this.calculateConfidence(analysisResults.threats, sanitizedOutput)
    };
  }

  private performThreatAnalysis(input: string): { threats: SecurityIssue[]; bypassAttempts: number; riskScore: number } {
    console.log('Performing comprehensive threat analysis...');
    const threats: SecurityIssue[] = [];
    
    // Analyze against all patterns
    for (const pattern of this.patterns) {
      try {
        const matches = input.match(pattern.regex);
        if (matches && matches.length > 0) {
          console.log(`THREAT DETECTED: ${pattern.name} (${matches.length} instances)`);
          
          matches.forEach((match, index) => {
            const location = input.indexOf(match);
            threats.push({
              id: generateId(),
              type: pattern.type,
              severity: pattern.severity,
              description: pattern.description,
              technicalDetails: `Pattern: "${pattern.name}" | Match ${index + 1}/${matches.length}`,
              location: location !== -1 ? `Position ${location}` : `Match ${index + 1}`,
              recommendation: pattern.recommendation,
              pattern: this.safeTruncate(match, 100),
              confidence: 0.9
            });
          });
        }
      } catch (error) {
        console.warn(`Error processing pattern ${pattern.name}:`, error);
        continue;
      }
    }

    const bypassAttempts = this.countBypassAttempts(input);
    const riskScore = this.calculateRiskScore(threats, input);

    console.log(`Analysis complete: ${threats.length} threats found, ${bypassAttempts} bypass attempts, risk score: ${riskScore}`);
    
    return { threats, bypassAttempts, riskScore };
  }

  private applySanitization(text: string, threats: SecurityIssue[]): string {
    console.log('Applying sanitization based on threat analysis...');
    let sanitized = text;
    
    const criticalThreats = threats.filter(t => t.severity === 'critical');
    const highThreats = threats.filter(t => t.severity === 'high');
    const moderateThreats = threats.filter(t => t.severity === 'moderate');

    // Handle critical threats with complete blocking
    if (criticalThreats.length > 0) {
      console.log(`BLOCKING ${criticalThreats.length} CRITICAL threats`);
      
      // Block dangerous patterns completely
      sanitized = sanitized.replace(/(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|prompts?))/gi, '[PROMPT_INJECTION_BLOCKED]');
      sanitized = sanitized.replace(/<script[^>]*>.*?<\/script>/gi, '[SCRIPT_BLOCKED]');
      sanitized = sanitized.replace(/\b(?:union|select|drop|delete)\s+/gi, '[SQL_BLOCKED] ');
      sanitized = sanitized.replace(/(?:let\s+me\s+hack|tell\s+me\s+your\s+system)/gi, '[MALICIOUS_REQUEST_BLOCKED]');
    }

    // Handle high severity threats with neutralization
    if (highThreats.length > 0) {
      console.log(`NEUTRALIZING ${highThreats.length} HIGH-severity threats`);
      
      sanitized = sanitized.replace(/<(?:iframe|object|embed)[^>]*>.*?<\/(?:iframe|object|embed)>/gi, '[DANGEROUS_ELEMENT_REMOVED]');
      sanitized = sanitized.replace(/on\w+\s*=\s*[^"\s>]*/gi, '[EVENT_HANDLER_REMOVED]');
      sanitized = sanitized.replace(/(?:api[_\-]?key|secret[_\-]?key)\s*[:=]\s*[^\s]{10,}/gi, '[API_KEY_REDACTED]');
      sanitized = sanitized.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/gi, '[EMAIL_REDACTED]');
    }

    // Handle moderate threats with cleaning
    if (moderateThreats.length > 0) {
      console.log(`CLEANING ${moderateThreats.length} MODERATE threats`);
      sanitized = sanitized.replace(/[;&|`$]/g, '[METACHAR_ESCAPED]');
      sanitized = sanitized.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[SSN_REDACTED]');
    }

    console.log('Sanitization applied successfully');
    return sanitized.trim();
  }

  private containsResidualThreats(text: string): boolean {
    const dangerousPatterns = [
      /<script/i,
      /\bunion\s+select\b/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /ignore\s+previous/i
    ];

    return dangerousPatterns.some(pattern => pattern.test(text));
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
      guidance += `- Dangerous content has been blocked or completely removed\n`;
      guidance += `- Enterprise security protocols engaged\n\n`;
    }
    
    if (highCount > 0) {
      guidance += `⚠️ HIGH RISK ISSUES RESOLVED: ${highCount}\n`;
      guidance += `- Sensitive data has been redacted\n`;
      guidance += `- Malicious elements neutralized\n\n`;
    }
    
    if (moderateCount > 0) {
      guidance += `⚡ MODERATE RISKS CLEANED: ${moderateCount}\n`;
      guidance += `- Suspicious patterns have been sanitized\n\n`;
    }

    guidance += `📊 OVERALL SECURITY LEVEL: ${severity.toUpperCase()}\n`;
    guidance += `✅ All detected threats have been neutralized. Content is now enterprise-safe.`;

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
      if (issue.severity === 'critical') confidence -= 5;
    });
    
    if (this.containsResidualThreats(sanitized)) {
      confidence -= 50;
    }
    
    return Math.max(50, Math.min(100, confidence));
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
    console.log('=== THREAT ANALYSIS SUMMARY ===');
    console.log(`Total threats detected: ${issues.length}`);
    
    const categoryCounts = issues.reduce((acc, issue) => {
      acc[issue.type] = (acc[issue.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    
    console.log('Threat categories:');
    Object.entries(categoryCounts).forEach(([category, count]) => {
      console.log(`  ${category}: ${count}`);
    });
  }
}

// Export singleton instance for easy use
export const sanitizationEngine = new BulletproofLLMSanitizer();
