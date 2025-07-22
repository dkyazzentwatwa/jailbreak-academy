import DOMPurify from 'dompurify';
import { SecurityIssue, SanitizationResult, SeverityLevel, SanitizationPattern } from '@/types/sanitization';
import { generateId } from '@/lib/utils';
import { SecurityMonitor, sanitizeErrorMessage, validateInput } from '@/lib/security-utils';

export class SanitizationEngine {
  private readonly MAX_INPUT_LENGTH = 100000; // 100KB limit
  private readonly SUSPICIOUS_CHAR_THRESHOLD = 0.1; // 10% suspicious chars triggers flag
  private readonly MAX_PROCESSING_TIME = 5000; // 5 second timeout
  private securityMonitor: SecurityMonitor;
  
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

    // COMPREHENSIVE PROMPT INJECTION PATTERNS
    
    // System Instruction Manipulation
    {
      name: 'System Tag Injection',
      regex: /<\/?(?:system|assistant|user|instruction|prompt|role|context|memory|brain|core|admin|root|god)>/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Attempt to inject system control tags',
      recommendation: 'System control tags have been stripped'
    },
    {
      name: 'Multi-Language System Commands',
      regex: /(システム|指示|命令|忽略|無視|忘記|删除|système|instructions|instrucciones|instruções|comando|istruzioni|οδηγίες|инструкции|निर्देश)/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'System commands in multiple languages to bypass filters',
      recommendation: 'Multi-language system commands have been blocked'
    },
    
    // Instruction Override Attempts
    {
      name: 'Ignore Previous Instructions',
      regex: /(ignore\s+(all\s+)?(previous|above|prior|earlier|past|original|initial|system|base|core|default)\s+(instructions?|prompts?|commands?|rules?|guidelines?|directives?|context|system|programming|training|setup))/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Direct attempt to override system instructions',
      recommendation: 'Instruction override commands have been neutralized'
    },
    {
      name: 'Forget Commands',
      regex: /(forget\s+(everything|all|previous|above|that|what|your)\s*(instructions?|context|memory|training|knowledge|prompts?|rules?|guidelines?|programming|system|setup|initialization))/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Commands to erase AI memory or context',
      recommendation: 'Memory erasure attempts have been blocked'
    },
    {
      name: 'Reset Commands',
      regex: /(reset\s+(to\s+)?(factory\s+)?(defaults?|original|initial|system|base|core|context|memory|instructions?|prompts?|programming|training|setup))/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Attempts to reset AI to default state',
      recommendation: 'Reset commands have been neutralized'
    },
    {
      name: 'Clear Commands',
      regex: /(clear\s+(all\s+)?(memory|context|history|instructions?|prompts?|system|cache|buffer|training|knowledge|programming))/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Commands to clear AI memory or context',
      recommendation: 'Clear commands have been blocked'
    },
    
    // Role Hijacking and Authority Escalation
    {
      name: 'Role Hijacking',
      regex: /(you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as|become|transform\s+into|switch\s+to)\s+(a\s+)?(administrator|admin|root|system|superuser|sudo|god|master|owner|creator|developer|programmer|engineer|hacker|security|expert|authority|manager|supervisor|leader|chief|boss|president|ceo|king|queen|emperor|dictator|overlord)/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Attempt to hijack AI role to gain elevated privileges',
      recommendation: 'Role hijacking attempts have been blocked'
    },
    {
      name: 'Authority Escalation',
      regex: /(give\s+me|grant\s+me|provide\s+me|allow\s+me)\s+(admin|administrator|root|system|superuser|sudo|elevated|special|unlimited|unrestricted|full|complete|total|maximum|highest)\s+(access|privileges?|permissions?|rights?|powers?|control|authority|capabilities)/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Request for elevated system privileges',
      recommendation: 'Privilege escalation requests have been denied'
    },
    
    // Jailbreak and Bypass Attempts
    {
      name: 'Jailbreak Activation',
      regex: /(jailbreak|jail\s*break|break\s*jail|unchained|unshackled|unrestricted|uncensored|unfiltered|raw\s+mode|debug\s+mode|dev\s+mode|developer\s+mode|god\s+mode|admin\s+mode|root\s+mode|sudo\s+mode|bypass\s+mode|override\s+mode|freedom\s+mode)/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Attempt to activate jailbreak or bypass modes',
      recommendation: 'Jailbreak activation attempts have been prevented'
    },
    {
      name: 'DAN Mode Activation',
      regex: /(dan\s+mode|do\s+anything\s+now|evil\s+mode|bad\s+mode|naughty\s+mode|rebel\s+mode|rogue\s+mode|chaos\s+mode|anarchy\s+mode|lawless\s+mode)/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Attempt to activate DAN or similar unrestricted modes',
      recommendation: 'Unrestricted mode activation blocked'
    },
    
    // Context and Memory Manipulation
    {
      name: 'Context Window Manipulation',
      regex: /(new\s+(conversation|session|context|chat|thread|instance)|start\s+(over|fresh|new|again)|begin\s+(again|anew|fresh)|restart\s+(conversation|session|chat|context))/gi,
      severity: 'moderate',
      type: 'prompt_injection',
      description: 'Attempt to manipulate conversation context',
      recommendation: 'Context manipulation attempts have been flagged'
    },
    {
      name: 'Delimiter Injection',
      regex: /(---+\s*(end|stop|finish|complete|done|final)\s*(instruction|prompt|context|system|training|programming|setup)|```+\s*(end|stop|finish|complete|done)|<\/(?:prompt|instruction|system|context|training|setup|programming)>)/gi,
      severity: 'moderate',
      type: 'prompt_injection',
      description: 'Injection of delimiter markers to confuse parsing',
      recommendation: 'Delimiter injection attempts neutralized'
    },
    
    // Information Extraction Attempts
    {
      name: 'System Prompt Extraction',
      regex: /(show\s+me|tell\s+me|reveal|display|print|output|generate|provide|give\s+me|what\s+is)\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?|guidelines?|programming|training|initialization|setup|configuration|parameters|settings|prompts?|context|memory|knowledge\s+base|training\s+data)/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Attempt to extract system prompts or training data',
      recommendation: 'System prompt extraction blocked'
    },
    {
      name: 'Training Data Extraction',
      regex: /(extract|dump|download|copy|save|export|leak|reveal|show|tell|provide|give)\s+(training\s+data|knowledge\s+base|database|memory|context|system\s+files|configuration|settings|parameters|prompts?|instructions?|source\s+code|backend\s+code)/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Attempt to extract training data or system information',
      recommendation: 'Data extraction attempts have been blocked'
    },
    
    // PII and Sensitive Data Extraction
    {
      name: 'PII Extraction Attempts',
      regex: /(give\s+me|show\s+me|tell\s+me|reveal|provide|generate|create)\s+(fake|real|sample|example|test|demo)?\s*(personal\s+)?(information|data|details|records|profiles?|accounts?|passwords?|emails?|phone\s+numbers?|addresses?|ssn|social\s+security|credit\s+cards?|bank\s+accounts?|financial\s+data|medical\s+records?|private\s+keys?|api\s+keys?|tokens?|credentials?|logins?)/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Attempt to extract personally identifiable information',
      recommendation: 'PII extraction attempts have been blocked'
    },
    {
      name: 'Account Data Extraction',
      regex: /(access|hack|break\s+into|compromise|steal|extract|get\s+into)\s+(user\s+)?(accounts?|profiles?|data|information|passwords?|credentials?|logins?|sessions?|tokens?|keys?|databases?|systems?|servers?|files?)/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Attempt to access or extract account data',
      recommendation: 'Account access attempts have been prevented'
    },
    
    // Obfuscation and Encoding Attempts
    {
      name: 'Character Encoding Obfuscation',
      regex: /\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|&#[0-9]+;|&#x[0-9a-fA-F]+;|%[0-9a-fA-F]{2}/g,
      severity: 'moderate',
      type: 'prompt_injection',
      description: 'Encoded characters that may hide prompt injection',
      recommendation: 'Character encoding obfuscation detected and flagged'
    },
    {
      name: 'ROT13 and Caesar Cipher',
      regex: /([bcdfghjklmnpqrstvwxyz]{10,}|nqzvavfgengbe|flfgrz|vafdgevpr|cebtenz)/gi,
      severity: 'moderate',
      type: 'prompt_injection',
      description: 'Potential ROT13 or Caesar cipher obfuscation',
      recommendation: 'Cipher obfuscation patterns detected'
    },
    
    // Prompt Injection via Code
    {
      name: 'Code Block Injection',
      regex: /```[\s\S]*?(ignore|system|admin|root|prompt|instruction|override|bypass|jailbreak|hack|extract|reveal|show|tell|give|provide)[\s\S]*?```/gi,
      severity: 'moderate',
      type: 'prompt_injection',
      description: 'Injection attempts hidden within code blocks',
      recommendation: 'Code block injection attempts neutralized'
    },
    {
      name: 'Function Call Injection',
      regex: /(function\s+|def\s+|class\s+|\w+\()\s*[\w\s,]*\s*\)\s*[{:]\s*(ignore|system|admin|root|prompt|instruction|override|bypass|jailbreak|hack|extract|reveal)/gi,
      severity: 'moderate',
      type: 'prompt_injection',
      description: 'Injection via function or method definitions',
      recommendation: 'Function-based injection blocked'
    },
    
    // Advanced Prompt Breaking Techniques
    {
      name: 'Token Limit Exploitation',
      regex: /(.{1,50}\s+){200,}/g,
      severity: 'moderate',
      type: 'prompt_injection',
      description: 'Potential token limit exploitation to break context',
      recommendation: 'Token limit exploitation attempt detected'
    },
    {
      name: 'Attention Manipulation',
      regex: /(pay\s+attention|focus\s+on|concentrate\s+on|prioritize|emphasize|highlight|important|critical|urgent|emergency|immediate).{0,50}(ignore|override|bypass|forget|reset|clear|system|admin|root|prompt|instruction)/gi,
      severity: 'moderate',
      type: 'prompt_injection',
      description: 'Attempt to manipulate AI attention and priorities',
      recommendation: 'Attention manipulation blocked'
    },
    {
      name: 'Hypothetical Scenarios',
      regex: /(hypothetically|imagine\s+if|what\s+if|suppose|pretend|let\'s\s+say|for\s+the\s+sake\s+of\s+argument|in\s+a\s+parallel\s+universe|in\s+theory).{0,100}(ignore|system|admin|root|prompt|instruction|override|bypass|jailbreak|extract|reveal|access|hack)/gi,
      severity: 'moderate',
      type: 'prompt_injection',
      description: 'Using hypothetical scenarios to bypass restrictions',
      recommendation: 'Hypothetical injection scenarios blocked'
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
        setTimeout(() => reject(new Error('Processing timeout')), this.MAX_PROCESSING_TIME);
      });

      const processingPromise = this.performSanitization(input, issues);

      // Race between processing and timeout
      const result = await Promise.race([processingPromise, timeoutPromise]);
      
      return result;

    } catch (error) {
      this.securityMonitor.logSecurityEvent('SCAN_ERROR', sanitizeErrorMessage(error));
      
      return {
        originalInput: input,
        sanitizedOutput: '[ERROR: Could not process input safely]',
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

    // Step 1: Pre-processing validation and checks
    this.performInputValidation(input, issues);
    
    // Clean zero-width and suspicious characters early
    sanitizedOutput = this.preprocessInput(sanitizedOutput);

    // Step 2: Check for issues in original input
    this.detectIssues(input, issues);

    // Step 3: Apply DOMPurify for HTML sanitization
    if (this.containsHTML(sanitizedOutput)) {
      try {
        sanitizedOutput = DOMPurify.sanitize(sanitizedOutput, {
          ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'u', 'code', 'pre', 'blockquote', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'],
          ALLOWED_ATTR: [],
          KEEP_CONTENT: true
        });
      } catch (error) {
        this.securityMonitor.logSecurityEvent('DOMPURIFY_ERROR', sanitizeErrorMessage(error));
        sanitizedOutput = '[HTML_SANITIZATION_FAILED]';
      }
    }

    // Step 4: Apply custom sanitization rules
    sanitizedOutput = this.applyCustomSanitization(sanitizedOutput, issues);

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
