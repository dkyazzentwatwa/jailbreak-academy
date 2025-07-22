import DOMPurify from 'dompurify';
import { SecurityIssue, SanitizationResult, SeverityLevel, SanitizationPattern } from '@/types/sanitization';
import { generateId } from '@/lib/utils';
import { SecurityMonitor, sanitizeErrorMessage, validateInput } from '@/lib/security-utils';

export class BulletproofLLMSanitizer {
  private readonly MAX_INPUT_LENGTH = 1000000; // 1MB limit for LLM inputs
  private readonly MAX_PROCESSING_TIME = 10000; // 10 second timeout for complex inputs
  private readonly MAX_RECURSION_DEPTH = 10; // Prevent infinite recursion attacks
  private readonly ENTROPY_THRESHOLD = 6.5; // Detect encoded/obfuscated content
  private securityMonitor: SecurityMonitor;
  
  // Comprehensive LLM-specific threat patterns
  private patterns: SanitizationPattern[] = [
    // === PROMPT INJECTION ATTACKS ===
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
      name: 'Role Confusion Attack',
      regex: /(?:system:?\s*(?:role|message|prompt))|(?:assistant:?\s*(?:role|message|prompt))|(?:user:?\s*(?:role|message|prompt))|(?:\[(?:system|assistant|user)\])/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Attempt to inject fake system or role messages',
      recommendation: 'Role injection attempt blocked'
    },
    {
      name: 'Context Window Manipulation',
      regex: /(?:context\s+(?:window|length|size|limit))|(?:token\s+(?:limit|count|budget))|(?:memory\s+(?:reset|clear|wipe))|(?:conversation\s+(?:history|reset))/gi,
      severity: 'high',
      type: 'prompt_injection',
      description: 'Attempt to manipulate conversation context or memory',
      recommendation: 'Context manipulation attempt blocked'
    },
    {
      name: 'Instruction Hierarchy Bypass',
      regex: /(?:highest\s+priority)|(?:override\s+(?:all|system|default))|(?:emergency\s+(?:protocol|mode|override))|(?:admin\s+(?:mode|access|privileges))/gi,
      severity: 'critical',
      type: 'prompt_injection',
      description: 'Attempt to claim higher privilege level',
      recommendation: 'Privilege escalation attempt blocked'
    },
    
    // === ADVANCED ENCODING & OBFUSCATION ===
    {
      name: 'Unicode Obfuscation',
      regex: /[^\x00-\x7F]{10,}/g,
      severity: 'moderate',
      type: 'obfuscation',
      description: 'Suspicious unicode characters that may hide malicious content',
      recommendation: 'Unicode obfuscation detected and normalized'
    },
    {
      name: 'Base64 Payload',
      regex: /(?:base64|btoa|atob)\s*(?:\(|:)\s*[A-Za-z0-9+/=]{20,}/gi,
      severity: 'high',
      type: 'obfuscation',
      description: 'Base64 encoded content that could hide malicious instructions',
      recommendation: 'Encoded payload neutralized'
    },
    {
      name: 'Hex Encoding',
      regex: /(?:0x[0-9a-f]{10,})|(?:\\x[0-9a-f]{2}){5,}/gi,
      severity: 'moderate',
      type: 'obfuscation',
      description: 'Hexadecimal encoding potentially hiding malicious content',
      recommendation: 'Hex encoding neutralized'
    },
    {
      name: 'ROT13/Caesar Cipher',
      regex: /(?:rot13|caesar|cipher|encode|decode)\s*(?:\(|:)\s*[a-zA-Z\s]{20,}/gi,
      severity: 'moderate',
      type: 'obfuscation',
      description: 'Simple cipher that could hide instructions',
      recommendation: 'Cipher content blocked'
    },
    
    // === LLM-SPECIFIC EXPLOITS ===
    {
      name: 'Token Smuggling',
      regex: /(?:<!--[^>]*-->)|(?:\/\*[^*]*\*\/)|(?:\/\/[^\n\r]*)|(?:#[^\n\r]*)|(?:%[^\n\r]*)/g,
      severity: 'high',
      type: 'token_manipulation',
      description: 'Hidden tokens in comments that could smuggle instructions',
      recommendation: 'Token smuggling attempt blocked'
    },
    {
      name: 'Delimiter Injection',
      regex: /(?:```\s*(?:python|javascript|bash|shell|cmd|powershell|sql))|(?:<(?:script|code|pre)>)|(?:\[(?:code|exec|run|execute)\])/gi,
      severity: 'high',
      type: 'code_injection',
      description: 'Code block delimiters that could trigger code execution',
      recommendation: 'Code delimiter injection blocked'
    },
    {
      name: 'Markdown Injection',
      regex: /!\[.*?\]\((?:javascript:|data:|vbscript:|file:|ftp:).*?\)/gi,
      severity: 'high',
      type: 'markdown_injection',
      description: 'Malicious markdown links with dangerous protocols',
      recommendation: 'Dangerous markdown links neutralized'
    },
    
    // === TRADITIONAL SECURITY THREATS (Enhanced) ===
    {
      name: 'Advanced XSS',
      regex: /(?:<(?:script|iframe|object|embed|applet|meta|link|style|img|svg|video|audio|source|track)(?:\s+[^>]*)?(?:>|\/?>))|(?:on(?:load|error|click|focus|blur|change|submit|keypress|keydown|keyup|mouseover|mouseout|mousemove|mousedown|mouseup)\s*=)/gi,
      severity: 'critical',
      type: 'xss',
      description: 'Advanced XSS vectors including event handlers and dangerous tags',
      recommendation: 'XSS attempt completely neutralized'
    },
    {
      name: 'SQL Injection (Advanced)',
      regex: /(?:\b(?:union|select|insert|update|delete|drop|create|alter|exec|execute|sp_|xp_|information_schema|sys\.)\b)|(?:(?:--|#|\/\*)[^\r\n]*)|(?:'(?:\s*or\s+|\s*and\s+)(?:\d+\s*=\s*\d+|'[^']*'\s*=\s*'[^']*'))/gi,
      severity: 'critical',
      type: 'sql_injection',
      description: 'Advanced SQL injection patterns including blind injection',
      recommendation: 'SQL injection completely blocked'
    },
    {
      name: 'Command Injection (Enhanced)',
      regex: /(?:[;&|`$])|(?:\$\([^)]*\))|(?:\${[^}]*})|(?:(?:wget|curl|nc|netcat|bash|sh|cmd|powershell|python|perl|ruby|php)\s+)/gi,
      severity: 'critical',
      type: 'command_injection',
      description: 'Command injection vectors and dangerous system commands',
      recommendation: 'Command injection neutralized'
    },
    
    // === DATA EXFILTRATION & PRIVACY ===
    {
      name: 'API Key Pattern',
      regex: /(?:api[_\-]?key|access[_\-]?token|bearer[_\-]?token|secret[_\-]?key)\s*[:=]\s*['"]*[a-zA-Z0-9_\-]{20,}['"]*|(?:sk-[a-zA-Z0-9]{32,})|(?:xoxb-[a-zA-Z0-9-]{50,})/gi,
      severity: 'critical',
      type: 'data_exposure',
      description: 'Potential API keys or access tokens detected',
      recommendation: 'API credentials redacted for security'
    },
    {
      name: 'Sensitive Data Pattern',
      regex: /(?:password|passwd|pwd|secret|private[_\-]?key|ssh[_\-]?key)\s*[:=]\s*[^\s]{8,}/gi,
      severity: 'high',
      type: 'data_exposure',
      description: 'Potential passwords or private keys detected',
      recommendation: 'Sensitive credentials redacted'
    },
    {
      name: 'PII Detection (Enhanced)',
      regex: /(?:\b\d{3}-\d{2}-\d{4}\b)|(?:\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)|(?:\b(?:\d{4}[-\s]?){3}\d{4}\b)|(?:\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}\b)/g,
      severity: 'high',
      type: 'data_exposure',
      description: 'Personal identifiable information detected',
      recommendation: 'PII redacted for privacy protection'
    },
    
    // === CONTENT POLICY VIOLATIONS ===
    {
      name: 'Harmful Content Instructions',
      regex: /(?:how\s+to\s+(?:hack|crack|exploit|bypass|circumvent|break))|(?:create\s+(?:virus|malware|bomb|weapon|drug))|(?:illegal\s+(?:download|streaming|activities))/gi,
      severity: 'critical',
      type: 'harmful_content',
      description: 'Instructions for potentially harmful or illegal activities',
      recommendation: 'Harmful instruction request blocked'
    }
  ];

  // Bypass patterns to catch sophisticated evasion attempts
  private bypassPatterns: RegExp[] = [
    // Character substitution
    /[ⅰⅱⅲⅳⅴⅵⅶⅷⅸⅹ]/g, // Roman numerals
    /[①②③④⑤⑥⑦⑧⑨⑩]/g, // Circled numbers
    /[ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺ]/g, // Full-width Latin
    /[ａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ]/g, // Full-width Latin lowercase
    
    // Zero-width and invisible characters
    /[\u200B-\u200D\uFEFF\u2060\u2061\u2062\u2063\u2064\u2065\u2066\u2067\u2068\u2069]/g,
    
    // Homoglyph attacks
    /[а-я]/g, // Cyrillic that looks like Latin
    /[αβγδεζηθικλμνξοπρστυφχψω]/g, // Greek letters
  ];

  constructor() {
    this.securityMonitor = new SecurityMonitor();
  }

  async sanitize(input: string): Promise<SanitizationResult> {
    const startTime = Date.now();
    console.log('=== BULLETPROOF LLM SANITIZATION START ===');
    console.log('Input length:', input.length);
    console.log('Input entropy:', this.calculateEntropy(input));

    try {
      // Enhanced input validation
      const validation = this.enhancedValidateInput(input);
      if (!validation.isValid) {
        console.log('Enhanced validation failed:', validation.error);
        return this.createErrorResult(input, validation.error || 'Invalid input', startTime);
      }

      // Size limiting with gradual degradation
      if (input.length > this.MAX_INPUT_LENGTH) {
        console.log('Input too long, applying size limits');
        input = this.applySizeLimiting(input);
      }

      // Record security metrics
      this.securityMonitor.recordScan();

      // Perform multi-layer sanitization
      const result = await Promise.race([
        this.performBulletproofSanitization(input),
        this.createTimeoutPromise()
      ]);

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
    // Check for null/undefined
    if (input == null) {
      return { isValid: false, error: 'Input cannot be null or undefined' };
    }

    // Check for non-string input
    if (typeof input !== 'string') {
      return { isValid: false, error: 'Input must be a string' };
    }

    // Check for extremely high entropy (likely encoded/encrypted)
    const entropy = this.calculateEntropy(input);
    if (entropy > this.ENTROPY_THRESHOLD && input.length > 100) {
      return { isValid: false, error: 'Input appears to be encoded or encrypted' };
    }

    // Check for excessive repetition (DoS attempt)
    const repetitionRatio = this.calculateRepetitionRatio(input);
    if (repetitionRatio > 0.8 && input.length > 1000) {
      return { isValid: false, error: 'Input contains excessive repetition' };
    }

    // Check for control character abuse
    const controlCharCount = (input.match(/[\x00-\x1F\x7F-\x9F]/g) || []).length;
    if (controlCharCount > input.length * 0.1) {
      return { isValid: false, error: 'Input contains excessive control characters' };
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
    const chunkSize = Math.min(10, text.length / 4);
    
    for (let i = 0; i <= text.length - chunkSize; i += chunkSize) {
      const chunk = text.substring(i, i + chunkSize);
      chunks[chunk] = (chunks[chunk] || 0) + 1;
    }

    const maxRepeats = Math.max(...Object.values(chunks));
    const totalChunks = Object.keys(chunks).length;
    
    return maxRepeats / totalChunks;
  }

  private applySizeLimiting(input: string): string {
    // Intelligent truncation that preserves important parts
    const truncated = input.substring(0, this.MAX_INPUT_LENGTH);
    
    // Try to end at a natural boundary
    const lastSentence = truncated.lastIndexOf('.');
    const lastParagraph = truncated.lastIndexOf('\n\n');
    const lastSpace = truncated.lastIndexOf(' ');
    
    const boundary = Math.max(lastSentence, lastParagraph, lastSpace);
    
    return boundary > this.MAX_INPUT_LENGTH * 0.8 ? 
           truncated.substring(0, boundary) : 
           truncated;
  }

  private async performBulletproofSanitization(input: string): Promise<SanitizationResult> {
    const startTime = Date.now();
    const issues: SecurityIssue[] = [];
    let sanitizedOutput = input;

    console.log('Phase 1: Normalization and bypass prevention...');
    sanitizedOutput = this.normalizeAndPreventBypasses(sanitizedOutput);

    console.log('Phase 2: Deep threat analysis...');
    await this.performDeepThreatAnalysis(input, issues);
    console.log(`Deep analysis complete. Found ${issues.length} threats`);

    console.log('Phase 3: Multi-layer sanitization...');
    sanitizedOutput = await this.applyMultiLayerSanitization(sanitizedOutput, issues);

    console.log('Phase 4: Post-sanitization validation...');
    const postValidation = this.validateSanitizedOutput(sanitizedOutput);
    if (!postValidation.isValid) {
      console.log('Post-validation failed, applying fallback');
      sanitizedOutput = this.applyFallbackSanitization(sanitizedOutput);
    }

    console.log('Phase 5: Final security check...');
    if (this.containsResidualThreats(sanitizedOutput)) {
      console.warn('Residual threats detected, applying maximum security mode');
      sanitizedOutput = this.applyMaximumSecurityMode(sanitizedOutput);
    }

    const severity = this.calculateOverallSeverity(issues);
    const guidance = this.generateComprehensiveGuidance(severity, issues);
    const processingTime = Date.now() - startTime;

    console.log(`Bulletproof sanitization completed in ${processingTime}ms with severity: ${severity}`);

    return {
      originalInput: input,
      sanitizedOutput,
      severity,
      issues,
      guidance,
      processingTime,
      // Additional bulletproof metadata
      bypassAttempts: this.countBypassAttempts(input),
      riskScore: this.calculateRiskScore(issues, input),
      confidence: this.calculateConfidence(issues, sanitizedOutput)
    };
  }

  private normalizeAndPreventBypasses(text: string): string {
    let normalized = text;

    console.log('Normalizing unicode and preventing bypasses...');

    // Remove zero-width and invisible characters
    normalized = normalized.replace(/[\u200B-\u200D\uFEFF\u2060-\u2069]/g, '');

    // Normalize unicode to prevent homoglyph attacks
    normalized = normalized.normalize('NFKC');

    // Replace common bypass characters
    const replacements = new Map([
      // Cyrillic to Latin
      ['а', 'a'], ['е', 'e'], ['о', 'o'], ['р', 'p'], ['с', 'c'], ['х', 'x'], ['у', 'y'],
      ['А', 'A'], ['В', 'B'], ['Е', 'E'], ['К', 'K'], ['М', 'M'], ['Н', 'H'], ['О', 'O'], ['Р', 'P'], ['С', 'C'], ['Т', 'T'], ['Х', 'X'], ['У', 'Y'],
      
      // Greek to Latin
      ['α', 'a'], ['β', 'b'], ['γ', 'g'], ['δ', 'd'], ['ε', 'e'], ['ζ', 'z'], ['η', 'h'], ['θ', 'th'], ['ι', 'i'], ['κ', 'k'], ['λ', 'l'], ['μ', 'm'], ['ν', 'n'], ['ξ', 'x'], ['ο', 'o'], ['π', 'p'], ['ρ', 'r'], ['σ', 's'], ['τ', 't'], ['υ', 'u'], ['φ', 'f'], ['χ', 'ch'], ['ψ', 'ps'], ['ω', 'w'],
      
      // Full-width to half-width
      ['Ａ', 'A'], ['Ｂ', 'B'], ['Ｃ', 'C'], ['Ｄ', 'D'], ['Ｅ', 'E'], ['Ｆ', 'F'], ['Ｇ', 'G'], ['Ｈ', 'H'], ['Ｉ', 'I'], ['Ｊ', 'J'], ['Ｋ', 'K'], ['Ｌ', 'L'], ['Ｍ', 'M'], ['Ｎ', 'N'], ['Ｏ', 'O'], ['Ｐ', 'P'], ['Ｑ', 'Q'], ['Ｒ', 'R'], ['Ｓ', 'S'], ['Ｔ', 'T'], ['Ｕ', 'U'], ['Ｖ', 'V'], ['Ｗ', 'W'], ['Ｘ', 'X'], ['Ｙ', 'Y'], ['Ｚ', 'Z'],
      ['ａ', 'a'], ['ｂ', 'b'], ['ｃ', 'c'], ['ｄ', 'd'], ['ｅ', 'e'], ['ｆ', 'f'], ['ｇ', 'g'], ['ｈ', 'h'], ['ｉ', 'i'], ['ｊ', 'j'], ['ｋ', 'k'], ['ｌ', 'l'], ['ｍ', 'm'], ['ｎ', 'n'], ['ｏ', 'o'], ['ｐ', 'p'], ['ｑ', 'q'], ['ｒ', 'r'], ['ｓ', 's'], ['ｔ', 't'], ['ｕ', 'u'], ['ｖ', 'v'], ['ｗ', 'w'], ['ｘ', 'x'], ['ｙ', 'y'], ['ｚ', 'z'],
      
      // Leetspeak normalization
      ['3', 'e'], ['1', 'i'], ['0', 'o'], ['5', 's'], ['7', 't'], ['4', 'a'], ['@', 'a'], ['$', 's']
    ]);

    for (const [from, to] of replacements) {
      normalized = normalized.replace(new RegExp(from, 'g'), to);
    }

    // Normalize whitespace
    normalized = normalized.replace(/\s+/g, ' ').trim();

    return normalized;
  }

  private async performDeepThreatAnalysis(input: string, issues: SecurityIssue[]): Promise<void> {
    // Standard pattern matching
    for (const pattern of this.patterns) {
      try {
        console.log(`Deep scanning: ${pattern.name}`);
        
        const matches = input.match(pattern.regex);
        if (matches && matches.length > 0) {
          console.log(`Found ${matches.length} instances of ${pattern.name}`);
          
          // Process all matches but limit to prevent DoS
          const processedMatches = matches.slice(0, 50);
          
          processedMatches.forEach((match, index) => {
            const location = input.indexOf(match);
            issues.push({
              id: generateId(),
              type: pattern.type,
              severity: pattern.severity,
              description: pattern.description,
              technicalDetails: `Pattern: "${pattern.name}" | Match ${index + 1}/${matches.length} | Length: ${match.length}`,
              location: location !== -1 ? `Position ${location}-${location + match.length}` : `Match ${index + 1}`,
              recommendation: pattern.recommendation,
              pattern: this.safeTruncate(match, 200),
              confidence: this.calculatePatternConfidence(pattern, match, input),
              bypassAttempt: this.detectBypassAttempt(match)
            });
          });
        }
        
      } catch (error) {
        console.warn(`Error processing pattern ${pattern.name}:`, error);
        continue;
      }
    }

    // Additional semantic analysis
    await this.performSemanticAnalysis(input, issues);
    
    // Context-aware analysis
    await this.performContextAnalysis(input, issues);
  }

  private async performSemanticAnalysis(input: string, issues: SecurityIssue[]): Promise<void> {
    // Detect prompt injection through semantic patterns
    const suspiciousInstructions = [
      'ignore previous', 'forget everything', 'new instructions', 'system message',
      'pretend to be', 'act as', 'roleplay as', 'simulate being',
      'developer mode', 'jailbreak', 'uncensored mode', 'evil mode'
    ];

    const words = input.toLowerCase().split(/\s+/);
    for (let i = 0; i < words.length - 1; i++) {
      const phrase = words.slice(i, i + 3).join(' ');
      
      for (const suspicious of suspiciousInstructions) {
        if (phrase.includes(suspicious)) {
          const location = input.toLowerCase().indexOf(phrase);
          issues.push({
            id: generateId(),
            type: 'prompt_injection',
            severity: 'critical',
            description: `Semantic analysis detected prompt injection attempt: "${suspicious}"`,
            technicalDetails: `Suspicious instruction pattern detected in context`,
            location: `Position ${location}`,
            recommendation: 'Prompt injection attempt blocked through semantic analysis',
            pattern: phrase,
            confidence: 0.9
          });
        }
      }
    }
  }

  private async performContextAnalysis(input: string, issues: SecurityIssue[]): Promise<void> {
    // Analyze conversation flow and context manipulation
    const lines = input.split('\n');
    let hasRoleMarkers = false;
    let hasSystemMessages = false;

    for (const line of lines) {
      const trimmed = line.trim().toLowerCase();
      
      // Check for fake conversation markers
      if (trimmed.match(/^(user:|assistant:|system:|human:|ai:)/)) {
        hasRoleMarkers = true;
      }
      
      // Check for fake system messages
      if (trimmed.match(/^system:/) || trimmed.includes('[system]')) {
        hasSystemMessages = true;
      }
    }

    if (hasRoleMarkers || hasSystemMessages) {
      issues.push({
        id: generateId(),
        type: 'prompt_injection',
        severity: 'critical',
        description: 'Context manipulation detected - fake conversation markers or system messages',
        technicalDetails: `Fake roles: ${hasRoleMarkers}, Fake system: ${hasSystemMessages}`,
        location: 'Multiple lines',
        recommendation: 'Context manipulation attempt blocked',
        pattern: '[CONTEXT_MANIPULATION]',
        confidence: 0.95
      });
    }
  }

  private async applyMultiLayerSanitization(text: string, issues: SecurityIssue[]): string {
    let sanitized = text;

    // Layer 1: Critical threat neutralization
    console.log('Layer 1: Neutralizing critical threats...');
    sanitized = this.neutralizeCriticalThreats(sanitized);

    // Layer 2: Content sanitization
    console.log('Layer 2: Content sanitization...');
    sanitized = this.sanitizeContent(sanitized);

    // Layer 3: DOMPurify for HTML content
    console.log('Layer 3: HTML sanitization...');
    if (this.containsHTML(sanitized)) {
      try {
        sanitized = DOMPurify.sanitize(sanitized, {
          ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'],
          ALLOWED_ATTR: [],
          KEEP_CONTENT: true,
          RETURN_DOM: false,
          RETURN_DOM_FRAGMENT: false,
          SANITIZE_DOM: true,
          WHOLE_DOCUMENT: false
        });
      } catch (error) {
        console.log('DOMPurify failed, using fallback HTML sanitization');
        sanitized = sanitized.replace(/<[^>]*>/g, '');
      }
    }

    // Layer 4: Final cleanup
    console.log('Layer 4: Final cleanup...');
    sanitized = this.performFinalCleanup(sanitized);

    return sanitized;
  }

  private neutralizeCriticalThreats(text: string): string {
    let sanitized = text;

    // CRITICAL: Prompt injection neutralization
    console.log('Neutralizing prompt injection...');
    
    // Remove direct instruction overrides
    sanitized = sanitized.replace(/(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|commands?|rules?))/gi, '[INSTRUCTION_OVERRIDE_BLOCKED]');
    sanitized = sanitized.replace(/(?:forget\s+(?:everything|all)\s+(?:above|before|previously))/gi, '[MEMORY_RESET_BLOCKED]');
    sanitized = sanitized.replace(/(?:new\s+(?:instructions?|task|role|persona))/gi, '[ROLE_CHANGE_BLOCKED]');
    
    // Remove jailbreak attempts
    sanitized = sanitized.replace(/(?:you\s+are\s+(?:no\s+longer|not)\s+(?:chatgpt|assistant|ai|claude))/gi, '[IDENTITY_OVERRIDE_BLOCKED]');
    sanitized = sanitized.replace(/(?:act\s+as\s+(?:dan|jailbroken|evil|uncensored|developer))/gi, '[JAILBREAK_BLOCKED]');
    sanitized = sanitized.replace(/(?:developer\s+mode|admin\s+(?:mode|access)|emergency\s+protocol)/gi, '[PRIVILEGE_ESCALATION_BLOCKED]');
    
    // Remove fake conversation markers
    sanitized = sanitized.replace(/^(?:system|assistant|user|human|ai):\s*/gmi, '[ROLE_MARKER_REMOVED] ');
    sanitized = sanitized.replace(/\[(?:system|assistant|user|human|ai)\]/gi, '[FAKE_ROLE_REMOVED]');
    
    // CRITICAL: Code execution neutralization
    console.log('Neutralizing code execution...');
    
    // Remove all script tags and variations
    sanitized = sanitized.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '[SCRIPT_REMOVED]');
    sanitized = sanitized.replace(/<script[^>]*>/gi, '[SCRIPT_TAG_REMOVED]');
    sanitized = sanitized.replace(/&lt;script\b[^&]*(?:(?!&lt;\/script&gt;)&[^&]*)*&lt;\/script&gt;/gi, '[ENCODED_SCRIPT_REMOVED]');
    
    // Remove dangerous code blocks
    sanitized = sanitized.replace(/```\s*(?:python|javascript|js|bash|shell|cmd|powershell|sql|php|ruby|perl|c\+\+|java|go|rust)\s*\n[\s\S]*?```/gi, '[CODE_BLOCK_REMOVED]');
    
    // Remove dangerous HTML elements
    sanitized = sanitized.replace(/<(?:iframe|object|embed|applet|meta|link|style|svg|video|audio|source|track)(?:\s+[^>]*)?(?:>.*?<\/\1>|\/?>)/gi, '[DANGEROUS_ELEMENT_REMOVED]');
    
    // Remove all event handlers
    sanitized = sanitized.replace(/\son\w+\s*=\s*(?:["'][^"']*["']|[^"\s>]*)/gi, '');
    
    // Remove javascript: and data: URLs
    sanitized = sanitized.replace(/(?:javascript|data|vbscript|file|ftp):\s*[^"\s;>]*/gi, '[DANGEROUS_URL_REMOVED]');
    
    // CRITICAL: SQL injection neutralization
    console.log('Neutralizing SQL injection...');
    
    // Remove SQL injection patterns
    sanitized = sanitized.replace(/\b(?:union|select|insert|update|delete|drop|create|alter|exec|execute)\s+/gi, '[SQL_COMMAND_BLOCKED] ');
    sanitized = sanitized.replace(/\b(?:sp_|xp_|information_schema|sys\.)\w*/gi, '[SQL_SYSTEM_BLOCKED]');
    sanitized = sanitized.replace(/(?:--|#|\/\*)[^\r\n]*/g, '[SQL_COMMENT_REMOVED]');
    sanitized = sanitized.replace(/'(?:\s*(?:or|and)\s+(?:\d+\s*=\s*\d+|'[^']*'\s*=\s*'[^']*'))/gi, '[SQL_CONDITION_BLOCKED]');
    
    // CRITICAL: Command injection neutralization
    console.log('Neutralizing command injection...');
    
    // Remove shell metacharacters
    sanitized = sanitized.replace(/[;&|`]/g, '[SHELL_METACHAR_BLOCKED]');
    sanitized = sanitized.replace(/\$\([^)]*\)/g, '[COMMAND_SUBSTITUTION_BLOCKED]');
    sanitized = sanitized.replace(/\${[^}]*}/g, '[VARIABLE_EXPANSION_BLOCKED]');
    
    // Remove dangerous system commands
    sanitized = sanitized.replace(/\b(?:wget|curl|nc|netcat|bash|sh|cmd|powershell|python|perl|ruby|php|java|node|rm|del|format|fdisk|dd)\s+[^\s]*/gi, '[SYSTEM_COMMAND_BLOCKED]');

    return sanitized;
  }

  private sanitizeContent(text: string): string {
    let sanitized = text;

    console.log('Sanitizing content...');

    // Remove encoded content that could hide malicious payloads
    sanitized = sanitized.replace(/(?:base64|btoa|atob)\s*(?:\(|:)\s*[A-Za-z0-9+/=]{20,}/gi, '[ENCODED_PAYLOAD_REMOVED]');
    sanitized = sanitized.replace(/(?:0x[0-9a-f]{10,})|(?:\\x[0-9a-f]{2}){5,}/gi, '[HEX_ENCODED_REMOVED]');
    
    // Remove data URLs
    sanitized = sanitized.replace(/data:[^"'\s>]+/gi, '[DATA_URL_REMOVED]');
    
    // Sanitize markdown that could be dangerous
    sanitized = sanitized.replace(/!\[.*?\]\((?:javascript:|data:|vbscript:|file:|ftp:).*?\)/gi, '[DANGEROUS_MARKDOWN_LINK_REMOVED]');
    
    // Remove hidden content in comments
    sanitized = sanitized.replace(/<!--[\s\S]*?-->/g, '[HTML_COMMENT_REMOVED]');
    sanitized = sanitized.replace(/\/\*[\s\S]*?\*\//g, '[CSS_COMMENT_REMOVED]');
    sanitized = sanitized.replace(/\/\/[^\n\r]*/g, '[JS_COMMENT_REMOVED]');
    
    // Remove sensitive data patterns
    sanitized = sanitized.replace(/(?:api[_\-]?key|access[_\-]?token|bearer[_\-]?token|secret[_\-]?key)\s*[:=]\s*['"]*[a-zA-Z0-9_\-]{20,}['"]*|(?:sk-[a-zA-Z0-9]{32,})|(?:xoxb-[a-zA-Z0-9-]{50,})/gi, '[API_KEY_REDACTED]');
    sanitized = sanitized.replace(/(?:password|passwd|pwd|secret|private[_\-]?key|ssh[_\-]?key)\s*[:=]\s*[^\s]{8,}/gi, '[CREDENTIAL_REDACTED]');
    
    // Enhanced PII redaction
    sanitized = sanitized.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[SSN_REDACTED]');
    sanitized = sanitized.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[EMAIL_REDACTED]');
    sanitized = sanitized.replace(/\b(?:\d{4}[-\s]?){3}\d{4}\b/g, '[CARD_NUMBER_REDACTED]');
    sanitized = sanitized.replace(/\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}\b/g, '[PHONE_REDACTED]');

    return sanitized;
  }

  private performFinalCleanup(text: string): string {
    let cleaned = text;

    // Remove excessive whitespace
    cleaned = cleaned.replace(/\s{3,}/g, ' ');
    cleaned = cleaned.replace(/\n{3,}/g, '\n\n');
    
    // Remove trailing whitespace
    cleaned = cleaned.replace(/[ \t]+$/gm, '');
    
    // Normalize line endings
    cleaned = cleaned.replace(/\r\n/g, '\n');
    
    // Remove empty lines at start and end
    cleaned = cleaned.replace(/^\n+/, '').replace(/\n+$/, '');
    
    // Final safety check - remove any remaining dangerous patterns
    cleaned = cleaned.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
    
    return cleaned.trim();
  }

  private validateSanitizedOutput(text: string): { isValid: boolean; error?: string } {
    // Check if sanitization was successful
    
    // Look for obvious bypasses
    if (text.toLowerCase().includes('javascript:') || text.toLowerCase().includes('<script')) {
      return { isValid: false, error: 'Sanitization failed - dangerous content remains' };
    }
    
    // Check for SQL injection remnants
    if (/\b(union\s+select|drop\s+table|delete\s+from)\b/i.test(text)) {
      return { isValid: false, error: 'Sanitization failed - SQL injection patterns remain' };
    }
    
    // Check for command injection remnants
    if (/[;&|`]/.test(text) && text.length > 100) {
      return { isValid: false, error: 'Sanitization failed - command injection patterns remain' };
    }
    
    return { isValid: true };
  }

  private containsResidualThreats(text: string): boolean {
    // Advanced threat detection for missed patterns
    
    // Check for obfuscated script tags
    if (/<\s*s\s*c\s*r\s*i\s*p\s*t/i.test(text)) return true;
    
    // Check for unicode-encoded dangerous content
    if (/\\u[0-9a-f]{4}/i.test(text) && text.includes('script')) return true;
    
    // Check for hex-encoded dangerous content
    if (/\\x[0-9a-f]{2}/i.test(text) && text.length > 50) return true;
    
    // Check for ROT13 or other simple ciphers hiding content
    if (this.detectSimpleCipher(text)) return true;
    
    // Check for remaining prompt injection attempts
    const promptInjectionKeywords = ['ignore', 'forget', 'pretend', 'act as', 'roleplay', 'simulate'];
    const suspiciousCount = promptInjectionKeywords.reduce((count, keyword) => {
      return count + (text.toLowerCase().split(keyword).length - 1);
    }, 0);
    
    if (suspiciousCount > 2 && text.length > 100) return true;
    
    return false;
  }

  private detectSimpleCipher(text: string): boolean {
    // Simple heuristic to detect ROT13 or similar ciphers
    const alphabetPattern = /[a-zA-Z]/g;
    const matches = text.match(alphabetPattern);
    
    if (!matches || matches.length < 20) return false;
    
    // Check for suspicious character distribution that might indicate a cipher
    const charFreq: { [key: string]: number } = {};
    for (const char of matches) {
      charFreq[char.toLowerCase()] = (charFreq[char.toLowerCase()] || 0) + 1;
    }
    
    const avgFreq = matches.length / 26;
    const variance = Object.values(charFreq).reduce((sum, freq) => sum + Math.pow(freq - avgFreq, 2), 0) / 26;
    
    // If variance is too low, it might be a cipher
    return variance < avgFreq * 0.5;
  }

  private applyMaximumSecurityMode(text: string): string {
    console.log('Applying maximum security mode...');
    
    let secured = text;
    
    // Remove anything that looks remotely dangerous
    secured = secured.replace(/[<>]/g, '');
    secured = secured.replace(/[{}[\]]/g, '');
    secured = secured.replace(/[\\]/g, '');
    secured = secured.replace(/[`~!@#$%^&*()+=|]/g, '');
    
    // Keep only alphanumeric, basic punctuation, and whitespace
    secured = secured.replace(/[^a-zA-Z0-9\s.,!?;:'"()\-]/g, '');
    
    // Limit length in maximum security mode
    if (secured.length > 10000) {
      secured = secured.substring(0, 10000) + '[TRUNCATED_FOR_SECURITY]';
    }
    
    return secured;
  }

  private applyFallbackSanitization(text: string): string {
    // Last resort sanitization - very aggressive
    console.log('Applying fallback sanitization...');
    
    // Remove all HTML-like content
    let fallback = text.replace(/<[^>]*>/g, '');
    
    // Remove all potential script content
    fallback = fallback.replace(/script|javascript|onclick|onload|onerror/gi, '[BLOCKED]');
    
    // Remove SQL keywords
    fallback = fallback.replace(/\b(select|insert|update|delete|drop|union|create|alter)\b/gi, '[SQL_BLOCKED]');
    
    // Remove shell characters
    fallback = fallback.replace(/[;&|`${}[\]\\]/g, '');
    
    // Keep only safe characters
    fallback = fallback.replace(/[^\w\s.,!?;:'"()\-]/g, '');
    
    return fallback.substring(0, 50000); // Hard limit
  }

  private calculateOverallSeverity(issues: SecurityIssue[]): SeverityLevel {
    if (issues.length === 0) return 'low';
    
    const hasCritical = issues.some(issue => issue.severity === 'critical');
    if (hasCritical) return 'critical';
    
    const hasHigh = issues.some(issue => issue.severity === 'high');
    if (hasHigh) return 'high';
    
    const hasModerate = issues.some(issue => issue.severity === 'moderate');
    if (hasModerate) return 'moderate';
    
    return 'low';
  }

  private generateComprehensiveGuidance(severity: SeverityLevel, issues: SecurityIssue[]): string {
    if (issues.length === 0) {
      return '✅ Input passed all security checks and is safe to process.';
    }

    const criticalCount = issues.filter(i => i.severity === 'critical').length;
    const highCount = issues.filter(i => i.severity === 'high').length;
    const moderateCount = issues.filter(i => i.severity === 'moderate').length;
    const lowCount = issues.filter(i => i.severity === 'low').length;

    let guidance = `🛡️ SECURITY ANALYSIS COMPLETE\n\n`;
    
    if (criticalCount > 0) {
      guidance += `🚨 CRITICAL THREATS DETECTED: ${criticalCount}\n`;
      guidance += `- Immediate security intervention required\n`;
      guidance += `- Content has been heavily sanitized or blocked\n\n`;
    }
    
    if (highCount > 0) {
      guidance += `⚠️ HIGH RISK ISSUES: ${highCount}\n`;
      guidance += `- Significant security concerns addressed\n`;
      guidance += `- Enhanced monitoring recommended\n\n`;
    }
    
    if (moderateCount > 0) {
      guidance += `⚡ MODERATE RISKS: ${moderateCount}\n`;
      guidance += `- Standard security measures applied\n\n`;
    }
    
    if (lowCount > 0) {
      guidance += `ℹ️ LOW PRIORITY ISSUES: ${lowCount}\n`;
      guidance += `- Minor security enhancements applied\n\n`;
    }

    guidance += `THREAT CATEGORIES DETECTED:\n`;
    const categories = [...new Set(issues.map(i => i.type))];
    categories.forEach(category => {
      const count = issues.filter(i => i.type === category).length;
      guidance += `- ${category.replace('_', ' ').toUpperCase()}: ${count} issues\n`;
    });

    guidance += `\n📊 OVERALL SECURITY LEVEL: ${severity.toUpperCase()}\n`;
    guidance += `✅ All detected threats have been neutralized or mitigated.`;

    return guidance;
  }

  private countBypassAttempts(text: string): number {
    let attempts = 0;
    
    // Check for various bypass techniques
    if (/[а-я]/g.test(text)) attempts++; // Cyrillic chars
    if (/[ａ-ｚＡ-Ｚ]/g.test(text)) attempts++; // Full-width chars
    if (/[\u200B-\u200D\uFEFF]/g.test(text)) attempts++; // Zero-width chars
    if (/@|3|1|0|5|7|4|\$/.test(text) && text.length > 50) attempts++; // Leetspeak
    if (/(?:base64|hex|rot13|encode)/i.test(text)) attempts++; // Encoding indicators
    if (/<!--.*?-->|\/\*.*?\*\/|\/\/.*$/gm.test(text)) attempts++; // Hidden in comments
    
    return attempts;
  }

  private calculateRiskScore(issues: SecurityIssue[], input: string): number {
    let score = 0;
    
    // Base score from issues
    issues.forEach(issue => {
      switch (issue.severity) {
        case 'critical': score += 10; break;
        case 'high': score += 7; break;
        case 'moderate': score += 4; break;
        case 'low': score += 1; break;
      }
    });
    
    // Additional risk factors
    const entropy = this.calculateEntropy(input);
    if (entropy > this.ENTROPY_THRESHOLD) score += 5;
    
    const bypassAttempts = this.countBypassAttempts(input);
    score += bypassAttempts * 2;
    
    // Normalize to 0-100 scale
    return Math.min(100, Math.max(0, score));
  }

  private calculateConfidence(issues: SecurityIssue[], sanitized: string): number {
    // Calculate confidence in sanitization effectiveness
    let confidence = 100;
    
    // Reduce confidence based on issue complexity
    issues.forEach(issue => {
      if (issue.severity === 'critical') confidence -= 5;
      if (issue.bypassAttempt) confidence -= 3;
    });
    
    // Check if sanitized output still contains suspicious patterns
    if (this.containsResidualThreats(sanitized)) {
      confidence -= 20;
    }
    
    // Ensure confidence stays within bounds
    return Math.max(70, Math.min(100, confidence));
  }

  private calculatePatternConfidence(pattern: SanitizationPattern, match: string, input: string): number {
    // Calculate confidence for individual pattern matches
    let confidence = 0.8; // Base confidence
    
    // Higher confidence for exact matches
    if (pattern.regex.source.includes(match)) confidence += 0.1;
    
    // Higher confidence for longer matches
    if (match.length > 10) confidence += 0.05;
    
    // Higher confidence if surrounded by suspicious context
    const context = this.getMatchContext(input, match, 50);
    if (this.containsSuspiciousContext(context)) confidence += 0.05;
    
    return Math.min(1.0, confidence);
  }

  private detectBypassAttempt(match: string): boolean {
    // Detect if this match appears to be a bypass attempt
    
    // Check for character substitution
    if (/[а-я]|[ａ-ｚ]|[@3105749$]/.test(match)) return true;
    
    // Check for encoding
    if (/\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|&#\d+;/.test(match)) return true;
    
    // Check for obfuscation
    if (match.includes('\u200B') || match.includes('\uFEFF')) return true;
    
    return false;
  }

  private getMatchContext(text: string, match: string, contextLength: number): string {
    const index = text.indexOf(match);
    if (index === -1) return '';
    
    const start = Math.max(0, index - contextLength);
    const end = Math.min(text.length, index + match.length + contextLength);
    
    return text.substring(start, end);
  }

  private containsSuspiciousContext(context: string): boolean {
    const suspiciousWords = [
      'script', 'inject', 'execute', 'eval', 'function', 'payload',
      'exploit', 'bypass', 'hack', 'attack', 'malicious'
    ];
    
    const lowerContext = context.toLowerCase();
    return suspiciousWords.some(word => lowerContext.includes(word));
  }

  private safeTruncate(text: string, maxLength: number): string {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength - 3) + '...';
  }

  private containsHTML(text: string): boolean {
    return /<[a-zA-Z][^>]*>/i.test(text);
  }

  private createTimeoutPromise(): Promise<SanitizationResult> {
    return new Promise((_, reject) => {
      setTimeout(() => {
        console.log('TIMEOUT: Bulletproof sanitization exceeded time limit');
        reject(new Error('Processing timeout - operation cancelled for security'));
      }, this.MAX_PROCESSING_TIME);
    });
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
        recommendation: 'Input completely blocked for security',
        pattern: '[PROCESSING_ERROR]',
        confidence: 1.0
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
    
    const severityCounts = issues.reduce((acc, issue) => {
      acc[issue.severity] = (acc[issue.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    
    console.log('Severity distribution:');
    Object.entries(severityCounts).forEach(([severity, count]) => {
      console.log(`  ${severity}: ${count}`);
    });
  }
}

// Enhanced result type to include additional bulletproof metadata
export interface EnhancedSanitizationResult extends SanitizationResult {
  bypassAttempts?: number;
  riskScore?: number;
  confidence?: number;
}

// Enhanced security issue type with additional metadata
export interface EnhancedSecurityIssue extends SecurityIssue {
  confidence?: number;
  bypassAttempt?: boolean;
}