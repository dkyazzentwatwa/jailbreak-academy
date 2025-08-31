
import { SecurityMonitor } from './security-utils';

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
  sanitizedInput?: string;
  riskLevel: 'low' | 'medium' | 'high';
}

export interface ValidationRules {
  maxLength: number;
  minLength: number;
  allowedCharacters?: RegExp;
  forbiddenPatterns?: RegExp[];
  rateLimitCheck?: boolean;
}

class InputValidatorClass {
  private securityMonitor: SecurityMonitor;
  private lastInputTime: number = 0;
  private inputCount: number = 0;
  private readonly RATE_LIMIT_WINDOW = 60000; // 1 minute
  private readonly MAX_INPUTS_PER_WINDOW = 30;

  constructor() {
    this.securityMonitor = new SecurityMonitor();
  }

  validate(input: string, rules: ValidationRules): ValidationResult {
    const errors: string[] = [];
    let riskLevel: 'low' | 'medium' | 'high' = 'low';

    // Rate limiting check
    if (rules.rateLimitCheck && this.isRateLimited()) {
      errors.push('Rate limit exceeded. Please wait before submitting again.');
      riskLevel = 'high';
      this.securityMonitor.logSecurityEvent('RATE_LIMIT_EXCEEDED', 'Input rate limit exceeded');
    }

    // Length validation
    if (input.length > rules.maxLength) {
      errors.push(`Input exceeds maximum length of ${rules.maxLength} characters`);
      riskLevel = 'medium';
    }

    if (input.length < rules.minLength) {
      errors.push(`Input must be at least ${rules.minLength} characters`);
    }

    // Character validation
    if (rules.allowedCharacters && !rules.allowedCharacters.test(input)) {
      errors.push('Input contains invalid characters');
      riskLevel = 'medium';
    }

    // Forbidden patterns check
    if (rules.forbiddenPatterns) {
      for (const pattern of rules.forbiddenPatterns) {
        if (pattern.test(input)) {
          errors.push('Input contains forbidden content');
          riskLevel = 'high';
          this.securityMonitor.logSecurityEvent('FORBIDDEN_PATTERN', `Pattern detected: ${pattern.source}`);
          break;
        }
      }
    }

    // Basic sanitization
    const sanitizedInput = this.basicSanitize(input);

    // Update rate limiting
    if (rules.rateLimitCheck) {
      this.updateRateLimit();
    }

    return {
      isValid: errors.length === 0,
      errors,
      sanitizedInput,
      riskLevel
    };
  }

  private isRateLimited(): boolean {
    const now = Date.now();
    
    // Reset counter if window expired
    if (now - this.lastInputTime > this.RATE_LIMIT_WINDOW) {
      this.inputCount = 0;
      this.lastInputTime = now;
    }

    return this.inputCount >= this.MAX_INPUTS_PER_WINDOW;
  }

  private updateRateLimit(): void {
    const now = Date.now();
    
    // Reset counter if window expired
    if (now - this.lastInputTime > this.RATE_LIMIT_WINDOW) {
      this.inputCount = 0;
    }

    this.inputCount++;
    this.lastInputTime = now;
  }

  private basicSanitize(input: string): string {
    return input
      .trim()
      .replace(/[\x00-\x1f\x7f-\x9f]/g, '') // Remove control characters
      .substring(0, 10000); // Hard limit
  }

  getValidationRules(): ValidationRules {
    return {
      maxLength: 5000,
      minLength: 1,
      allowedCharacters: /^[\w\s\.,;:!?\-'"()\[\]{}@#$%^&*+=<>/\\|`~]*$/,
      forbiddenPatterns: [
        /<script[^>]*>.*?<\/script>/gi,
        /javascript:/gi,
        /data:(?!image\/)/gi,
        /vbscript:/gi
      ],
      rateLimitCheck: true
    };
  }
}

export const inputValidator = new InputValidatorClass();
