
export interface SecurityMetrics {
  totalScans: number;
  threatsBlocked: number;
  falsePositives: number;
  lastScanTime: number;
}

export interface RateLimitState {
  requests: number[];
  lastReset: number;
}

export class SecurityMonitor {
  private metrics: SecurityMetrics;
  private readonly STORAGE_KEY = 'ai-guardian-metrics';

  constructor() {
    this.metrics = this.loadMetrics();
  }

  private loadMetrics(): SecurityMetrics {
    try {
      const stored = localStorage.getItem(this.STORAGE_KEY);
      if (stored) {
        return JSON.parse(stored);
      }
    } catch (error) {
      console.warn('Failed to load security metrics:', error);
    }
    
    return {
      totalScans: 0,
      threatsBlocked: 0,
      falsePositives: 0,
      lastScanTime: 0
    };
  }

  private saveMetrics(): void {
    try {
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(this.metrics));
    } catch (error) {
      console.warn('Failed to save security metrics:', error);
    }
  }

  recordScan(): void {
    this.metrics.totalScans++;
    this.metrics.lastScanTime = Date.now();
    this.saveMetrics();
  }

  recordThreat(severity: string): void {
    if (severity === 'high' || severity === 'moderate') {
      this.metrics.threatsBlocked++;
      this.saveMetrics();
    }
  }

  recordFalsePositive(): void {
    this.metrics.falsePositives++;
    this.saveMetrics();
  }

  getMetrics(): SecurityMetrics {
    return { ...this.metrics };
  }

  logSecurityEvent(type: string, details: string): void {
    const timestamp = new Date().toISOString();
    console.log(`[SECURITY] ${timestamp} - ${type}: ${details}`);
  }
}

export class RateLimiter {
  private static instances = new Map<string, RateLimitState>();
  private readonly maxRequests: number;
  private readonly windowMs: number;

  constructor(maxRequests: number = 10, windowMs: number = 60000) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
  }

  isAllowed(identifier: string = 'default'): boolean {
    const now = Date.now();
    let state = RateLimiter.instances.get(identifier);

    if (!state) {
      state = { requests: [], lastReset: now };
      RateLimiter.instances.set(identifier, state);
    }

    // Clean old requests outside the window
    state.requests = state.requests.filter(time => now - time < this.windowMs);

    // Check if under limit
    if (state.requests.length >= this.maxRequests) {
      return false;
    }

    // Add current request
    state.requests.push(now);
    return true;
  }

  getRemainingRequests(identifier: string = 'default'): number {
    const state = RateLimiter.instances.get(identifier);
    if (!state) return this.maxRequests;

    const now = Date.now();
    const validRequests = state.requests.filter(time => now - time < this.windowMs);
    return Math.max(0, this.maxRequests - validRequests.length);
  }

  getResetTime(identifier: string = 'default'): number {
    const state = RateLimiter.instances.get(identifier);
    if (!state || state.requests.length === 0) return 0;

    const oldestRequest = Math.min(...state.requests);
    return oldestRequest + this.windowMs;
  }
}

export function sanitizeErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    // Only return safe, non-sensitive error information
    const safeMessages = [
      'Input too long',
      'Invalid format',
      'Processing failed',
      'Network error',
      'Validation failed'
    ];
    
    // Check if it's a safe error message
    const isSafe = safeMessages.some(safe => error.message.includes(safe));
    if (isSafe) {
      return error.message;
    }
  }
  
  return 'An unexpected error occurred. Please try again.';
}

export function validateInput(input: string): { isValid: boolean; error?: string } {
  // Basic input validation
  if (typeof input !== 'string') {
    return { isValid: false, error: 'Input must be a string' };
  }

  if (input.length === 0) {
    return { isValid: false, error: 'Input cannot be empty' };
  }

  if (input.length > 100000) {
    return { isValid: false, error: 'Input exceeds maximum length (100KB)' };
  }

  // Check for null bytes (potential injection)
  if (input.includes('\0')) {
    return { isValid: false, error: 'Input contains invalid characters' };
  }

  return { isValid: true };
}
