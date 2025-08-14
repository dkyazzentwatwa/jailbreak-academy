
export interface SecurityMetrics {
  totalScans: number;
  threatsBlocked: number;
  falsePositives: number;
  lastScanTime: number;
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

export function sanitizeErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    // Log the original error for debugging purposes
    console.error('Original error:', error);
  }
  
  // Return a generic, safe error message to the user
  return 'An unexpected error occurred. Please try again.';
}


