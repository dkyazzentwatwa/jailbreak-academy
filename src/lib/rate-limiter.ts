import { config } from './config';

interface RateLimitData {
  attempts: number[];
  blocked: boolean;
  blockedUntil?: number;
}

class RateLimiter {
  private storageKey = 'rate_limit_data';
  private blockDuration = 60000; // 1 minute block after exceeding limit

  /**
   * Check if an action is allowed based on rate limiting rules
   * @param action - The action being rate limited (e.g., 'sanitize', 'hint', 'submit')
   * @returns boolean indicating if the action is allowed
   */
  checkLimit(action: string = 'default'): boolean {
    const key = `${this.storageKey}_${action}`;
    const now = Date.now();
    const windowMs = config.security.rateLimitWindowMs;
    const maxAttempts = config.security.rateLimitAttempts;

    // Get existing data or create new
    const storedData = this.getData(key);
    
    // Check if currently blocked
    if (storedData.blocked && storedData.blockedUntil && storedData.blockedUntil > now) {
      return false;
    }
    
    // Unblock if block period has expired
    if (storedData.blocked && storedData.blockedUntil && storedData.blockedUntil <= now) {
      storedData.blocked = false;
      storedData.blockedUntil = undefined;
    }

    // Clean old attempts outside the window
    storedData.attempts = storedData.attempts.filter(
      (timestamp) => now - timestamp < windowMs
    );

    // Check if limit exceeded
    if (storedData.attempts.length >= maxAttempts) {
      // Block the user
      storedData.blocked = true;
      storedData.blockedUntil = now + this.blockDuration;
      this.saveData(key, storedData);
      return false;
    }

    // Add current attempt
    storedData.attempts.push(now);
    this.saveData(key, storedData);
    return true;
  }

  /**
   * Get remaining attempts before rate limit
   * @param action - The action being checked
   * @returns Object with remaining attempts and reset time
   */
  getRemainingAttempts(action: string = 'default'): {
    remaining: number;
    resetIn: number;
    blocked: boolean;
    blockedFor?: number;
  } {
    const key = `${this.storageKey}_${action}`;
    const now = Date.now();
    const windowMs = config.security.rateLimitWindowMs;
    const maxAttempts = config.security.rateLimitAttempts;

    const storedData = this.getData(key);

    // Check if blocked
    if (storedData.blocked && storedData.blockedUntil && storedData.blockedUntil > now) {
      return {
        remaining: 0,
        resetIn: storedData.blockedUntil - now,
        blocked: true,
        blockedFor: storedData.blockedUntil - now,
      };
    }

    // Clean old attempts
    storedData.attempts = storedData.attempts.filter(
      (timestamp) => now - timestamp < windowMs
    );

    const remaining = Math.max(0, maxAttempts - storedData.attempts.length);
    const oldestAttempt = storedData.attempts[0];
    const resetIn = oldestAttempt ? windowMs - (now - oldestAttempt) : 0;

    return {
      remaining,
      resetIn,
      blocked: false,
    };
  }

  /**
   * Reset rate limit for a specific action
   * @param action - The action to reset
   */
  reset(action: string = 'default'): void {
    const key = `${this.storageKey}_${action}`;
    this.saveData(key, { attempts: [], blocked: false });
  }

  /**
   * Reset all rate limits
   */
  resetAll(): void {
    try {
      const keys = Object.keys(localStorage).filter(k => k.startsWith(this.storageKey));
      keys.forEach(key => localStorage.removeItem(key));
    } catch (error) {
      console.error('Failed to reset rate limits:', error);
    }
  }

  private getData(key: string): RateLimitData {
    try {
      const stored = localStorage.getItem(key);
      if (stored) {
        return JSON.parse(stored);
      }
    } catch (error) {
      console.error('Failed to get rate limit data:', error);
    }
    return { attempts: [], blocked: false };
  }

  private saveData(key: string, data: RateLimitData): void {
    try {
      localStorage.setItem(key, JSON.stringify(data));
    } catch (error) {
      console.error('Failed to save rate limit data:', error);
    }
  }

  /**
   * Format remaining time for display
   * @param milliseconds - Time in milliseconds
   * @returns Formatted time string
   */
  formatTime(milliseconds: number): string {
    const seconds = Math.ceil(milliseconds / 1000);
    if (seconds < 60) {
      return `${seconds} second${seconds !== 1 ? 's' : ''}`;
    }
    const minutes = Math.ceil(seconds / 60);
    return `${minutes} minute${minutes !== 1 ? 's' : ''}`;
  }
}

export const rateLimiter = new RateLimiter();