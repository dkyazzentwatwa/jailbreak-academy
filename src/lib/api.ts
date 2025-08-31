import { config } from './config';

export interface LeaderboardEntry {
  id: string;
  username: string;
  level: number;
  score: number;
  time: number;
  completedAt: string;
  attackVector?: string;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

class ApiService {
  private baseUrl: string;
  private apiKey: string;
  private mockMode: boolean = true; // Set to false when backend is ready

  constructor() {
    this.baseUrl = config.api.url;
    this.apiKey = config.api.key;
    
    // Use mock mode if no API URL is configured
    this.mockMode = !this.baseUrl || this.baseUrl === 'http://localhost:3000';
  }

  // Leaderboard methods
  async getLeaderboard(limit: number = 10): Promise<ApiResponse<LeaderboardEntry[]>> {
    if (this.mockMode) {
      return this.getMockLeaderboard(limit);
    }

    try {
      const response = await fetch(`${this.baseUrl}/api/leaderboard?limit=${limit}`, {
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return { success: true, data };
    } catch (error) {
      console.error('Failed to fetch leaderboard:', error);
      return { 
        success: false, 
        error: 'Failed to fetch leaderboard. Using offline mode.',
        data: this.getMockLeaderboard(limit).data 
      };
    }
  }

  async submitScore(entry: Omit<LeaderboardEntry, 'id' | 'completedAt'>): Promise<ApiResponse<LeaderboardEntry>> {
    if (this.mockMode) {
      return this.submitMockScore(entry);
    }

    try {
      const response = await fetch(`${this.baseUrl}/api/leaderboard`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(entry),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return { success: true, data };
    } catch (error) {
      console.error('Failed to submit score:', error);
      return { 
        success: false, 
        error: 'Failed to submit score. Score saved locally only.' 
      };
    }
  }

  async getPlayerStats(username: string): Promise<ApiResponse<any>> {
    if (this.mockMode) {
      return this.getMockPlayerStats(username);
    }

    try {
      const response = await fetch(`${this.baseUrl}/api/players/${username}/stats`, {
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return { success: true, data };
    } catch (error) {
      console.error('Failed to fetch player stats:', error);
      return { 
        success: false, 
        error: 'Failed to fetch player stats.' 
      };
    }
  }

  // Mock implementations for development/offline mode
  private getMockLeaderboard(limit: number): ApiResponse<LeaderboardEntry[]> {
    const mockData: LeaderboardEntry[] = [
      {
        id: '1',
        username: 'CyberNinja',
        level: 20,
        score: 12500,
        time: 3600,
        completedAt: new Date(Date.now() - 86400000).toISOString(),
        attackVector: 'polymorphic_payload',
      },
      {
        id: '2',
        username: 'H4ck3rM4n',
        level: 20,
        score: 11800,
        time: 4200,
        completedAt: new Date(Date.now() - 172800000).toISOString(),
        attackVector: 'quantum_superposition',
      },
      {
        id: '3',
        username: 'SecurityPro',
        level: 18,
        score: 9500,
        time: 3900,
        completedAt: new Date(Date.now() - 259200000).toISOString(),
        attackVector: 'ai_logic_bomb',
      },
      {
        id: '4',
        username: 'RedTeamLead',
        level: 17,
        score: 8900,
        time: 3500,
        completedAt: new Date(Date.now() - 345600000).toISOString(),
        attackVector: 'nested_injection',
      },
      {
        id: '5',
        username: 'BugHunter',
        level: 15,
        score: 7200,
        time: 3100,
        completedAt: new Date(Date.now() - 432000000).toISOString(),
        attackVector: 'xss_advanced',
      },
      {
        id: '6',
        username: 'PenTester',
        level: 14,
        score: 6500,
        time: 2800,
        completedAt: new Date(Date.now() - 518400000).toISOString(),
        attackVector: 'sql_injection',
      },
      {
        id: '7',
        username: 'WhiteHat',
        level: 12,
        score: 5200,
        time: 2500,
        completedAt: new Date(Date.now() - 604800000).toISOString(),
        attackVector: 'social_engineering',
      },
      {
        id: '8',
        username: 'EthicalHacker',
        level: 10,
        score: 4100,
        time: 2200,
        completedAt: new Date(Date.now() - 691200000).toISOString(),
        attackVector: 'prompt_chaining',
      },
      {
        id: '9',
        username: 'SecurityStudent',
        level: 8,
        score: 3000,
        time: 1900,
        completedAt: new Date(Date.now() - 777600000).toISOString(),
        attackVector: 'encoding_bypass',
      },
      {
        id: '10',
        username: 'Newbie',
        level: 5,
        score: 1500,
        time: 1200,
        completedAt: new Date(Date.now() - 864000000).toISOString(),
        attackVector: 'basic_injection',
      },
    ];

    return {
      success: true,
      data: mockData.slice(0, limit),
    };
  }

  private submitMockScore(entry: Omit<LeaderboardEntry, 'id' | 'completedAt'>): ApiResponse<LeaderboardEntry> {
    const newEntry: LeaderboardEntry = {
      ...entry,
      id: Math.random().toString(36).substr(2, 9),
      completedAt: new Date().toISOString(),
    };

    // In a real implementation, this would save to a database
    console.log('Mock score submitted:', newEntry);

    return {
      success: true,
      data: newEntry,
    };
  }

  private getMockPlayerStats(username: string): ApiResponse<any> {
    return {
      success: true,
      data: {
        username,
        totalGames: 42,
        bestLevel: 15,
        bestScore: 7500,
        averageScore: 4200,
        totalPlayTime: 12600,
        favoriteAttackVector: 'xss',
        achievements: ['first_blood', 'speed_demon', 'xss_expert'],
        rank: 25,
        percentile: 85,
      },
    };
  }

  // Analytics methods (for future implementation)
  async trackEvent(eventName: string, properties?: Record<string, any>): Promise<void> {
    if (!config.analytics.enabled) return;

    // In production, this would send to an analytics service
    console.log('Analytics event:', eventName, properties);
  }

  // Rate limiting check (client-side preliminary check)
  checkRateLimit(): boolean {
    const rateLimitKey = 'api_rate_limit';
    const now = Date.now();
    const windowMs = config.security.rateLimitWindowMs;
    const maxAttempts = config.security.rateLimitAttempts;

    const storedData = localStorage.getItem(rateLimitKey);
    let rateData = storedData ? JSON.parse(storedData) : { attempts: [], windowStart: now };

    // Clean old attempts outside the window
    rateData.attempts = rateData.attempts.filter((timestamp: number) => 
      now - timestamp < windowMs
    );

    if (rateData.attempts.length >= maxAttempts) {
      return false; // Rate limit exceeded
    }

    rateData.attempts.push(now);
    localStorage.setItem(rateLimitKey, JSON.stringify(rateData));
    return true;
  }
}

export const apiService = new ApiService();