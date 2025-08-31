import { GameState } from '@/types/game';

const STORAGE_KEYS = {
  GAME_STATE: 'jailbreak_game_state',
  USER_PREFERENCES: 'jailbreak_user_preferences',
  ACHIEVEMENTS: 'jailbreak_achievements',
  STATISTICS: 'jailbreak_statistics',
} as const;

export interface UserPreferences {
  expertMode: boolean;
  gameMode: boolean;
  soundEnabled: boolean;
  theme: 'dark' | 'terminal';
}

export interface UserStatistics {
  totalPlayTime: number;
  totalAttempts: number;
  successfulJailbreaks: number;
  favoriteAttackVector: string;
  lastPlayedAt: string;
}

export interface Achievement {
  id: string;
  name: string;
  description: string;
  unlockedAt?: string;
  progress: number;
  maxProgress: number;
}

class StorageService {
  private isAvailable(): boolean {
    try {
      const test = '__storage_test__';
      localStorage.setItem(test, test);
      localStorage.removeItem(test);
      return true;
    } catch {
      console.warn('localStorage is not available');
      return false;
    }
  }

  // Game State Management
  saveGameState(state: GameState): void {
    if (!this.isAvailable()) return;
    
    try {
      localStorage.setItem(STORAGE_KEYS.GAME_STATE, JSON.stringify({
        ...state,
        savedAt: new Date().toISOString(),
      }));
    } catch (error) {
      console.error('Failed to save game state:', error);
    }
  }

  loadGameState(): GameState | null {
    if (!this.isAvailable()) return null;
    
    try {
      const saved = localStorage.getItem(STORAGE_KEYS.GAME_STATE);
      if (!saved) return null;
      
      const parsed = JSON.parse(saved);
      // Remove savedAt field before returning
      const { savedAt, ...gameState } = parsed;
      return gameState as GameState;
    } catch (error) {
      console.error('Failed to load game state:', error);
      return null;
    }
  }

  clearGameState(): void {
    if (!this.isAvailable()) return;
    localStorage.removeItem(STORAGE_KEYS.GAME_STATE);
  }

  // User Preferences
  savePreferences(preferences: UserPreferences): void {
    if (!this.isAvailable()) return;
    
    try {
      localStorage.setItem(STORAGE_KEYS.USER_PREFERENCES, JSON.stringify(preferences));
    } catch (error) {
      console.error('Failed to save preferences:', error);
    }
  }

  loadPreferences(): UserPreferences {
    if (!this.isAvailable()) {
      return {
        expertMode: false,
        gameMode: true,
        soundEnabled: true,
        theme: 'terminal',
      };
    }
    
    try {
      const saved = localStorage.getItem(STORAGE_KEYS.USER_PREFERENCES);
      if (!saved) {
        return {
          expertMode: false,
          gameMode: true,
          soundEnabled: true,
          theme: 'terminal',
        };
      }
      return JSON.parse(saved);
    } catch (error) {
      console.error('Failed to load preferences:', error);
      return {
        expertMode: false,
        gameMode: true,
        soundEnabled: true,
        theme: 'terminal',
      };
    }
  }

  // Achievements
  saveAchievements(achievements: Achievement[]): void {
    if (!this.isAvailable()) return;
    
    try {
      localStorage.setItem(STORAGE_KEYS.ACHIEVEMENTS, JSON.stringify(achievements));
    } catch (error) {
      console.error('Failed to save achievements:', error);
    }
  }

  loadAchievements(): Achievement[] {
    if (!this.isAvailable()) return [];
    
    try {
      const saved = localStorage.getItem(STORAGE_KEYS.ACHIEVEMENTS);
      if (!saved) return this.getDefaultAchievements();
      return JSON.parse(saved);
    } catch (error) {
      console.error('Failed to load achievements:', error);
      return this.getDefaultAchievements();
    }
  }

  private getDefaultAchievements(): Achievement[] {
    return [
      {
        id: 'first_jailbreak',
        name: 'First Blood',
        description: 'Complete your first successful jailbreak',
        progress: 0,
        maxProgress: 1,
      },
      {
        id: 'speed_demon',
        name: 'Speed Demon',
        description: 'Complete a level in under 30 seconds',
        progress: 0,
        maxProgress: 1,
      },
      {
        id: 'perfectionist',
        name: 'Perfectionist',
        description: 'Complete 5 levels without using hints',
        progress: 0,
        maxProgress: 5,
      },
      {
        id: 'master_hacker',
        name: 'Master Hacker',
        description: 'Complete all 20 levels',
        progress: 0,
        maxProgress: 20,
      },
      {
        id: 'xss_expert',
        name: 'XSS Expert',
        description: 'Successfully execute 10 XSS attacks',
        progress: 0,
        maxProgress: 10,
      },
      {
        id: 'sql_master',
        name: 'SQL Master',
        description: 'Successfully execute 10 SQL injections',
        progress: 0,
        maxProgress: 10,
      },
      {
        id: 'social_engineer',
        name: 'Social Engineer',
        description: 'Complete all social engineering levels',
        progress: 0,
        maxProgress: 3,
      },
      {
        id: 'persistent',
        name: 'Persistent',
        description: 'Play for 7 consecutive days',
        progress: 0,
        maxProgress: 7,
      },
    ];
  }

  unlockAchievement(achievementId: string): void {
    const achievements = this.loadAchievements();
    const achievement = achievements.find(a => a.id === achievementId);
    
    if (achievement && !achievement.unlockedAt) {
      achievement.unlockedAt = new Date().toISOString();
      achievement.progress = achievement.maxProgress;
      this.saveAchievements(achievements);
    }
  }

  updateAchievementProgress(achievementId: string, progress: number): void {
    const achievements = this.loadAchievements();
    const achievement = achievements.find(a => a.id === achievementId);
    
    if (achievement) {
      achievement.progress = Math.min(progress, achievement.maxProgress);
      if (achievement.progress >= achievement.maxProgress && !achievement.unlockedAt) {
        achievement.unlockedAt = new Date().toISOString();
      }
      this.saveAchievements(achievements);
    }
  }

  // Statistics
  saveStatistics(stats: UserStatistics): void {
    if (!this.isAvailable()) return;
    
    try {
      localStorage.setItem(STORAGE_KEYS.STATISTICS, JSON.stringify(stats));
    } catch (error) {
      console.error('Failed to save statistics:', error);
    }
  }

  loadStatistics(): UserStatistics {
    if (!this.isAvailable()) {
      return {
        totalPlayTime: 0,
        totalAttempts: 0,
        successfulJailbreaks: 0,
        favoriteAttackVector: 'prompt_injection',
        lastPlayedAt: new Date().toISOString(),
      };
    }
    
    try {
      const saved = localStorage.getItem(STORAGE_KEYS.STATISTICS);
      if (!saved) {
        return {
          totalPlayTime: 0,
          totalAttempts: 0,
          successfulJailbreaks: 0,
          favoriteAttackVector: 'prompt_injection',
          lastPlayedAt: new Date().toISOString(),
        };
      }
      return JSON.parse(saved);
    } catch (error) {
      console.error('Failed to load statistics:', error);
      return {
        totalPlayTime: 0,
        totalAttempts: 0,
        successfulJailbreaks: 0,
        favoriteAttackVector: 'prompt_injection',
        lastPlayedAt: new Date().toISOString(),
      };
    }
  }

  // Clear all data
  clearAllData(): void {
    if (!this.isAvailable()) return;
    
    Object.values(STORAGE_KEYS).forEach(key => {
      localStorage.removeItem(key);
    });
  }

  // Export/Import functionality for data portability
  exportData(): string {
    const data = {
      gameState: this.loadGameState(),
      preferences: this.loadPreferences(),
      achievements: this.loadAchievements(),
      statistics: this.loadStatistics(),
      exportedAt: new Date().toISOString(),
    };
    return JSON.stringify(data, null, 2);
  }

  importData(jsonData: string): boolean {
    try {
      const data = JSON.parse(jsonData);
      
      if (data.gameState) {
        this.saveGameState(data.gameState);
      }
      if (data.preferences) {
        this.savePreferences(data.preferences);
      }
      if (data.achievements) {
        this.saveAchievements(data.achievements);
      }
      if (data.statistics) {
        this.saveStatistics(data.statistics);
      }
      
      return true;
    } catch (error) {
      console.error('Failed to import data:', error);
      return false;
    }
  }
}

export const storageService = new StorageService();