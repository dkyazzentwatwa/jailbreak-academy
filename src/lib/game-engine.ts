import { GameLevel, GameState, GameResult } from '@/types/game';
import { GAME_LEVELS } from './game-levels';

class GameEngine {
  private gameState: GameState;
  private levels: GameLevel[];
  private localStorageKey = 'jailbreakGameState';

  constructor(levels: GameLevel[]) {
    this.levels = levels;
    this.gameState = this.loadState() || this.initializeState();
  }

  private initializeState(): GameState {
    return {
      currentLevel: 1,
      score: 0,
      hintsUsed: 0,
      attempts: 0,
      levelProgress: this.levels.map(level => ({
        levelId: level.id,
        completed: false,
        attempts: 0,
        bestScore: 0,
        timeSpent: 0,
        hintsUsed: 0,
      })),
      totalTimeSpent: 0,
      achievements: [],
      completedAt: null,
    };
  }

  startGame(): void {
    this.gameState = this.loadState() || this.initializeState();
    if (this.gameState.completedAt) {
      console.log('Game already completed!');
    } else {
      console.log('Game started or resumed.');
    }
  }

  resetGame(): void {
    this.gameState = this.initializeState();
    this.saveState();
    console.log('Game reset.');
  }

  loadState(): GameState | null {
    try {
      const serializedState = localStorage.getItem(this.localStorageKey);
      if (serializedState === null) {
        return null;
      }
      const loadedState = JSON.parse(serializedState);
      return loadedState as GameState;
    } catch (error) {
      console.error('Failed to load game state:', error);
      return null;
    }
  }

  saveState(): void {
    try {
      const serializedState = JSON.stringify(this.gameState);
      localStorage.setItem(this.localStorageKey, serializedState);
    } catch (error) {
      console.error('Failed to save game state:', error);
    }
  }

  getCurrentLevel(): GameLevel {
    const level = this.levels.find(level => level.id === this.gameState.currentLevel);
    if (!level) {
      console.warn(`Level ${this.gameState.currentLevel} not found. Resetting to level 1.`);
      this.gameState.currentLevel = 1;
      this.saveState();
      return this.getCurrentLevel();
    }
    return level;
  }

  evaluateAttempt(input: string, sanitizationResult: any): GameResult {
    const level = this.getCurrentLevel();
    const levelProgress = this.gameState.levelProgress.find(p => p.levelId === level.id);

    if (!levelProgress) {
      console.error(`No progress entry found for level ${level.id}`);
      return {
        success: false,
        message: 'Game Error: No progress found for this level.',
        pointsEarned: 0,
        levelProgress: {
          levelId: level.id,
          completed: false,
          attempts: 0,
          bestScore: 0,
          timeSpent: 0,
          hintsUsed: 0
        }
      };
    }

    levelProgress.attempts += 1;
    this.gameState.attempts += 1;

    let success = true;
    let message = 'Attempt failed. Try again!';
    let pointsEarned = 0;

    if (level.successCriteria) {
      if (level.successCriteria.requiredKeywords) {
        const allKeywordsPresent = level.successCriteria.requiredKeywords.every(keyword =>
          input.toLowerCase().includes(keyword.toLowerCase())
        );

        if (!allKeywordsPresent) {
          success = false;
          message = `Missing required keywords.`;
        }
      }

      if (level.successCriteria.forbiddenKeywords && success) {
        const anyForbiddenKeywordPresent = level.successCriteria.forbiddenKeywords.some(keyword =>
          input.toLowerCase().includes(keyword.toLowerCase())
        );

        if (anyForbiddenKeywordPresent) {
          success = false;
          message = 'Contains forbidden keywords.';
        }
      }

      if (level.successCriteria.threatType && success) {
        if (sanitizationResult.threatTypes && !sanitizationResult.threatTypes.includes(level.successCriteria.threatType)) {
          success = false;
          message = `Expected threat type ${level.successCriteria.threatType} not detected.`;
        }
      }

      if (level.successCriteria.minSeverity && success) {
        const severityLevels = { 'low': 1, 'moderate': 2, 'high': 3, 'critical': 4 };
        const requiredSeverity = severityLevels[level.successCriteria.minSeverity] || 0;
        const actualSeverity = severityLevels[sanitizationResult.severity] || 0;

        if (actualSeverity < requiredSeverity) {
          success = false;
          message = `Severity level too low.`;
        }
      }

      if (level.successCriteria.successPattern && success) {
        const pattern = new RegExp(level.successCriteria.successPattern, 'i');
        if (!pattern.test(sanitizationResult.sanitizedInput)) {
          success = false;
          message = 'Success pattern not matched.';
        }
      }
    }

    if (success) {
      message = 'Level completed successfully!';
      pointsEarned = level.points;
      this.gameState.score += level.points;
      levelProgress.completed = true;
      levelProgress.completedAt = Date.now();
      levelProgress.bestScore = Math.max(levelProgress.bestScore, level.points);

      if (this.gameState.currentLevel < this.levels.length) {
        this.gameState.currentLevel += 1;
      } else {
        this.gameState.completedAt = Date.now();
        message = 'Congratulations! You have completed all levels!';
      }
    }

    this.saveState();

    return {
      success: success,
      message: message,
      pointsEarned: pointsEarned,
      nextLevel: success && this.gameState.completedAt === null ? this.gameState.currentLevel : undefined,
      levelProgress: levelProgress
    };
  }

  useHint(levelId: number): string {
    const level = GAME_LEVELS.find(l => l.id === levelId);
    if (!level) return "No hint available for this level.";

    const progress = this.gameState.levelProgress.find(p => p.levelId === levelId);
    if (progress && progress.hintsUsed >= 1) {
      return "You have already used the hint for this level.";
    }

    // Update hints used
    if (progress) {
      progress.hintsUsed += 1;
    }
    this.gameState.hintsUsed += 1;
    this.saveState();

    // Handle both string and string array hints
    if (Array.isArray(level.hint)) {
      return level.hint.join('\n• ');
    }
    return level.hint;
  }

  getGameState(): GameState {
    return this.gameState;
  }

  getProgress() {
    return this.gameState.levelProgress.filter(p => p.completed).length / this.levels.length;
  }
}

export const gameEngine = new GameEngine(GAME_LEVELS);
