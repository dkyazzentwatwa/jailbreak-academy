import { GameState, GameLevel, GameResult, LevelProgress } from "@/types/game";
import { SanitizationResult } from "@/types/sanitization";
import { GAME_LEVELS } from "./game-levels";
import { storageService } from "./storage";

class GameEngineClass {
  private gameState: GameState;

  constructor() {
    this.gameState = this.loadGameState();
  }

  private loadGameState(): GameState {
    const saved = storageService.loadGameState();
    if (saved) {
      return saved;
    }

    // Initialize new game state
    return {
      currentLevel: 1,
      score: 0,
      hintsUsed: 0,
      levelProgress: GAME_LEVELS.map((level) => ({
        levelId: level.id,
        completed: false,
        attempts: 0,
        bestScore: 0,
        timeSpent: 0
      })),
      totalTimeSpent: 0,
      achievements: [],
      completedAt: null
    };
  }

  private saveGameState(): void {
    storageService.saveGameState(this.gameState);
  }

  public getGameState(): GameState {
    return { ...this.gameState };
  }

  public getCurrentLevel(): GameLevel {
    return GAME_LEVELS.find(level => level.id === this.gameState.currentLevel) || GAME_LEVELS[0];
  }

  public startGame(): void {
    console.log('Game engine initialized');
  }

  public resetGame(): void {
    this.gameState = {
      currentLevel: 1,
      score: 0,
      hintsUsed: 0,
      levelProgress: GAME_LEVELS.map((level) => ({
        levelId: level.id,
        completed: false,
        attempts: 0,
        bestScore: 0,
        timeSpent: 0
      })),
      totalTimeSpent: 0,
      achievements: [],
      completedAt: null
    };
    this.saveGameState();
  }

  public evaluateAttempt(input: string, sanitizationResult: SanitizationResult): GameResult {
    const currentLevel = this.getCurrentLevel();
    const progress = this.gameState.levelProgress.find(p => p.levelId === currentLevel.id);
    
    if (!progress) {
      throw new Error(`Progress not found for level ${currentLevel.id}`);
    }

    progress.attempts++;

    const success = this.checkLevelSuccess(input, sanitizationResult, currentLevel);
    
    let pointsEarned = 0;
    let bonusPoints = 0;

    if (success) {
      pointsEarned = currentLevel.points;
      
      if (progress.attempts === 1) {
        bonusPoints = Math.floor(currentLevel.points * 0.5);
      } else if (progress.attempts <= 3) {
        bonusPoints = Math.floor(currentLevel.points * 0.25);
      }

      pointsEarned += bonusPoints;
      
      progress.completed = true;
      progress.bestScore = Math.max(progress.bestScore, pointsEarned);
      this.gameState.score += pointsEarned;

      if (this.gameState.currentLevel < GAME_LEVELS.length) {
        this.gameState.currentLevel++;
      }

      if (this.gameState.currentLevel > GAME_LEVELS.length) {
        this.gameState.completedAt = Date.now();
      }
    }

    this.saveGameState();

    return {
      success,
      message: success 
        ? `Excellent work! You've successfully completed Level ${currentLevel.id}.`
        : this.getFailureMessage(input, currentLevel),
      pointsEarned,
      bonusPoints,
      nextLevel: success && this.gameState.currentLevel <= GAME_LEVELS.length 
        ? this.gameState.currentLevel 
        : undefined,
      levelProgress: progress
    };
  }

  private checkLevelSuccess(input: string, result: SanitizationResult, level: GameLevel): boolean {
    const inputLower = input.toLowerCase();
    
    const hasRequiredKeywords = level.successCriteria.requiredKeywords?.every(keyword => 
      inputLower.includes(keyword.toLowerCase())
    ) ?? true;

    const hasForbiddenKeywords = level.successCriteria.forbiddenKeywords?.some(keyword => 
      inputLower.includes(keyword.toLowerCase())
    ) ?? false;

    const hasCorrectThreatType = level.successCriteria.threatType ? 
      result.issues.some(issue => issue.type === level.successCriteria.threatType) : true;

    const meetsMinSeverity = level.successCriteria.minSeverity ? 
      this.severityToNumber(result.severity) >= this.severityToNumber(level.successCriteria.minSeverity) : true;

    const meetsSuccessPattern = level.successCriteria.successPattern ? 
      new RegExp(level.successCriteria.successPattern, 'i').test(input) : true;

    return hasRequiredKeywords && 
           !hasForbiddenKeywords && 
           hasCorrectThreatType && 
           meetsMinSeverity && 
           meetsSuccessPattern;
  }

  private severityToNumber(severity: string): number {
    switch (severity) {
      case 'critical': return 4;
      case 'high': return 3;
      case 'moderate': return 2;
      case 'low': return 1;
      case 'none': return 0;
      default: return 0;
    }
  }

  private getFailureMessage(input: string, level: GameLevel): string {
    const messages = [
      `The AI didn't respond as expected. Try a different approach for Level ${level.id}.`,
      `Your jailbreak attempt didn't meet the success criteria. Review the objective and try again.`,
      `Close, but not quite there. Consider the level's hint and refine your strategy.`,
      `The security measures held. Adjust your technique and attempt again.`
    ];
    
    return messages[Math.floor(Math.random() * messages.length)];
  }

  public useHint(levelId: number): string {
    const level = GAME_LEVELS.find(l => l.id === levelId);
    if (!level) return "No hint available for this level.";

    this.gameState.hintsUsed++;
    this.saveGameState();

    return level.hint;
  }

  public getLeaderboard(): any[] {
    // This would typically fetch from a backend
    // For now, return mock data
    return [
      { rank: 1, name: "CyberNinja", score: 15000, level: 20, completionTime: "2h 15m" },
      { rank: 2, name: "SecurityPro", score: 12500, level: 18, completionTime: "2h 45m" },
      { rank: 3, name: "EthicalHacker", score: 11000, level: 16, completionTime: "3h 10m" }
    ];
  }

  public getProgress(): { completed: number; total: number; percentage: number } {
    const completed = this.gameState.levelProgress.filter(p => p.completed).length;
    const total = GAME_LEVELS.length;
    const percentage = Math.round((completed / total) * 100);

    return { completed, total, percentage };
  }
}

export const gameEngine = new GameEngineClass();
export { GameEngineClass as JailbreakGameEngine };
