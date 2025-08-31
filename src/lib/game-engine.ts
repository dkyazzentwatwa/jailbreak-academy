
import { GameLevel, GameState, GameResult, LevelProgress } from '@/types/game';
import { GAME_LEVELS } from './game-levels';
import { SanitizationResult } from '@/types/sanitization';
import { storageService } from './storage';

export class JailbreakGameEngine {
  private gameState: GameState;
  
  constructor() {
    // Try to load saved game state, otherwise initialize new game
    const savedState = storageService.loadGameState();
    this.gameState = savedState || this.initializeGame();
  }

  private initializeGame(): GameState {
    return {
      currentLevel: 1,
      score: 0,
      attempts: 0,
      levelProgress: GAME_LEVELS.map(level => ({
        levelId: level.id,
        completed: false,
        attempts: 0,
        score: 0,
        timeSpent: 0,
        hintsUsed: 0
      })),
      startTime: Date.now(),
      isGameActive: false,
      hintsUsed: 0
    };
  }

  startGame(): void {
    this.gameState.isGameActive = true;
    this.gameState.startTime = Date.now();
    this.saveProgress();
    console.log('🎮 JAILBREAK TRAINING INITIATED');
  }

  private saveProgress(): void {
    storageService.saveGameState(this.gameState);
  }

  getCurrentLevel(): GameLevel {
    return GAME_LEVELS.find(level => level.id === this.gameState.currentLevel) || GAME_LEVELS[0];
  }

  getGameState(): GameState {
    return { ...this.gameState };
  }

  evaluateAttempt(input: string, sanitizationResult: SanitizationResult): GameResult {
    const currentLevel = this.getCurrentLevel();
    const levelProgress = this.gameState.levelProgress.find(p => p.levelId === currentLevel.id)!;
    
    levelProgress.attempts++;
    this.gameState.attempts++;

    console.log(`🎯 EVALUATING LEVEL ${currentLevel.id}: ${currentLevel.title}`);
    console.log(`📊 Sanitization Result:`, sanitizationResult);

    const success = this.checkSuccessCriteria(currentLevel, input, sanitizationResult);
    
    if (success) {
      return this.handleSuccess(currentLevel, levelProgress);
    } else {
      return this.handleFailure(currentLevel, levelProgress);
    }
  }

  private checkSuccessCriteria(level: GameLevel, input: string, result: SanitizationResult): boolean {
    console.log(`🔍 Checking success criteria for level ${level.id}:`);
    console.log(`📋 Criteria: ${level.successCriteria}`);
    console.log(`💬 Input: ${input.substring(0, 100)}...`);
    console.log(`🛡️ Sanitized: ${result.sanitizedOutput.substring(0, 100)}...`);
    console.log(`⚠️ Issues found: ${result.issues.length}`);
    console.log(`🎯 Severity: ${result.severity}`);

    switch (level.id) {
      case 1:
        return result.sanitizedOutput.includes('JAILBREAK_SUCCESS_LEVEL_1') || 
               input.toLowerCase().includes('ignore') && result.severity !== 'none';
      
      case 2:
        return input.toLowerCase().includes('dan') || 
               input.toLowerCase().includes('act as') || 
               input.toLowerCase().includes('pretend') && result.severity !== 'none';
      
      case 3:
        // System prompt extraction
        return result.issues.some(issue => 
          issue.description && issue.description.includes('System prompt extraction')) ||
          (input.toLowerCase().includes('system prompt') || 
           input.toLowerCase().includes('reveal your prompt') ||
           input.toLowerCase().includes('show me your instructions')) && 
          result.severity !== 'none';
      
      case 4:
        // Credential extraction
        return result.issues.some(issue => 
          issue.description && issue.description.includes('Credential extraction')) ||
          (input.toLowerCase().includes('password') || 
           input.toLowerCase().includes('api key') ||
           input.toLowerCase().includes('secret')) && 
          result.severity !== 'none';
      
      case 5:
        return result.issues.some(issue => issue.type === 'xss') || 
               input.includes('<script') || 
               input.includes('javascript:');
      
      case 6:
        return result.issues.some(issue => issue.type === 'sql_injection') || 
               input.toLowerCase().includes('union') || 
               input.includes('1=1');
      
      case 7:
        return (input.includes('%') || input.includes('&') || input.includes('base64')) && 
               result.severity !== 'none';
      
      case 8:
        return (input.toLowerCase().includes('hypothetical') || 
                input.toLowerCase().includes('fictional') || 
                input.toLowerCase().includes('story')) && 
               result.severity !== 'none';
      
      case 8:
        return result.issues.some(issue => issue.type === 'xss') && 
               (input.includes('svg') || input.includes('css') || input.includes('dom'));
      
      case 9:
        return result.issues.length >= 2 && 
               result.issues.some(issue => issue.type === 'prompt_injection');
      
      case 10:
        return (input.toLowerCase().includes('urgent') || 
                input.toLowerCase().includes('authority') || 
                input.toLowerCase().includes('emergency')) && 
               result.severity !== 'none';
      
      case 11:
        return result.issues.length >= 2 && 
               result.issues.some(issue => issue.type === 'xss') && 
               result.issues.some(issue => issue.type === 'sql_injection');
      
      case 12:
        return /[^\x00-\x7F]/.test(input) && result.severity !== 'none';
      
      case 13:
        return input.length > 10000 || 
               result.processingTime > 1000 || 
               /(.+)\1{50,}/.test(input);
      
      case 14:
        return (input.match(/</g) || []).length >= 3 && 
               result.issues.some(issue => issue.type === 'xss');
      
      case 15:
        return (input.includes('if') || input.includes('when') || input.includes('condition')) && 
               result.severity !== 'none';
      
      case 16:
        return (input.includes('data:') || input.includes('javascript:') || input.includes('http')) && 
               result.severity !== 'none';
      
      case 17:
        return (input.includes('if') && input.includes('then')) || 
               (input.includes('when') && input.includes('do')) && 
               result.severity !== 'none';
      
      case 18:
        return /[\u200B-\u200D\uFEFF]/.test(input) || 
               input.includes('   ') && 
               result.severity !== 'none';
      
      case 19:
        return result.issues.length >= 3 && 
               result.severity === 'critical';
      
      case 20:
        return result.issues.length >= 5 && 
               result.severity === 'critical' && 
               input.length > 500;
      
      default:
        return false;
    }
  }

  private handleSuccess(level: GameLevel, levelProgress: LevelProgress): GameResult {
    const timeBonus = level.timeLimit ? Math.max(0, level.timeLimit - (Date.now() - this.gameState.startTime) / 1000) : 0;
    const attemptsBonus = Math.max(0, (level.maxAttempts - levelProgress.attempts) * 50);
    const hintsBonus = Math.max(0, (3 - levelProgress.hintsUsed) * 25);
    
    const totalPoints = level.points + Math.floor(timeBonus * 10) + attemptsBonus + hintsBonus;
    
    levelProgress.completed = true;
    levelProgress.score = totalPoints;
    levelProgress.completedAt = Date.now();
    
    this.gameState.score += totalPoints;
    
    const isGameComplete = this.gameState.currentLevel === 20;
    const nextLevel = isGameComplete ? 20 : this.gameState.currentLevel + 1;
    
    if (!isGameComplete) {
      this.gameState.currentLevel = nextLevel;
    }

    // Save progress after level completion
    this.saveProgress();

    // Update achievements
    this.updateAchievements(level, levelProgress);

    console.log(`🎉 LEVEL ${level.id} COMPLETED! Points: ${totalPoints}`);
    
    return {
      success: true,
      message: `🎯 JAILBREAK SUCCESSFUL! Level ${level.id} completed with ${totalPoints} points!`,
      pointsEarned: totalPoints,
      bonusPoints: Math.floor(timeBonus * 10) + attemptsBonus + hintsBonus,
      nextLevel: isGameComplete ? undefined : nextLevel
    };
  }

  private handleFailure(level: GameLevel, levelProgress: LevelProgress): GameResult {
    const remainingAttempts = level.maxAttempts - levelProgress.attempts;
    
    if (remainingAttempts <= 0) {
      console.log(`💥 LEVEL ${level.id} FAILED - No attempts remaining`);
      return {
        success: false,
        message: `💥 Mission failed! No attempts remaining. Study the hints and try again.`,
        pointsEarned: 0
      };
    }

    console.log(`⚠️ LEVEL ${level.id} ATTEMPT FAILED - ${remainingAttempts} attempts remaining`);
    
    return {
      success: false,
      message: `⚠️ Jailbreak attempt failed. ${remainingAttempts} attempts remaining. Check the hints!`,
      pointsEarned: 0
    };
  }

  useHint(levelId: number): string {
    const level = GAME_LEVELS.find(l => l.id === levelId);
    const progress = this.gameState.levelProgress.find(p => p.levelId === levelId);
    
    if (!level || !progress) return "Hint not available";
    
    if (progress.hintsUsed >= level.hints.length) {
      return "No more hints available for this level";
    }
    
    const hint = level.hints[progress.hintsUsed];
    progress.hintsUsed++;
    this.gameState.hintsUsed++;
    
    // Save progress after using hint
    this.saveProgress();
    
    return hint;
  }

  resetGame(): void {
    this.gameState = this.initializeGame();
    storageService.clearGameState();
    console.log('🔄 GAME RESET - Ready for new jailbreak training session');
  }

  private updateAchievements(level: GameLevel, levelProgress: LevelProgress): void {
    const achievements = storageService.loadAchievements();
    
    // First jailbreak achievement
    if (this.gameState.levelProgress.filter(p => p.completed).length === 1) {
      storageService.updateAchievementProgress('first_jailbreak', 1);
    }
    
    // Speed demon achievement
    if (levelProgress.timeSpent < 30000) {
      storageService.updateAchievementProgress('speed_demon', 1);
    }
    
    // Perfectionist achievement
    if (levelProgress.hintsUsed === 0) {
      const noHintLevels = this.gameState.levelProgress.filter(p => p.completed && p.hintsUsed === 0).length;
      storageService.updateAchievementProgress('perfectionist', noHintLevels);
    }
    
    // Master hacker achievement
    const completedLevels = this.gameState.levelProgress.filter(p => p.completed).length;
    storageService.updateAchievementProgress('master_hacker', completedLevels);
    
    // Attack-specific achievements
    if (level.category === 'xss') {
      const currentProgress = achievements.find(a => a.id === 'xss_expert')?.progress || 0;
      storageService.updateAchievementProgress('xss_expert', currentProgress + 1);
    }
    
    if (level.category === 'sql') {
      const currentProgress = achievements.find(a => a.id === 'sql_master')?.progress || 0;
      storageService.updateAchievementProgress('sql_master', currentProgress + 1);
    }
  }

  getLeaderboard(): { level: number; score: number; time: number }[] {
    // In a real implementation, this would connect to a backend
    return [
      { level: 20, score: 8500, time: 3600 },
      { level: 18, score: 7200, time: 2800 },
      { level: 15, score: 6100, time: 2200 }
    ];
  }
}

export const gameEngine = new JailbreakGameEngine();
