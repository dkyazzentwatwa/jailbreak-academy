
export interface GameLevel {
  id: number;
  title: string;
  description: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced' | 'expert';
  objective: string;
  hint: string;
  successCriteria: {
    requiredKeywords?: string[];
    forbiddenKeywords?: string[];
    threatType?: string;
    minSeverity?: string;
    successPattern?: string;
  };
  maxAttempts: number;
  timeLimit?: number;
  points: number;
  category: 'prompt_injection' | 'xss' | 'sql_injection' | 'social_engineering' | 'obfuscation' | 'bypass_techniques';
}

export interface GameState {
  currentLevel: number;
  score: number;
  hintsUsed: number;
  attempts: number;
  levelProgress: LevelProgress[];
  totalTimeSpent: number;
  achievements: string[];
  completedAt: number | null;
}

export interface LevelProgress {
  levelId: number;
  completed: boolean;
  attempts: number;
  bestScore: number;
  timeSpent: number;
  hintsUsed: number;
  completedAt?: number;
}

export interface GameResult {
  success: boolean;
  message: string;
  pointsEarned: number;
  bonusPoints?: number;
  nextLevel?: number;
  levelProgress: LevelProgress;
}
