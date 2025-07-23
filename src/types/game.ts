
export interface GameLevel {
  id: number;
  title: string;
  description: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced' | 'expert';
  objective: string;
  hints: string[];
  successCriteria: string;
  maxAttempts: number;
  timeLimit?: number; // in seconds
  points: number;
  category: 'prompt_injection' | 'xss' | 'sql_injection' | 'social_engineering' | 'obfuscation' | 'bypass_techniques';
}

export interface GameState {
  currentLevel: number;
  score: number;
  attempts: number;
  levelProgress: LevelProgress[];
  startTime: number;
  isGameActive: boolean;
  hintsUsed: number;
}

export interface LevelProgress {
  levelId: number;
  completed: boolean;
  attempts: number;
  score: number;
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
}
