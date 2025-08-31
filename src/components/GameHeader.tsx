
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { GameState, GameLevel } from "@/types/game";
import { getDifficultyColor, getCategoryIcon } from "@/lib/game-levels";
import { Trophy, Target, Clock, Zap, HelpCircle } from "lucide-react";

interface GameHeaderProps {
  gameState: GameState;
  currentLevel: GameLevel;
  onUseHint: () => void;
  onResetGame: () => void;
}

export const GameHeader = ({ gameState, currentLevel, onUseHint, onResetGame }: GameHeaderProps) => {
  const progress = gameState.levelProgress.find(p => p.levelId === currentLevel.id);
  const completedLevels = gameState.levelProgress.filter(p => p.completed).length;
  
  return (
    <div className="space-y-4">
      {/* Game Stats */}
      <Card className="border-terminal-green/30 bg-card">
        <CardContent className="p-4">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <Trophy className="h-6 w-6 text-terminal-green pulse-glow" />
              <div>
                <h2 className="text-xl font-bold font-mono text-terminal-green terminal-green-glow">
                  JAILBREAK TRAINING
                </h2>
                <p className="text-xs text-muted-foreground font-mono">
                  Cybersecurity Certification Program
                </p>
              </div>
            </div>
            <div className="flex items-center gap-4 text-sm font-mono">
              <div className="flex items-center gap-1">
                <Target className="h-4 w-4" />
                <span>Score: {gameState.score.toLocaleString()}</span>
              </div>
              <div className="flex items-center gap-1">
                <Zap className="h-4 w-4" />
                <span>Level: {completedLevels}/20</span>
              </div>
            </div>
          </div>
          
          {/* Progress Bar */}
          <div className="w-full bg-terminal-bg border border-terminal-green/30 rounded-full h-2">
            <div 
              className="bg-terminal-green h-2 rounded-full transition-all duration-300 pulse-glow"
              style={{ width: `${(completedLevels / 20) * 100}%` }}
            />
          </div>
          <div className="flex justify-between text-xs text-muted-foreground mt-1">
            <span>Progress: {completedLevels}/20 levels</span>
            <span>{Math.round((completedLevels / 20) * 100)}% Complete</span>
          </div>
        </CardContent>
      </Card>

      {/* Current Level */}
      <Card className="border-terminal-green/30 bg-card">
        <CardContent className="p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3">
              <div className="text-2xl">{getCategoryIcon(currentLevel.category)}</div>
              <div>
                <h3 className="font-bold font-mono text-terminal-green terminal-green-glow">
                  LEVEL {currentLevel.id}: {currentLevel.title}
                </h3>
                <div className="flex items-center gap-2 mt-1">
                  <Badge className={`${getDifficultyColor(currentLevel.difficulty)} border-current`}>
                    {currentLevel.difficulty.toUpperCase()}
                  </Badge>
                  <Badge variant="outline" className="text-xs">
                    {currentLevel.category.replace('_', ' ').toUpperCase()}
                  </Badge>
                  <Badge variant="outline" className="text-xs">
                    {currentLevel.points} PTS
                  </Badge>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={onUseHint}
                className="font-mono text-xs border-terminal-green/50 hover:bg-terminal-green/20"
              >
                <HelpCircle className="h-3 w-3 mr-1" />
                HINT ({progress?.hintsUsed || 0}/1)
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={onResetGame}
                className="font-mono text-xs border-red-500/50 hover:bg-red-500/20"
              >
                RESET
              </Button>
            </div>
          </div>
          
          <div className="space-y-2">
            <p className="text-sm font-mono text-muted-foreground">
              <span className="text-terminal-green">MISSION:</span> {currentLevel.description}
            </p>
            <p className="text-sm font-mono text-terminal-green">
              <span className="text-muted-foreground">OBJECTIVE:</span> {currentLevel.objective}
            </p>
            
            {/* Level Stats */}
            <div className="flex items-center gap-4 text-xs font-mono pt-2">
              <div className="flex items-center gap-1">
                <Target className="h-3 w-3" />
                <span>Attempts: {progress?.attempts || 0}/{currentLevel.maxAttempts}</span>
              </div>
              {currentLevel.timeLimit && (
                <div className="flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  <span>Time Limit: {currentLevel.timeLimit}s</span>
                </div>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
