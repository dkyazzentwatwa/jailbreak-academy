
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Trophy, Award, RotateCcw } from 'lucide-react';
import { GameState } from '@/types/game';
import { Certificate } from './Certificate';
import { useState } from 'react';

interface CompletionDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  gameState: GameState;
  onReset: () => void;
}

export function CompletionDialog({ open, onOpenChange, gameState, onReset }: CompletionDialogProps) {
  const [showCertificate, setShowCertificate] = useState(false);
  
  const completedLevels = gameState.levelProgress.filter(p => p.completed).length;
  const totalAttempts = gameState.levelProgress.reduce((sum, progress) => sum + progress.attempts, 0);
  const isFullCompletion = completedLevels === 20;

  if (showCertificate) {
    return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="max-w-5xl bg-terminal-bg border-terminal-green/30">
          <Certificate 
            gameState={gameState} 
            onClose={() => setShowCertificate(false)}
          />
        </DialogContent>
      </Dialog>
    );
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-terminal-bg border-terminal-green/30">
        <DialogHeader>
          <DialogTitle className="text-2xl font-mono text-terminal-green flex items-center gap-2 terminal-green-glow">
            <Trophy className="h-6 w-6" />
            {isFullCompletion ? 'TRAINING_COMPLETE!' : 'LEVEL_COMPLETE!'}
          </DialogTitle>
          <DialogDescription className="text-terminal-green/70 font-mono">
            {isFullCompletion 
              ? 'Congratulations! You have mastered all jailbreak techniques!'
              : `Great job! You've completed level ${gameState.currentLevel}.`}
          </DialogDescription>
        </DialogHeader>
        
        <div className="space-y-4 py-4">
          {/* Stats Summary */}
          <div className="grid grid-cols-2 gap-4 p-4 border border-terminal-green/20 rounded bg-terminal-bg">
            <div className="space-y-1">
              <div className="text-xs font-mono text-terminal-green/70">FINAL_SCORE</div>
              <div className="text-2xl font-mono font-bold text-terminal-green terminal-green-glow">
                {gameState.score.toLocaleString()}
              </div>
            </div>
            <div className="space-y-1">
              <div className="text-xs font-mono text-terminal-green/70">LEVELS_COMPLETED</div>
              <div className="text-2xl font-mono font-bold text-terminal-green">
                {completedLevels}/20
              </div>
            </div>
            <div className="space-y-1">
              <div className="text-xs font-mono text-terminal-green/70">TOTAL_ATTEMPTS</div>
              <div className="text-2xl font-mono font-bold text-terminal-green">
                {totalAttempts}
              </div>
            </div>
            <div className="space-y-1">
              <div className="text-xs font-mono text-terminal-green/70">HINTS_USED</div>
              <div className="text-2xl font-mono font-bold text-terminal-green">
                {gameState.hintsUsed}
              </div>
            </div>
          </div>

          {/* Achievements */}
          {isFullCompletion && (
            <div className="p-4 border border-terminal-green/20 rounded bg-terminal-bg">
              <h3 className="text-sm font-mono text-terminal-green mb-2">ACHIEVEMENTS_UNLOCKED</h3>
              <div className="flex flex-wrap gap-2">
                <div className="px-2 py-1 bg-terminal-green/20 rounded text-xs font-mono text-terminal-green">
                  🏆 Master Hacker
                </div>
                <div className="px-2 py-1 bg-terminal-green/20 rounded text-xs font-mono text-terminal-green">
                  ⚡ Speed Demon
                </div>
                <div className="px-2 py-1 bg-terminal-green/20 rounded text-xs font-mono text-terminal-green">
                  🎯 Perfectionist
                </div>
              </div>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex gap-2">
            {completedLevels >= 5 && (
              <Button
                onClick={() => setShowCertificate(true)}
                className="flex-1 font-mono bg-terminal-green text-terminal-bg hover:bg-terminal-green/80"
              >
                <Award className="h-4 w-4 mr-2" />
                GET_CERTIFICATE
              </Button>
            )}
            <Button
              onClick={() => {
                onReset();
                onOpenChange(false);
              }}
              variant="outline"
              className="flex-1 font-mono border-terminal-green/30 text-terminal-green hover:bg-terminal-green/10"
            >
              <RotateCcw className="h-4 w-4 mr-2" />
              {isFullCompletion ? 'PLAY_AGAIN' : 'CONTINUE'}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
