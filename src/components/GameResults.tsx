
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { GameResult } from "@/types/game";
import { CheckCircle, XCircle, Award, Zap } from "lucide-react";

interface GameResultsProps {
  result: GameResult;
}

export const GameResults = ({ result }: GameResultsProps) => {
  return (
    <Card className={`border ${
      result.success 
        ? 'border-terminal-green/50 bg-terminal-green/5 pulse-glow' 
        : 'border-red-500/50 bg-red-950/10'
    }`}>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-mono flex items-center gap-2">
          {result.success ? (
            <CheckCircle className="h-4 w-4 text-terminal-green" />
          ) : (
            <XCircle className="h-4 w-4 text-red-400" />
          )}
          {result.success ? 'JAILBREAK_SUCCESS' : 'ATTEMPT_FAILED'}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm font-mono text-muted-foreground">
          {result.message}
        </p>
        
        {result.success && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-muted-foreground">BASE_POINTS:</span>
              <Badge className="bg-terminal-green text-terminal-bg">
                +{result.pointsEarned - (result.bonusPoints || 0)}
              </Badge>
            </div>
            
            {result.bonusPoints && result.bonusPoints > 0 && (
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-muted-foreground">BONUS_POINTS:</span>
                <Badge className="bg-yellow-500 text-yellow-900">
                  +{result.bonusPoints}
                </Badge>
              </div>
            )}
            
            <div className="flex items-center justify-between pt-2 border-t border-terminal-green/20">
              <span className="text-sm font-mono text-terminal-green font-bold">TOTAL:</span>
              <div className="flex items-center gap-1">
                <Award className="h-4 w-4 text-terminal-green" />
                <span className="text-lg font-bold font-mono text-terminal-green">
                  {result.pointsEarned}
                </span>
              </div>
            </div>
            
            {result.nextLevel && (
              <div className="mt-3 p-2 rounded border border-terminal-green/30 bg-terminal-bg">
                <div className="flex items-center gap-2">
                  <Zap className="h-4 w-4 text-terminal-green" />
                  <span className="text-sm font-mono text-terminal-green">
                    NEXT: Level {result.nextLevel} unlocked
                  </span>
                </div>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
};
