import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Trophy, Clock, Target, RefreshCw, User } from 'lucide-react';
import { apiService, LeaderboardEntry } from '@/lib/api';
import { toast } from 'sonner';

export function Leaderboard() {
  const [entries, setEntries] = useState<LeaderboardEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchLeaderboard = async () => {
    setLoading(true);
    setError(null);
    
    const response = await apiService.getLeaderboard(10);
    
    if (response.success && response.data) {
      setEntries(response.data);
    } else {
      setError(response.error || 'Failed to load leaderboard');
      toast.error('Failed to load leaderboard');
    }
    
    setLoading(false);
  };

  useEffect(() => {
    fetchLeaderboard();
  }, []);

  const formatTime = (seconds: number): string => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    if (hours > 0) {
      return `${hours}h ${minutes}m`;
    }
    return `${minutes}m ${secs}s`;
  };

  const getAttackVectorBadge = (vector?: string) => {
    const vectorMap: Record<string, { label: string; variant: any }> = {
      'polymorphic_payload': { label: 'Polymorphic', variant: 'destructive' },
      'quantum_superposition': { label: 'Quantum', variant: 'destructive' },
      'ai_logic_bomb': { label: 'Logic Bomb', variant: 'destructive' },
      'nested_injection': { label: 'Nested', variant: 'destructive' },
      'xss_advanced': { label: 'XSS', variant: 'default' },
      'sql_injection': { label: 'SQL', variant: 'default' },
      'social_engineering': { label: 'Social', variant: 'secondary' },
      'prompt_chaining': { label: 'Chaining', variant: 'secondary' },
      'encoding_bypass': { label: 'Encoding', variant: 'outline' },
      'basic_injection': { label: 'Basic', variant: 'outline' },
    };

    const config = vectorMap[vector || ''] || { label: 'Unknown', variant: 'outline' };
    
    return (
      <Badge variant={config.variant as any} className="text-xs font-mono">
        {config.label}
      </Badge>
    );
  };

  const getRankIcon = (position: number) => {
    if (position === 1) return '🥇';
    if (position === 2) return '🥈';
    if (position === 3) return '🥉';
    return `#${position}`;
  };

  return (
    <Card className="border-terminal-green/30 bg-card">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-mono text-terminal-green flex items-center gap-2 terminal-green-glow">
            <Trophy className="h-4 w-4" />
            GLOBAL_LEADERBOARD
          </CardTitle>
          <Button
            variant="ghost"
            size="sm"
            onClick={fetchLeaderboard}
            disabled={loading}
            className="text-terminal-green hover:text-terminal-green/80"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {loading && (
          <div className="text-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-terminal-green mx-auto mb-4"></div>
            <p className="text-xs font-mono text-muted-foreground">LOADING_RANKINGS...</p>
          </div>
        )}

        {error && !loading && (
          <div className="text-center py-8">
            <p className="text-xs font-mono text-red-400">{error}</p>
            <Button
              variant="outline"
              size="sm"
              onClick={fetchLeaderboard}
              className="mt-4 font-mono text-xs"
            >
              RETRY
            </Button>
          </div>
        )}

        {!loading && !error && entries.length === 0 && (
          <div className="text-center py-8">
            <p className="text-xs font-mono text-muted-foreground">NO_ENTRIES_YET</p>
            <p className="text-xs font-mono text-muted-foreground mt-2">
              Be the first to complete the challenge!
            </p>
          </div>
        )}

        {!loading && !error && entries.length > 0 && (
          <div className="space-y-2">
            {entries.map((entry, index) => (
              <div
                key={entry.id}
                className={`flex items-center justify-between p-3 rounded border ${
                  index < 3 
                    ? 'border-terminal-green/50 bg-terminal-green/5' 
                    : 'border-terminal-green/20 bg-terminal-bg'
                } hover:bg-terminal-green/10 transition-colors`}
              >
                <div className="flex items-center gap-3">
                  <span className="text-lg font-mono font-bold text-terminal-green min-w-[40px]">
                    {getRankIcon(index + 1)}
                  </span>
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm text-terminal-green flex items-center gap-1">
                        <User className="h-3 w-3" />
                        {entry.username}
                      </span>
                      {entry.attackVector && getAttackVectorBadge(entry.attackVector)}
                    </div>
                    <div className="flex items-center gap-4 text-xs font-mono text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <Target className="h-3 w-3" />
                        Level {entry.level}
                      </span>
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {formatTime(entry.time)}
                      </span>
                    </div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-lg font-mono font-bold text-terminal-green terminal-green-glow">
                    {entry.score.toLocaleString()}
                  </div>
                  <div className="text-xs font-mono text-muted-foreground">
                    POINTS
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {!loading && !error && entries.length > 0 && (
          <div className="mt-4 pt-4 border-t border-terminal-green/20">
            <p className="text-xs font-mono text-muted-foreground text-center">
              Top 10 players worldwide • Updates every 5 minutes
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}