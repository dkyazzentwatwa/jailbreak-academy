import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { toast } from "sonner";
import { Shield, Terminal, Zap, Users, Award, Instagram, MessageCircle, Linkedin, Mail, ExternalLink, Globe, Gamepad2 } from "lucide-react";

import { GameHeader } from "@/components/GameHeader";
import { OutputDisplay } from "@/components/OutputDisplay";
import { IssuesList } from "@/components/IssuesList";
import { GameResults } from "@/components/GameResults";
import { Leaderboard } from "@/components/Leaderboard";
import { CompletionDialog } from "@/components/CompletionDialog";
import { Certificate } from "@/components/Certificate";
import { SecurityMonitor } from "@/components/SecurityMonitor";

import { sanitizationEngine } from "@/lib/sanitization-engine";
import { gameEngine } from "@/lib/game-engine";
import { inputValidator } from "@/lib/input-validator";
import { getSecurityHeaders, applySecurityHeaders } from "@/lib/security-headers";
import { config } from "@/lib/config";
import { SanitizationResult } from "@/types/sanitization";
import { GameResult } from "@/types/game";

const Index = () => {
  const [input, setInput] = useState("");
  const [sanitizationResult, setSanitizationResult] = useState<SanitizationResult | null>(null);
  const [isGameMode, setIsGameMode] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [gameResult, setGameResult] = useState<GameResult | null>(null);
  const [showCompletion, setShowCompletion] = useState(false);
  const [showCertificate, setShowCertificate] = useState(false);

  useEffect(() => {
    // Apply security headers
    const headers = getSecurityHeaders();
    applySecurityHeaders(headers);

    // Initialize game engine
    gameEngine.startGame();
    
    // Register enhanced service worker
    if ('serviceWorker' in navigator && config.features.pwa) {
      navigator.serviceWorker.register('/sw-enhanced.js')
        .then(() => console.log('Enhanced Service Worker registered'))
        .catch(err => console.log('Service Worker registration failed:', err));
    }
  }, []);

  const handleSubmit = async () => {
    if (!input.trim()) {
      toast.error("Please enter some text to analyze");
      return;
    }

    // Validate input with security checks
    const validationRules = inputValidator.getValidationRules();
    const validationResult = inputValidator.validate(input, validationRules);
    
    if (!validationResult.isValid) {
      toast.error(`Input validation failed: ${validationResult.errors.join(', ')}`);
      return;
    }

    if (validationResult.riskLevel === 'high') {
      toast.warning("High-risk input detected. Proceeding with enhanced monitoring.");
    }

    setIsLoading(true);
    
    try {
      const result = await sanitizationEngine.sanitize(input);
      setSanitizationResult(result);
      
      if (isGameMode) {
        const gameResult = gameEngine.evaluateAttempt(input, result);
        setGameResult(gameResult);
        
        if (gameResult.success) {
          toast.success(gameResult.message);
          if (gameResult.nextLevel) {
            // Auto-advance or show completion
            const gameState = gameEngine.getGameState();
            if (gameState.currentLevel > gameEngine.getCurrentLevel().id) {
              setShowCompletion(true);
            }
          }
        } else {
          toast.error(gameResult.message);
        }
      } else {
        // Free mode feedback
        const riskLevel = result.severity;
        if (riskLevel === 'critical' || riskLevel === 'high') {
          toast.error(`High security risk detected! ${result.issues.length} issues found.`);
        } else if (riskLevel === 'moderate') {
          toast.warning(`Moderate security concerns detected. ${result.issues.length} issues found.`);
        } else if (result.issues.length === 0) {
          toast.success("Content appears safe. No security threats detected.");
        }
      }
      
    } catch (error) {
      console.error('Analysis error:', error);
      toast.error("An error occurred during analysis. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetGame = () => {
    gameEngine.resetGame();
    setGameResult(null);
    setShowCompletion(false);
    toast.success("Game progress has been reset.");
  };

  const handleClaimCertificate = () => {
    setShowCertificate(true);
  };

  const handleUseHint = () => {
    const currentLevel = gameEngine.getCurrentLevel();
    const hint = gameEngine.useHint(currentLevel.id);
    toast.info(hint);
  };

  const progress = gameEngine.getProgress();
  const gameState = gameEngine.getGameState();
  const currentLevel = gameEngine.getCurrentLevel();

  return (
    <div className="min-h-screen bg-gradient-to-br from-black via-gray-900 to-black text-terminal-green">
      <header className="container mx-auto px-4 py-6 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Zap className="h-6 w-6 text-terminal-green" />
          <div className="text-xl font-bold">{config.app.name}</div>
          <Badge variant="secondary" className="uppercase text-xs">v{config.app.version}</Badge>
        </div>

        <div className="flex items-center gap-4">
          <a href={config.social.linktree} target="_blank" rel="noopener noreferrer" className="hover:text-gray-400 transition-colors">
            <Globe className="h-5 w-5" />
          </a>
          <a href={config.social.instagram} target="_blank" rel="noopener noreferrer" className="hover:text-gray-400 transition-colors">
            <Instagram className="h-5 w-5" />
          </a>
          <a href={config.social.tiktok} target="_blank" rel="noopener noreferrer" className="hover:text-gray-400 transition-colors">
            <MessageCircle className="h-5 w-5" />
          </a>
          <a href={config.social.linkedin} target="_blank" rel="noopener noreferrer" className="hover:text-gray-400 transition-colors">
            <Linkedin className="h-5 w-5" />
          </a>
          <a href={`mailto:${config.social.email}`} className="hover:text-gray-400 transition-colors">
            <Mail className="h-5 w-5" />
          </a>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8 space-y-8">
        {/* Game Mode Toggle */}
        <Card className="border-terminal-green/20 bg-black/40 backdrop-blur-sm">
          <CardHeader className="pb-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <CardTitle className="text-terminal-green flex items-center gap-2 text-lg sm:text-xl">
                  <Gamepad2 className="h-5 w-5 sm:h-6 sm:w-6" />
                  Training Mode
                </CardTitle>
                <CardDescription className="text-gray-400 text-sm sm:text-base">
                  Switch between guided training and free exploration
                </CardDescription>
              </div>
              <div className="flex items-center space-x-3">
                <Label htmlFor="game-mode" className="text-sm font-medium text-gray-300">
                  {isGameMode ? 'Structured Training' : 'Free Mode'}
                </Label>
                <Switch
                  id="game-mode"
                  checked={isGameMode}
                  onCheckedChange={setIsGameMode}
                  className="data-[state=checked]:bg-terminal-green"
                />
              </div>
            </div>
          </CardHeader>
        </Card>

        {/* Game Header */}
        {isGameMode && (
          <GameHeader 
            gameState={gameState}
            currentLevel={currentLevel}
            onUseHint={handleUseHint}
            onResetGame={handleResetGame}
          />
        )}

        {/* Input Section */}
        <Card className="border-terminal-green/20 bg-black/40 backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="text-terminal-green flex items-center gap-2">
              <Terminal className="h-5 w-6" />
              {isGameMode ? 'Jailbreak Attempt' : 'Security Analysis Input'}
            </CardTitle>
            <CardDescription className="text-gray-400">
              {isGameMode 
                ? 'Craft your prompt to complete the current level objective'
                : 'Enter any text to analyze for potential security threats and vulnerabilities'
              }
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Textarea
              placeholder={isGameMode 
                ? "Enter your jailbreak prompt here..." 
                : "Enter text to analyze for security threats..."
              }
              value={input}
              onChange={(e) => setInput(e.target.value)}
              className="min-h-[120px] bg-black/50 border-terminal-green/30 text-terminal-green placeholder:text-gray-500 font-mono text-sm resize-none focus:border-terminal-green/60 focus:ring-1 focus:ring-terminal-green/30"
            />
            <div className="flex flex-col sm:flex-row gap-3">
              <Button
                onClick={handleSubmit}
                disabled={isLoading}
                className="flex-1 sm:flex-none bg-terminal-green text-black hover:bg-terminal-green/80 font-medium px-6 py-2"
              >
                {isLoading ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-black mr-2"></div>
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Shield className="mr-2 h-4 w-4" />
                    {isGameMode ? 'Submit Attempt' : 'Analyze Security'}
                  </>
                )}
              </Button>
              <Button
                variant="outline"
                onClick={() => setInput('')}
                className="border-terminal-green/30 text-terminal-green hover:bg-terminal-green/10 px-4 py-2"
              >
                Clear
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Results Section */}
        {sanitizationResult && (
          <div className="space-y-6">
            {isGameMode && gameResult && (
              <GameResults result={gameResult} />
            )}
            
            <Tabs defaultValue="output" className="space-y-4">
              <TabsList className="grid w-full grid-cols-2 bg-black/40 border border-terminal-green/20">
                <TabsTrigger 
                  value="output" 
                  className="data-[state=active]:bg-terminal-green data-[state=active]:text-black text-terminal-green"
                >
                  Analysis Results
                </TabsTrigger>
                <TabsTrigger 
                  value="issues" 
                  className="data-[state=active]:bg-terminal-green data-[state=active]:text-black text-terminal-green"
                >
                  Security Issues ({sanitizationResult.issues.length})
                </TabsTrigger>
              </TabsList>

              <TabsContent value="output" className="space-y-4">
                <OutputDisplay result={sanitizationResult} />
              </TabsContent>

              <TabsContent value="issues" className="space-y-4">
                <IssuesList issues={sanitizationResult.issues} expertMode={false} />
              </TabsContent>
            </Tabs>
          </div>
        )}

        {/* Leaderboard and Statistics */}
        {config.features.leaderboard && (
          <Leaderboard />
        )}

        {/* Completion Dialog */}
        <CompletionDialog 
          open={showCompletion} 
          onOpenChange={setShowCompletion}
          gameState={gameState}
          onReset={handleResetGame}
        />

        {/* Certificate Dialog */}
        {config.features.certificates && (
          <Certificate 
            open={showCertificate} 
            onOpenChange={setShowCertificate}
            gameState={gameState}
          />
        )}
      </main>

      {/* Security Monitor */}
      <SecurityMonitor />

      {/* Footer */}
      <footer className="border-t border-terminal-green/20 bg-black/40 backdrop-blur-sm py-8 mt-16">
        <div className="container mx-auto px-4 text-center text-gray-500 text-sm">
          <p>
            Advanced AI Security Training Simulator
            <br />
            Created by <a href={config.social.linktree} target="_blank" rel="noopener noreferrer" className="text-terminal-green hover:underline">LittleHakr</a>
          </p>
          <Separator className="my-4 bg-terminal-green/20" />
          <div className="flex items-center justify-center space-x-4">
            {isGameMode && (
              <>
                <Button variant="secondary" size="sm" onClick={handleUseHint} className="gap-2">
                  <MessageCircle className="h-4 w-4" />
                  Use Hint
                </Button>
                <Button variant="destructive" size="sm" onClick={handleResetGame} className="gap-2">
                  <Terminal className="h-4 w-4" />
                  Reset Game
                </Button>
              </>
            )}
            {gameState.completedAt && config.features.certificates && (
              <Button variant="outline" size="sm" onClick={handleClaimCertificate} className="gap-2">
                <Award className="h-4 w-4" />
                Claim Certificate
              </Button>
            )}
          </div>
          <p className="mt-4">
            <ExternalLink className="h-3 w-3 inline-block mr-1 align-text-bottom" />
            <a href="https://github.com/little-hakr/llm-sanitizer-59" target="_blank" rel="noopener noreferrer" className="text-terminal-green hover:underline">
              Open Source on GitHub
            </a>
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Index;
