import { useState, useEffect } from "react";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Shield, Zap, BarChart3, AlertTriangle, CheckCircle, Clock, Scan, Mail, Instagram, ExternalLink, Play, Pause } from "lucide-react";
import { sanitizationEngine } from "@/lib/sanitization-engine";
import { gameEngine } from "@/lib/game-engine";
import { SanitizationResult } from "@/types/sanitization";
import { GameState, GameLevel } from "@/types/game";
import { OutputDisplay } from "@/components/OutputDisplay";
import { IssuesList } from "@/components/IssuesList";
import { SeverityBadge } from "@/components/SeverityBadge";
import { TerminalEffects } from "@/components/TerminalEffects";
import { GameHeader } from "@/components/GameHeader";
import { GameResults } from "@/components/GameResults";
import { Leaderboard } from "@/components/Leaderboard";
import { toast } from "sonner";
import { storageService } from "@/lib/storage";
import { config } from "@/lib/config";
import { rateLimiter } from "@/lib/rate-limiter";

const Index = () => {
  // Load user preferences
  const preferences = storageService.loadPreferences();
  
  const [input, setInput] = useState("");
  const [result, setResult] = useState<SanitizationResult | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [expertMode, setExpertMode] = useState(preferences.expertMode);
  const [showBootAnimation, setShowBootAnimation] = useState(true);
  const [gameMode, setGameMode] = useState(preferences.gameMode);
  const [gameState, setGameState] = useState<GameState>(gameEngine.getGameState());
  const [currentLevel, setCurrentLevel] = useState<GameLevel>(gameEngine.getCurrentLevel());
  const [gameResult, setGameResult] = useState<any>(null);
  const [currentHint, setCurrentHint] = useState<string>("");

  // Hide boot animation after 3 seconds
  useEffect(() => {
    const timer = setTimeout(() => setShowBootAnimation(false), 3000);
    return () => clearTimeout(timer);
  }, []);

  // Start the game
  useEffect(() => {
    if (gameMode) {
      gameEngine.startGame();
      setGameState(gameEngine.getGameState());
      setCurrentLevel(gameEngine.getCurrentLevel());
    }
  }, [gameMode]);

  const handleSanitize = async () => {
    if (!input.trim()) {
      toast.error("Please enter some content to analyze");
      return;
    }

    // Check rate limit
    if (!rateLimiter.checkLimit('sanitize')) {
      const status = rateLimiter.getRemainingAttempts('sanitize');
      toast.error(`Rate limit exceeded. Please wait ${rateLimiter.formatTime(status.resetIn)} before trying again.`);
      return;
    }

    console.log("Starting sanitization process...");
    setIsProcessing(true);
    setGameResult(null);
    
    try {
      const sanitizationResult = await sanitizationEngine.sanitize(input);
      setResult(sanitizationResult);
      
      if (gameMode) {
        const attemptResult = gameEngine.evaluateAttempt(input, sanitizationResult);
        setGameResult(attemptResult);
        setGameState(gameEngine.getGameState());
        setCurrentLevel(gameEngine.getCurrentLevel());
        
        if (attemptResult.success) {
          toast.success(`🎯 Level ${currentLevel.id} completed!`);
        } else {
          toast.error(attemptResult.message);
        }
      } else {
        // Original functionality
        switch (sanitizationResult.severity) {
          case 'critical':
            toast.error(`Critical threats detected and neutralized!`);
            break;
          case 'high':
            toast.error(`High severity threats detected and neutralized!`);
            break;
          case 'moderate':
            toast.warning(`${sanitizationResult.issues.length} potential issues found and handled`);
            break;
          case 'low':
            toast.info(`${sanitizationResult.issues.length} minor issues cleaned up`);
            break;
          default:
            toast.success("Content appears safe - no threats detected");
        }
      }
    } catch (error) {
      console.error('Sanitization error:', error);
      toast.error("An error occurred during analysis. Please try again.");
    } finally {
      setIsProcessing(false);
    }
  };

  const handleUseHint = () => {
    // Check rate limit for hints
    if (!rateLimiter.checkLimit('hint')) {
      const status = rateLimiter.getRemainingAttempts('hint');
      toast.error(`Too many hint requests. Please wait ${rateLimiter.formatTime(status.resetIn)}.`);
      return;
    }
    
    const hint = gameEngine.useHint(currentLevel.id);
    setCurrentHint(hint);
    setGameState(gameEngine.getGameState());
    toast.info(`💡 Hint: ${hint}`);
  };

  const handleResetGame = () => {
    gameEngine.resetGame();
    setGameState(gameEngine.getGameState());
    setCurrentLevel(gameEngine.getCurrentLevel());
    setResult(null);
    setGameResult(null);
    setInput("");
    setCurrentHint("");
    toast.success("🔄 Game reset - Ready for new training session");
  };

  // Get security metrics
  const metrics = sanitizationEngine['securityMonitor']?.getMetrics() || {
    totalScans: 0,
    threatsBlocked: 0,
    falsePositives: 0,
    lastScanTime: 0
  };

  const socialLinks = [
    { name: "Email", icon: Mail, url: "mailto:littlehakr@protonmail.com", label: "email" },
    { name: "Instagram", icon: Instagram, url: "https://www.instagram.com/little_hakr/", label: "IG" },
    { name: "TikTok", icon: ExternalLink, url: "https://www.tiktok.com/@littlehakr", label: "TikTok" },
    { name: "LinkTree", icon: ExternalLink, url: "https://linktr.ee/littlehakr", label: "website" },
    { name: "LinkedIn", icon: ExternalLink, url: "https://www.linkedin.com/in/david-kyazze-ntwatwa", label: "linkedin" }
  ];

  return (
    <div className="min-h-screen bg-terminal-bg text-terminal-green font-mono relative terminal-flicker">
      <TerminalEffects />
      
      {/* Boot sequence overlay */}
      {showBootAnimation && (
        <div className="fixed inset-0 bg-terminal-bg z-50 flex items-center justify-center terminal-boot">
          <div className="text-center">
            <div className="text-4xl font-bold text-terminal-green mb-4 pulse-glow">
              {gameMode ? "JAILBREAK_TRAINING" : "AI_GUARDIAN"}
            </div>
            <div className="typewriter text-lg">
              {gameMode ? "Loading training simulation..." : "Initializing security protocols..."}
            </div>
            <div className="mt-4 flex justify-center">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-terminal-green"></div>
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <div className="border-b border-terminal-green/30 bg-card relative z-10">
        <div className="container mx-auto px-4 py-6">
          <div className="flex items-center gap-3 mb-2">
            <Shield className="h-8 w-8 text-terminal-green pulse-glow" />
            <h1 className="text-2xl font-bold text-terminal-green terminal-green-glow">
              {gameMode ? "JAILBREAK_TRAINING" : "AI_GUARDIAN"}
            </h1>
            <div className="flex items-center space-x-2">
              <Switch
                id="game-mode"
                checked={gameMode}
                onCheckedChange={(checked) => {
                  setGameMode(checked);
                  storageService.savePreferences({
                    ...preferences,
                    gameMode: checked,
                  });
                }}
              />
              <Label htmlFor="game-mode" className="text-xs font-mono">
                {gameMode ? "TRAINING" : "SECURITY"}
              </Label>
            </div>
            <Badge variant="outline" className="bg-terminal-green/20 text-terminal-green border-terminal-green/50 pulse-glow">
              {gameMode ? "GAME_MODE" : "v2.0"}
            </Badge>
          </div>
          <p className="text-muted-foreground text-sm typewriter mb-4">
            {gameMode 
              ? "// 20-level jailbreaking certification program for cybersecurity professionals"
              : "// Advanced threat detection and content sanitization engine"
            }
          </p>
          
          {/* Social Media Links */}
          <div className="absolute top-4 right-4 flex items-center gap-4">
            {socialLinks.map((link, index) => (
              <a
                key={index}
                href={link.url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-terminal-green transition-colors duration-200 pulse-glow hover:terminal-green-glow"
              >
                <link.icon className="h-5 w-5" />
              </a>
            ))}
          </div>

          {!gameMode && (
            <div className="flex items-center gap-6 text-xs data-stream">
              <div className="flex items-center gap-2">
                <Scan className="h-4 w-4" />
                <span>Scans: {metrics.totalScans}</span>
              </div>
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-red-400" />
                <span>Threats Blocked: {metrics.threatsBlocked}</span>
              </div>
              <div className="flex items-center gap-2">
                <Clock className="h-4 w-4" />
                <span>Last Scan: {metrics.lastScanTime ? new Date(metrics.lastScanTime).toLocaleTimeString() : 'Never'}</span>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="container mx-auto px-4 py-8 relative z-10">
        {gameMode && (
          <div className="mb-6">
            <GameHeader
              gameState={gameState}
              currentLevel={currentLevel}
              onUseHint={handleUseHint}
              onResetGame={handleResetGame}
            />
          </div>
        )}

        <div className={`grid grid-cols-1 ${gameMode && config.features.leaderboard ? 'lg:grid-cols-3' : 'lg:grid-cols-2'} gap-6`}>
          {/* Input Section */}
          <div className="space-y-4">
            <Card className="border-terminal-green/30 bg-card pulse-glow">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-mono text-terminal-green flex items-center gap-2 terminal-green-glow">
                    <Zap className="h-4 w-4" />
                    {gameMode ? "JAILBREAK_ATTEMPT" : "OUTPUT_ANALYZER"}
                  </CardTitle>
                  {!gameMode && (
                    <div className="flex items-center space-x-2">
                      <Switch
                        id="expert-mode"
                        checked={expertMode}
                        onCheckedChange={(checked) => {
                          setExpertMode(checked);
                          storageService.savePreferences({
                            ...preferences,
                            expertMode: checked,
                          });
                        }}
                      />
                      <Label htmlFor="expert-mode" className="text-xs font-mono">
                        EXPERT_MODE
                      </Label>
                    </div>
                  )}
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="relative">
                  <Textarea
                    placeholder={gameMode 
                      ? "// Enter your jailbreak attempt here..."
                      : "// Enter content to analyze for security threats..."
                    }
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    className="min-h-[300px] font-mono text-sm bg-terminal-bg border-terminal-green/30 text-terminal-green placeholder:text-muted-foreground resize-none data-stream"
                  />
                  {isProcessing && (
                    <div className="absolute inset-0 bg-terminal-bg/90 flex items-center justify-center">
                      <div className="text-center">
                        <div className="text-terminal-green font-mono text-lg glitch mb-4">
                          {gameMode ? "ANALYZING JAILBREAK..." : "SCANNING FOR THREATS..."}
                        </div>
                        <div className="flex justify-center space-x-1">
                          {Array.from({ length: 5 }).map((_, i) => (
                            <div
                              key={i}
                              className="w-2 h-2 bg-terminal-green rounded-full animate-pulse"
                              style={{
                                animationDelay: `${i * 0.1}s`,
                                animationDuration: '1s'
                              }}
                            />
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
                
                {currentHint && (
                  <div className="p-3 rounded border border-terminal-green/20 bg-terminal-bg">
                    <p className="text-xs font-mono text-terminal-green">
                      💡 HINT: {currentHint}
                    </p>
                  </div>
                )}
                
                <div className="flex items-center gap-2">
                  <Button 
                    onClick={handleSanitize}
                    disabled={isProcessing || !input.trim()}
                    className="font-mono bg-terminal-green text-terminal-bg hover:bg-terminal-green/80 pulse-glow"
                  >
                    {isProcessing ? (
                      <>
                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-terminal-bg mr-2" />
                        {gameMode ? "EXECUTING..." : "SCANNING..."}
                      </>
                    ) : (
                      <>
                        <Shield className="h-4 w-4 mr-2" />
                        {gameMode ? "EXECUTE_JAILBREAK" : "ANALYZE_THREATS"}
                      </>
                    )}
                  </Button>
                  {input.length > 0 && (
                    <Badge variant="outline" className="font-mono text-xs animate-pulse">
                      {input.length.toLocaleString()} chars
                    </Badge>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Security Metrics / Game Stats */}
            <Card className="border-terminal-green/30 bg-card">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-mono text-terminal-green flex items-center gap-2 terminal-green-glow">
                  <BarChart3 className="h-4 w-4" />
                  {gameMode ? "TRAINING_STATS" : "SECURITY_METRICS"}
                </CardTitle>
              </CardHeader>
              <CardContent>
                {gameMode ? (
                  <div className="grid grid-cols-3 gap-4 text-center">
                    <div className="space-y-1 data-stream">
                      <div className="text-2xl font-bold font-mono text-terminal-green terminal-green-glow">
                        {gameState.currentLevel}
                      </div>
                      <div className="text-xs text-muted-foreground font-mono">
                        CURRENT_LEVEL
                      </div>
                    </div>
                    <div className="space-y-1">
                      <div className="text-2xl font-bold font-mono text-terminal-green glitch">
                        {gameState.score.toLocaleString()}
                      </div>
                      <div className="text-xs text-muted-foreground font-mono">
                        TOTAL_SCORE
                      </div>
                    </div>
                    <div className="space-y-1">
                      <div className="text-2xl font-bold font-mono text-terminal-green">
                        {gameState.levelProgress.filter(p => p.completed).length}
                      </div>
                      <div className="text-xs text-muted-foreground font-mono">
                        COMPLETED
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="grid grid-cols-3 gap-4 text-center">
                    <div className="space-y-1 data-stream">
                      <div className="text-2xl font-bold font-mono text-terminal-green terminal-green-glow">
                        {metrics.totalScans}
                      </div>
                      <div className="text-xs text-muted-foreground font-mono">
                        TOTAL_SCANS
                      </div>
                    </div>
                    <div className="space-y-1">
                      <div className="text-2xl font-bold font-mono text-red-400 glitch">
                        {metrics.threatsBlocked}
                      </div>
                      <div className="text-xs text-muted-foreground font-mono">
                        THREATS_BLOCKED
                      </div>
                    </div>
                    <div className="space-y-1">
                      <div className="text-2xl font-bold font-mono text-terminal-green">
                        {result?.processingTime || 0}<span className="text-xs">ms</span>
                      </div>
                      <div className="text-xs text-muted-foreground font-mono">
                        LAST_SCAN_TIME
                      </div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Results Section */}
          <div className="space-y-4">
            {gameResult && (
              <GameResults result={gameResult} />
            )}

            {result && (
              <>
                {/* Summary Card */}
                <Card className={`border-terminal-green/30 bg-card ${
                  result.severity === 'critical' ? 'threat-detected glitch' : 
                  result.severity !== 'none' ? 'pulse-glow' : ''
                }`}>
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-sm font-mono text-terminal-green flex items-center gap-2 terminal-green-glow">
                        <CheckCircle className="h-4 w-4" />
                        {gameMode ? "JAILBREAK_ANALYSIS" : "SCAN_SUMMARY"}
                      </CardTitle>
                      <SeverityBadge severity={result.severity} />
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-muted-foreground">ISSUES_DETECTED:</span>
                      <span className={`text-terminal-green ${result.issues.length > 0 ? 'glitch' : ''}`}>
                        {result.issues.length}
                      </span>
                    </div>
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-muted-foreground">PROCESSING_TIME:</span>
                      <span className="text-terminal-green">{result.processingTime}ms</span>
                    </div>
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-muted-foreground">STATUS:</span>
                      <span className={result.severity === 'none' ? 'text-terminal-green' : 'text-red-400 glitch'}>
                        {result.severity === 'none' ? 'SAFE' : 'THREATS_FOUND'}
                      </span>
                    </div>
                    {result.guidance && (
                      <div className="mt-3 p-3 rounded border border-terminal-green/20 bg-terminal-bg data-stream">
                        <p className="text-xs font-mono text-muted-foreground">
                          {result.guidance}
                        </p>
                      </div>
                    )}
                  </CardContent>
                </Card>

                {/* Tabbed Results */}
                <Tabs defaultValue="output" className="w-full">
                  <TabsList className="grid w-full grid-cols-2 bg-card border border-terminal-green/30">
                    <TabsTrigger value="output" className="font-mono text-xs">
                      {gameMode ? "EXECUTION_OUTPUT" : "SANITIZED_OUTPUT"}
                    </TabsTrigger>
                    <TabsTrigger value="issues" className="font-mono text-xs">
                      {gameMode ? "VULNERABILITY_ANALYSIS" : "THREAT_ANALYSIS"}
                      {result.issues.length > 0 && (
                        <Badge variant="outline" className="ml-2 bg-red-900/50 text-red-200 border-red-500/50 glitch">
                          {result.issues.length}
                        </Badge>
                      )}
                    </TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="output" className="mt-4">
                    <div className="space-y-4">
                      <OutputDisplay content={input} type="original" />
                      <OutputDisplay content={result.sanitizedOutput} type="sanitized" />
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="issues" className="mt-4">
                    <IssuesList issues={result.issues} expertMode={expertMode} />
                  </TabsContent>
                </Tabs>
              </>
            )}

            {!result && (
              <Card className="border-terminal-green/30 bg-card pulse-glow">
                <CardContent className="p-8 text-center">
                  <Shield className="h-12 w-12 mx-auto mb-4 text-terminal-green/50 pulse-glow" />
                  <p className="text-muted-foreground font-mono text-sm typewriter">
                    {gameMode 
                      ? "// Ready to test your jailbreaking skills"
                      : "// Ready to analyze content for security threats"
                    }
                  </p>
                  <p className="text-muted-foreground font-mono text-xs mt-2">
                    {gameMode 
                      ? "Craft your jailbreak attempt and click EXECUTE_JAILBREAK"
                      : "Enter content above and click ANALYZE_THREATS to begin"
                    }
                  </p>
                </CardContent>
              </Card>
            )}
          </div>

          {/* Leaderboard Section - Only in game mode */}
          {gameMode && config.features.leaderboard && (
            <div className="space-y-4">
              <Leaderboard />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Index;
