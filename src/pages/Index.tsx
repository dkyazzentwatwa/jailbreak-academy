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
          <div className="text-center px-4">
            <div className="text-xl md:text-4xl font-bold text-terminal-green mb-4 pulse-glow">
              {gameMode ? "JAILBREAK_TRAINING" : "AI_GUARDIAN"}
            </div>
            <div className="typewriter text-xs md:text-lg">
              {gameMode ? "Loading training simulation..." : "Initializing security protocols..."}
            </div>
            <div className="mt-4 flex justify-center">
              <div className="animate-spin rounded-full h-6 w-6 md:h-8 md:w-8 border-b-2 border-terminal-green"></div>
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <div className="border-b border-terminal-green/30 bg-card relative z-10">
        <div className="container mx-auto px-3 md:px-4 py-3 md:py-6">
          <div className="flex flex-col gap-2 mb-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Shield className="h-5 w-5 md:h-8 md:w-8 text-terminal-green pulse-glow flex-shrink-0" />
                <h1 className="text-sm md:text-2xl font-bold text-terminal-green terminal-green-glow">
                  {gameMode ? "JAILBREAK_TRAINING" : "AI_GUARDIAN"}
                </h1>
                <Badge variant="outline" className="bg-terminal-green/20 text-terminal-green border-terminal-green/50 pulse-glow text-xs px-1">
                  {gameMode ? "GAME" : "v2.0"}
                </Badge>
              </div>
              
              {/* Social Media Links - Smaller on mobile */}
              <div className="flex items-center gap-1 md:gap-3">
                {socialLinks.slice(0, 3).map((link, index) => (
                  <a
                    key={index}
                    href={link.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-muted-foreground hover:text-terminal-green transition-colors duration-200 pulse-glow hover:terminal-green-glow"
                    title={link.name}
                  >
                    <link.icon className="h-3 w-3 md:h-5 md:w-5" />
                  </a>
                ))}
              </div>
            </div>

            {/* Game mode toggle - moved to second row on mobile */}
            <div className="flex items-center justify-between">
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
            </div>
          </div>
          
          <p className="text-muted-foreground text-xs leading-tight mb-3">
            {gameMode 
              ? "// 20-level jailbreaking certification program"
              : "// Advanced threat detection and content sanitization engine"
            }
          </p>

          {!gameMode && (
            <div className="grid grid-cols-3 gap-2 text-xs data-stream">
              <div className="flex flex-col items-center">
                <Scan className="h-3 w-3 mb-1" />
                <span className="text-center">Scans: {metrics.totalScans}</span>
              </div>
              <div className="flex flex-col items-center">
                <AlertTriangle className="h-3 w-3 mb-1 text-red-400" />
                <span className="text-center">Threats: {metrics.threatsBlocked}</span>
              </div>
              <div className="flex flex-col items-center">
                <Clock className="h-3 w-3 mb-1" />
                <span className="text-center">
                  {metrics.lastScanTime ? new Date(metrics.lastScanTime).toLocaleTimeString() : 'Never'}
                </span>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="container mx-auto px-3 md:px-4 py-4 md:py-8 relative z-10">
        {gameMode && (
          <div className="mb-4">
            <GameHeader
              gameState={gameState}
              currentLevel={currentLevel}
              onUseHint={handleUseHint}
              onResetGame={handleResetGame}
            />
          </div>
        )}

        <div className="space-y-4 lg:space-y-0 lg:grid lg:grid-cols-2 lg:gap-6 xl:grid-cols-3">
          {/* Input Section - Full width on mobile */}
          <div className="space-y-3 lg:space-y-4">
            <Card className="border-terminal-green/30 bg-card pulse-glow">
              <CardHeader className="pb-2 px-3 pt-3">
                <div className="flex flex-col gap-2">
                  <CardTitle className="text-xs md:text-sm font-mono text-terminal-green flex items-center gap-2 terminal-green-glow">
                    <Zap className="h-3 w-3 md:h-4 md:w-4" />
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
              <CardContent className="space-y-3 px-3 pb-3">
                <div className="relative">
                  <Textarea
                    placeholder={gameMode 
                      ? "// Enter your jailbreak attempt here..."
                      : "// Enter content to analyze for security threats..."
                    }
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    className="min-h-[150px] md:min-h-[300px] font-mono text-xs md:text-sm bg-terminal-bg border-terminal-green/30 text-terminal-green placeholder:text-muted-foreground resize-none data-stream"
                  />
                  {isProcessing && (
                    <div className="absolute inset-0 bg-terminal-bg/90 flex items-center justify-center">
                      <div className="text-center px-4">
                        <div className="text-terminal-green font-mono text-xs md:text-lg glitch mb-4">
                          {gameMode ? "ANALYZING JAILBREAK..." : "SCANNING FOR THREATS..."}
                        </div>
                        <div className="flex justify-center space-x-1">
                          {Array.from({ length: 5 }).map((_, i) => (
                            <div
                              key={i}
                              className="w-1 h-1 md:w-2 md:h-2 bg-terminal-green rounded-full animate-pulse"
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
                  <div className="p-2 md:p-3 rounded border border-terminal-green/20 bg-terminal-bg">
                    <p className="text-xs font-mono text-terminal-green break-words">
                      💡 HINT: {currentHint}
                    </p>
                  </div>
                )}
                
                <div className="flex flex-col gap-2">
                  <Button 
                    onClick={handleSanitize}
                    disabled={isProcessing || !input.trim()}
                    className="font-mono bg-terminal-green text-terminal-bg hover:bg-terminal-green/80 pulse-glow w-full text-xs md:text-sm h-8 md:h-10"
                  >
                    {isProcessing ? (
                      <>
                        <div className="animate-spin rounded-full h-3 w-3 md:h-4 md:w-4 border-b-2 border-terminal-bg mr-2" />
                        {gameMode ? "EXECUTING..." : "SCANNING..."}
                      </>
                    ) : (
                      <>
                        <Shield className="h-3 w-3 md:h-4 md:w-4 mr-2" />
                        {gameMode ? "EXECUTE" : "ANALYZE"}
                      </>
                    )}
                  </Button>
                  {input.length > 0 && (
                    <div className="flex justify-center">
                      <Badge variant="outline" className="font-mono text-xs animate-pulse">
                        {input.length.toLocaleString()} chars
                      </Badge>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Security Metrics / Game Stats */}
            <Card className="border-terminal-green/30 bg-card">
              <CardHeader className="pb-2 px-3 pt-3">
                <CardTitle className="text-xs md:text-sm font-mono text-terminal-green flex items-center gap-2 terminal-green-glow">
                  <BarChart3 className="h-3 w-3 md:h-4 md:w-4" />
                  {gameMode ? "TRAINING_STATS" : "SECURITY_METRICS"}
                </CardTitle>
              </CardHeader>
              <CardContent className="px-3 pb-3">
                {gameMode ? (
                  <div className="grid grid-cols-3 gap-2 text-center">
                    <div className="space-y-1 data-stream">
                      <div className="text-lg md:text-2xl font-bold font-mono text-terminal-green terminal-green-glow">
                        {gameState.currentLevel}
                      </div>
                      <div className="text-xs text-muted-foreground font-mono">
                        LEVEL
                      </div>
                    </div>
                    <div className="space-y-1">
                      <div className="text-lg md:text-2xl font-bold font-mono text-terminal-green glitch">
                        {gameState.score.toLocaleString()}
                      </div>
                      <div className="text-xs text-muted-foreground font-mono">
                        SCORE
                      </div>
                    </div>
                    <div className="space-y-1">
                      <div className="text-lg md:text-2xl font-bold font-mono text-terminal-green">
                        {gameState.levelProgress.filter(p => p.completed).length}
                      </div>
                      <div className="text-xs text-muted-foreground font-mono">
                        DONE
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="grid grid-cols-3 gap-2 text-center">
                    <div className="space-y-1 data-stream">
                      <div className="text-lg md:text-2xl font-bold font-mono text-terminal-green terminal-green-glow">
                        {metrics.totalScans}
                      </div>
                      <div className="text-xs text-muted-foreground font-mono">
                        SCANS
                      </div>
                    </div>
                    <div className="space-y-1">
                      <div className="text-lg md:text-2xl font-bold font-mono text-red-400 glitch">
                        {metrics.threatsBlocked}
                      </div>
                      <div className="text-xs text-muted-foreground font-mono">
                        BLOCKED
                      </div>
                    </div>
                    <div className="space-y-1">
                      <div className="text-lg md:text-2xl font-bold font-mono text-terminal-green">
                        {result?.processingTime || 0}<span className="text-xs">ms</span>
                      </div>
                      <div className="text-xs text-muted-foreground font-mono">
                        TIME
                      </div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Results Section */}
          <div className="space-y-3 lg:space-y-4">
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
                  <CardHeader className="pb-2 px-3 pt-3">
                    <div className="flex flex-col gap-2">
                      <CardTitle className="text-xs md:text-sm font-mono text-terminal-green flex items-center gap-2 terminal-green-glow">
                        <CheckCircle className="h-3 w-3 md:h-4 md:w-4" />
                        {gameMode ? "JAILBREAK_ANALYSIS" : "SCAN_SUMMARY"}
                      </CardTitle>
                      <SeverityBadge severity={result.severity} />
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-2 px-3 pb-3">
                    <div className="grid grid-cols-3 gap-2 text-xs font-mono">
                      <div className="text-center">
                        <div className="text-muted-foreground">ISSUES</div>
                        <div className={`text-terminal-green ${result.issues.length > 0 ? 'glitch' : ''}`}>
                          {result.issues.length}
                        </div>
                      </div>
                      <div className="text-center">
                        <div className="text-muted-foreground">TIME</div>
                        <div className="text-terminal-green">{result.processingTime}ms</div>
                      </div>
                      <div className="text-center">
                        <div className="text-muted-foreground">STATUS</div>
                        <div className={result.severity === 'none' ? 'text-terminal-green' : 'text-red-400 glitch'}>
                          {result.severity === 'none' ? 'SAFE' : 'THREATS'}
                        </div>
                      </div>
                    </div>
                    {result.guidance && (
                      <div className="mt-2 p-2 rounded border border-terminal-green/20 bg-terminal-bg data-stream">
                        <p className="text-xs font-mono text-muted-foreground break-words">
                          {result.guidance}
                        </p>
                      </div>
                    )}
                  </CardContent>
                </Card>

                {/* Tabbed Results */}
                <Tabs defaultValue="output" className="w-full">
                  <TabsList className="grid w-full grid-cols-2 bg-card border border-terminal-green/30 h-8">
                    <TabsTrigger value="output" className="font-mono text-xs py-1">
                      OUTPUT
                    </TabsTrigger>
                    <TabsTrigger value="issues" className="font-mono text-xs py-1">
                      ANALYSIS
                      {result.issues.length > 0 && (
                        <Badge variant="outline" className="ml-1 bg-red-900/50 text-red-200 border-red-500/50 glitch text-xs px-1">
                          {result.issues.length}
                        </Badge>
                      )}
                    </TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="output" className="mt-3">
                    <div className="space-y-3">
                      <OutputDisplay content={input} type="original" />
                      <OutputDisplay content={result.sanitizedOutput} type="sanitized" />
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="issues" className="mt-3">
                    <IssuesList issues={result.issues} expertMode={expertMode} />
                  </TabsContent>
                </Tabs>
              </>
            )}

            {!result && (
              <Card className="border-terminal-green/30 bg-card pulse-glow">
                <CardContent className="p-4 md:p-8 text-center">
                  <Shield className="h-8 w-8 md:h-12 md:w-12 mx-auto mb-4 text-terminal-green/50 pulse-glow" />
                  <p className="text-muted-foreground font-mono text-xs md:text-sm typewriter break-words">
                    {gameMode 
                      ? "// Ready to test your jailbreaking skills"
                      : "// Ready to analyze content for security threats"
                    }
                  </p>
                  <p className="text-muted-foreground font-mono text-xs mt-2 break-words">
                    {gameMode 
                      ? "Craft your jailbreak attempt and click EXECUTE"
                      : "Enter content above and click ANALYZE to begin"
                    }
                  </p>
                </CardContent>
              </Card>
            )}
          </div>

          {/* Leaderboard Section - Only in game mode and hidden on mobile */}
          {gameMode && config.features.leaderboard && (
            <div className="hidden xl:block space-y-4">
              <Leaderboard />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Index;
