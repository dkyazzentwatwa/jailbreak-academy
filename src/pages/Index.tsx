import { useState, useEffect } from "react";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Shield, Zap, BarChart3, AlertTriangle, CheckCircle, Clock, Scan } from "lucide-react";
import { sanitizationEngine } from "@/lib/sanitization-engine";
import { SanitizationResult } from "@/types/sanitization";
import { OutputDisplay } from "@/components/OutputDisplay";
import { IssuesList } from "@/components/IssuesList";
import { SeverityBadge } from "@/components/SeverityBadge";
import { TerminalEffects } from "@/components/TerminalEffects";
import { toast } from "sonner";

const Index = () => {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<SanitizationResult | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [expertMode, setExpertMode] = useState(false);
  const [showBootAnimation, setShowBootAnimation] = useState(true);

  // Hide boot animation after 3 seconds
  useEffect(() => {
    const timer = setTimeout(() => setShowBootAnimation(false), 3000);
    return () => clearTimeout(timer);
  }, []);

  const handleSanitize = async () => {
    if (!input.trim()) {
      toast.error("Please enter some content to analyze");
      return;
    }

    console.log("Starting sanitization process...");
    setIsProcessing(true);
    
    try {
      console.log("Calling sanitizationEngine.sanitize...");
      const sanitizationResult = await sanitizationEngine.sanitize(input);
      console.log("Sanitization complete:", sanitizationResult);
      setResult(sanitizationResult);
      
      // Show appropriate toast based on severity
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
    } catch (error) {
      console.error('Sanitization error:', error);
      toast.error("An error occurred during analysis. Please try again.");
    } finally {
      console.log("Setting isProcessing to false");
      setIsProcessing(false);
    }
  };

  // Get security metrics
  const metrics = sanitizationEngine['securityMonitor']?.getMetrics() || {
    totalScans: 0,
    threatsBlocked: 0,
    falsePositives: 0,
    lastScanTime: 0
  };

  return (
    <div className="min-h-screen bg-terminal-bg text-terminal-green font-mono relative terminal-flicker">
      <TerminalEffects />
      
      {/* Boot sequence overlay */}
      {showBootAnimation && (
        <div className="fixed inset-0 bg-terminal-bg z-50 flex items-center justify-center terminal-boot">
          <div className="text-center">
            <div className="text-4xl font-bold text-terminal-green mb-4 pulse-glow">
              AI_GUARDIAN
            </div>
            <div className="typewriter text-lg">
              Initializing security protocols...
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
            <h1 className="text-2xl font-bold text-terminal-green terminal-green-glow">AI_GUARDIAN</h1>
            <Badge variant="outline" className="bg-terminal-green/20 text-terminal-green border-terminal-green/50 pulse-glow">
              v2.0
            </Badge>
          </div>
          <p className="text-muted-foreground text-sm typewriter">
            // Advanced threat detection and content sanitization engine
          </p>
          <div className="mt-4 flex items-center gap-6 text-xs data-stream">
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
        </div>
      </div>

      <div className="container mx-auto px-4 py-8 relative z-10">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Input Section */}
          <div className="space-y-4">
            <Card className="border-terminal-green/30 bg-card pulse-glow">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-mono text-terminal-green flex items-center gap-2 terminal-green-glow">
                    <Zap className="h-4 w-4" />
                    INPUT_ANALYZER
                  </CardTitle>
                  <div className="flex items-center space-x-2">
                    <Switch
                      id="expert-mode"
                      checked={expertMode}
                      onCheckedChange={setExpertMode}
                    />
                    <Label htmlFor="expert-mode" className="text-xs font-mono">
                      EXPERT_MODE
                    </Label>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="relative">
                  <Textarea
                    placeholder="// Enter content to analyze for security threats..."
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    className="min-h-[300px] font-mono text-sm bg-terminal-bg border-terminal-green/30 text-terminal-green placeholder:text-muted-foreground resize-none data-stream"
                  />
                  {isProcessing && (
                    <div className="absolute inset-0 bg-terminal-bg/90 flex items-center justify-center">
                      <div className="text-center">
                        <div className="text-terminal-green font-mono text-lg glitch mb-4">
                          SCANNING FOR THREATS...
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
                <div className="flex items-center gap-2">
                  <Button 
                    onClick={handleSanitize}
                    disabled={isProcessing || !input.trim()}
                    className="font-mono bg-terminal-green text-terminal-bg hover:bg-terminal-green/80 pulse-glow"
                  >
                    {isProcessing ? (
                      <>
                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-terminal-bg mr-2" />
                        SCANNING...
                      </>
                    ) : (
                      <>
                        <Shield className="h-4 w-4 mr-2" />
                        ANALYZE_THREATS
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

            {/* Security Metrics */}
            <Card className="border-terminal-green/30 bg-card">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-mono text-terminal-green flex items-center gap-2 terminal-green-glow">
                  <BarChart3 className="h-4 w-4" />
                  SECURITY_METRICS
                </CardTitle>
              </CardHeader>
              <CardContent>
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
              </CardContent>
            </Card>
          </div>

          {/* Results Section */}
          <div className="space-y-4">
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
                        SCAN_SUMMARY
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
                      SANITIZED_OUTPUT
                    </TabsTrigger>
                    <TabsTrigger value="issues" className="font-mono text-xs">
                      THREAT_ANALYSIS
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
                    // Ready to analyze content for security threats
                  </p>
                  <p className="text-muted-foreground font-mono text-xs mt-2">
                    Enter content above and click ANALYZE_THREATS to begin
                  </p>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Index;
