import { useState } from "react";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Shield, AlertTriangle, CheckCircle, Info, Eye, Code, FileText, Terminal, Zap, Download } from "lucide-react";
import { SanitizationEngine } from "@/lib/sanitization-engine";
import { SeverityLevel, SanitizationResult } from "@/types/sanitization";
import { SeverityBadge } from "@/components/SeverityBadge";
import { IssuesList } from "@/components/IssuesList";
import { OutputDisplay } from "@/components/OutputDisplay";
import jsPDF from 'jspdf';

const Index = () => {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<SanitizationResult | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [expertMode, setExpertMode] = useState(false);

  const handleSanitize = async () => {
    if (!input.trim()) return;

    setIsProcessing(true);
    
    try {
      // Simulate processing time for UX
      await new Promise(resolve => setTimeout(resolve, 800));
      
      const sanitizer = new SanitizationEngine();
      const sanitizationResult = sanitizer.sanitize(input);
      setResult(sanitizationResult);
    } catch (error) {
      console.error("Sanitization error:", error);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleExportPDF = () => {
    if (!result) return;

    const pdf = new jsPDF();
    const pageWidth = pdf.internal.pageSize.getWidth();
    const pageHeight = pdf.internal.pageSize.getHeight();
    let yPosition = 20;

    // Set font
    pdf.setFont('courier');

    // Title
    pdf.setFontSize(16);
    pdf.text('LLM SANITIZATION REPORT', pageWidth / 2, yPosition, { align: 'center' });
    yPosition += 20;

    // Timestamp
    pdf.setFontSize(10);
    pdf.text(`Generated: ${new Date().toLocaleString()}`, 20, yPosition);
    yPosition += 15;

    // Severity
    pdf.setFontSize(12);
    pdf.text(`SEVERITY: ${result.severity.toUpperCase()}`, 20, yPosition);
    yPosition += 10;

    // Issues count
    pdf.text(`ISSUES FOUND: ${result.issues.length}`, 20, yPosition);
    yPosition += 15;

    // Issues details
    if (result.issues.length > 0) {
      pdf.setFontSize(14);
      pdf.text('THREAT ANALYSIS:', 20, yPosition);
      yPosition += 10;

      result.issues.forEach((issue, index) => {
        if (yPosition > pageHeight - 40) {
          pdf.addPage();
          yPosition = 20;
        }

        pdf.setFontSize(10);
        pdf.text(`${index + 1}. [${issue.severity.toUpperCase()}] ${issue.type.toUpperCase()}`, 20, yPosition);
        yPosition += 7;
        
        const descLines = pdf.splitTextToSize(issue.description, pageWidth - 40);
        pdf.text(descLines, 25, yPosition);
        yPosition += descLines.length * 5 + 5;

        if (issue.recommendation) {
          const recLines = pdf.splitTextToSize(`Recommendation: ${issue.recommendation}`, pageWidth - 40);
          pdf.text(recLines, 25, yPosition);
          yPosition += recLines.length * 5 + 10;
        }
      });
    }

    // Add new page for output comparison
    pdf.addPage();
    yPosition = 20;

    pdf.setFontSize(14);
    pdf.text('SANITIZED OUTPUT:', 20, yPosition);
    yPosition += 15;

    pdf.setFontSize(8);
    const outputLines = pdf.splitTextToSize(result.sanitizedOutput || 'No output generated', pageWidth - 40);
    outputLines.forEach((line: string) => {
      if (yPosition > pageHeight - 20) {
        pdf.addPage();
        yPosition = 20;
      }
      pdf.text(line, 20, yPosition);
      yPosition += 5;
    });

    // Save the PDF
    pdf.save(`llm-sanitization-report-${Date.now()}.pdf`);
  };

  const getSeverityIcon = (severity: SeverityLevel) => {
    switch (severity) {
      case 'high':
        return <AlertTriangle className="h-5 w-5 text-red-400" />;
      case 'moderate':
        return <Info className="h-5 w-5 text-yellow-400" />;
      case 'low':
        return <AlertTriangle className="h-5 w-5 text-blue-400" />;
      default:
        return <CheckCircle className="h-5 w-5 text-terminal-green" />;
    }
  };

  const getSeverityMessage = (severity: SeverityLevel, issueCount: number) => {
    switch (severity) {
      case 'high':
        return `CRITICAL: Malicious payload detected and neutralized (${issueCount} threat${issueCount === 1 ? '' : 's'})`;
      case 'moderate':
        return `WARNING: Suspicious content found and sanitized (${issueCount} issue${issueCount === 1 ? '' : 's'})`;
      case 'low':
        return `INFO: Minor anomalies cleaned (${issueCount} issue${issueCount === 1 ? '' : 's'})`;
      default:
        return "STATUS: All systems green - output verified secure";
    }
  };

  return (
    <div className="min-h-screen bg-terminal-bg relative overflow-x-hidden">
      {/* Animated scan line */}
      <div className="scan-line" />
      
      {/* Matrix-style background pattern */}
      <div className="fixed inset-0 opacity-5 pointer-events-none">
        <div className="absolute inset-0" style={{
          backgroundImage: `radial-gradient(circle at 1px 1px, hsl(var(--terminal-green)) 1px, transparent 0)`,
          backgroundSize: '20px 20px'
        }} />
      </div>

      <div className="container mx-auto py-8 px-4 max-w-6xl relative z-10">
        {/* Terminal Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Terminal className="h-8 w-8 text-terminal-green terminal-green-glow" />
            <h1 className="text-4xl font-bold terminal-green-glow font-mono tracking-wider">
              LLM_SANITIZER_v2.1
            </h1>
            <Zap className="h-6 w-6 text-terminal-green animate-pulse" />
          </div>
          <div className="font-mono text-terminal-green text-sm mb-2">
            <span className="terminal-cursor">NEURAL_DEFENSE_PROTOCOL_ACTIVE</span>
          </div>
          <p className="text-muted-foreground max-w-2xl mx-auto font-mono text-sm leading-relaxed">
            [CLASSIFIED] Military-grade AI output sanitization system.
            <br />
            Neutralizes malicious code, prevents XSS attacks, eliminates injection vectors.
          </p>
        </div>

        {/* Mode Toggle and Export */}
        <div className="flex items-center justify-center gap-4 mb-6 font-mono">
          <Label htmlFor="expert-mode" className="text-terminal-green">[NOVICE_MODE]</Label>
          <Switch
            id="expert-mode"
            checked={expertMode}
            onCheckedChange={setExpertMode}
            className="data-[state=checked]:bg-terminal-green"
          />
          <Label htmlFor="expert-mode" className="text-terminal-green">[EXPERT_MODE]</Label>
          
          {result && (
            <Button
              onClick={handleExportPDF}
              variant="outline"
              size="sm"
              className="ml-8 border-terminal-green/50 text-terminal-green hover:bg-terminal-green/20 font-mono"
            >
              <Download className="h-4 w-4 mr-2" />
              EXPORT_PDF
            </Button>
          )}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Input Section */}
          <Card className="h-fit bg-card border-terminal-green/30 terminal-glow">
            <CardHeader className="border-b border-terminal-green/20">
              <CardTitle className="flex items-center gap-2 font-mono text-terminal-green">
                <FileText className="h-5 w-5" />
                INPUT_BUFFER
              </CardTitle>
              <CardDescription className="font-mono text-xs text-muted-foreground">
                // Paste potentially hostile AI output for analysis
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 pt-6">
              <Textarea
                placeholder=">>> PASTE_AI_OUTPUT_HERE
// WARNING: Treat all input as potentially malicious
// System will analyze for XSS, injections, exploits..."
                value={input}
                onChange={(e) => setInput(e.target.value)}
                className="min-h-[300px] font-mono text-sm resize-none bg-input border-terminal-green/30 text-terminal-green placeholder:text-muted-foreground focus:border-terminal-green focus:ring-terminal-green/50"
              />
              <div className="flex items-center justify-between font-mono text-xs">
                <span className="text-muted-foreground">
                  BUFFER_SIZE: {input.length} bytes
                </span>
                <Button 
                  onClick={handleSanitize}
                  disabled={!input.trim() || isProcessing}
                  className="bg-terminal-green hover:bg-terminal-green/80 text-black font-mono font-bold tracking-wide transition-all duration-200 hover:shadow-lg hover:shadow-terminal-green/25"
                >
                  {isProcessing ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-black mr-2" />
                      ANALYZING...
                    </>
                  ) : (
                    <>
                      <Shield className="h-4 w-4 mr-2" />
                      EXECUTE_SCAN
                    </>
                  )}
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Results Section */}
          <Card className="h-fit bg-card border-terminal-green/30 terminal-glow">
            <CardHeader className="border-b border-terminal-green/20">
              <CardTitle className="flex items-center gap-2 font-mono text-terminal-green">
                <Eye className="h-5 w-5" />
                ANALYSIS_OUTPUT
              </CardTitle>
              <CardDescription className="font-mono text-xs text-muted-foreground">
                // Security analysis results and sanitized payload
              </CardDescription>
            </CardHeader>
            <CardContent className="pt-6">
              {!result ? (
                <div className="text-center py-8 text-muted-foreground border-2 border-dashed border-terminal-green/20 rounded-lg bg-terminal-bg">
                  <Terminal className="h-12 w-12 mx-auto mb-3 opacity-50" />
                  <p className="font-mono text-sm">AWAITING_INPUT...</p>
                  <p className="font-mono text-xs mt-1 opacity-60">
                    // Initialize scan protocol to begin threat analysis
                  </p>
                </div>
              ) : (
                <div className="space-y-4">
                  {/* Severity Summary */}
                  <Alert className={`border font-mono ${
                    result.severity === 'high' ? 'border-red-500/50 bg-red-950/20' :
                    result.severity === 'moderate' ? 'border-yellow-500/50 bg-yellow-950/20' :
                    result.severity === 'low' ? 'border-blue-500/50 bg-blue-950/20' :
                    'border-terminal-green/50 bg-terminal-green/5'
                  }`}>
                    <div className="flex items-center gap-2">
                      {getSeverityIcon(result.severity)}
                      <AlertTitle className="text-sm font-mono font-bold">
                        <SeverityBadge severity={result.severity} />
                      </AlertTitle>
                    </div>
                    <AlertDescription className="mt-2 font-mono text-xs">
                      {getSeverityMessage(result.severity, result.issues.length)}
                    </AlertDescription>
                  </Alert>

                  {/* Issues List */}
                  {(expertMode || result.issues.length > 0) && (
                    <IssuesList issues={result.issues} expertMode={expertMode} />
                  )}

                  {/* Output Display */}
                  <Tabs defaultValue="sanitized" className="w-full">
                    <TabsList className="grid w-full grid-cols-2 bg-secondary border border-terminal-green/20 font-mono">
                      <TabsTrigger value="sanitized" className="data-[state=active]:bg-terminal-green data-[state=active]:text-black font-mono">CLEAN_OUTPUT</TabsTrigger>
                      <TabsTrigger value="comparison" className="data-[state=active]:bg-terminal-green data-[state=active]:text-black font-mono">DIFF_VIEW</TabsTrigger>
                    </TabsList>
                    <TabsContent value="sanitized">
                      <OutputDisplay 
                        content={result.sanitizedOutput} 
                        type="sanitized"
                      />
                    </TabsContent>
                    <TabsContent value="comparison">
                      <div className="space-y-4">
                        <div>
                          <h4 className="font-mono text-sm mb-2 text-red-400 font-bold">[ORIGINAL_HOSTILE]</h4>
                          <OutputDisplay 
                            content={result.originalInput} 
                            type="original"
                          />
                        </div>
                        <div>
                          <h4 className="font-mono text-sm mb-2 text-terminal-green font-bold">[SANITIZED_SAFE]</h4>
                          <OutputDisplay 
                            content={result.sanitizedOutput} 
                            type="sanitized"
                          />
                        </div>
                      </div>
                    </TabsContent>
                  </Tabs>

                  {/* Guidance */}
                  {result.guidance && (
                    <Alert className="border-terminal-green/30 bg-terminal-green/5">
                      <Info className="h-4 w-4 text-terminal-green" />
                      <AlertTitle className="font-mono text-terminal-green">SYSTEM_RECOMMENDATION</AlertTitle>
                      <AlertDescription className="font-mono text-xs text-muted-foreground">{result.guidance}</AlertDescription>
                    </Alert>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Terminal Footer */}
        <div className="mt-12 text-center">
          <Card className="bg-card border-terminal-green/30 terminal-glow">
            <CardContent className="pt-6">
              <div className="flex items-center justify-center gap-2 mb-3">
                <Shield className="h-5 w-5 text-terminal-green" />
                <h3 className="font-mono font-bold text-terminal-green">THREAT_INTELLIGENCE_BRIEFING</h3>
              </div>
              <p className="font-mono text-xs text-muted-foreground max-w-4xl mx-auto leading-relaxed">
                // AI models can generate malicious payloads disguised as benign content
                <br />
                // This system implements military-grade sanitization protocols
                <br />
                // Neutralizes XSS, injections, prompt hijacking, and zero-day exploits
                <br />
                // [CLASSIFIED] Keeping the digital battlefield secure, one output at a time
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default Index;
