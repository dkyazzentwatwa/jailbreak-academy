
import { useState } from "react";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Shield, AlertTriangle, CheckCircle, Info, Eye, Code, FileText } from "lucide-react";
import { SanitizationEngine } from "@/lib/sanitization-engine";
import { SeverityLevel, SanitizationResult } from "@/types/sanitization";
import { SeverityBadge } from "@/components/SeverityBadge";
import { IssuesList } from "@/components/IssuesList";
import { OutputDisplay } from "@/components/OutputDisplay";

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
      await new Promise(resolve => setTimeout(resolve, 500));
      
      const sanitizer = new SanitizationEngine();
      const sanitizationResult = sanitizer.sanitize(input);
      setResult(sanitizationResult);
    } catch (error) {
      console.error("Sanitization error:", error);
    } finally {
      setIsProcessing(false);
    }
  };

  const getSeverityIcon = (severity: SeverityLevel) => {
    switch (severity) {
      case 'high':
        return <AlertTriangle className="h-5 w-5 text-red-500" />;
      case 'moderate':
        return <Info className="h-5 w-5 text-yellow-500" />;
      case 'low':
        return <AlertTriangle className="h-5 w-5 text-blue-500" />;
      default:
        return <CheckCircle className="h-5 w-5 text-green-500" />;
    }
  };

  const getSeverityMessage = (severity: SeverityLevel, issueCount: number) => {
    switch (severity) {
      case 'high':
        return `Dangerous content detected and removed (${issueCount} critical ${issueCount === 1 ? 'issue' : 'issues'})`;
      case 'moderate':
        return `Potentially harmful content found and sanitized (${issueCount} ${issueCount === 1 ? 'issue' : 'issues'})`;
      case 'low':
        return `Minor issues cleaned up (${issueCount} ${issueCount === 1 ? 'issue' : 'issues'})`;
      default:
        return "No security issues detected - output is safe to use";
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
      <div className="container mx-auto py-8 px-4 max-w-6xl">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Shield className="h-8 w-8 text-blue-600" />
            <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
              LLM Output Sanitizer
            </h1>
          </div>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
            Professional-grade security analysis for AI-generated content. 
            Remove malicious code, prevent XSS attacks, and ensure safe AI outputs.
          </p>
        </div>

        {/* Expert Mode Toggle */}
        <div className="flex items-center justify-center gap-2 mb-6">
          <Label htmlFor="expert-mode">Simple Mode</Label>
          <Switch
            id="expert-mode"
            checked={expertMode}
            onCheckedChange={setExpertMode}
          />
          <Label htmlFor="expert-mode">Expert Mode</Label>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Input Section */}
          <Card className="h-fit">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileText className="h-5 w-5" />
                AI Output Input
              </CardTitle>
              <CardDescription>
                Paste any AI-generated content here for security analysis
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Textarea
                placeholder="Paste your AI output here (HTML, code, text, etc.)..."
                value={input}
                onChange={(e) => setInput(e.target.value)}
                className="min-h-[300px] font-mono text-sm resize-none"
              />
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">
                  {input.length} characters
                </span>
                <Button 
                  onClick={handleSanitize}
                  disabled={!input.trim() || isProcessing}
                  className="bg-blue-600 hover:bg-blue-700"
                >
                  {isProcessing ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2" />
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <Shield className="h-4 w-4 mr-2" />
                      Sanitize Output
                    </>
                  )}
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Results Section */}
          <Card className="h-fit">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Eye className="h-5 w-5" />
                Security Analysis Results
              </CardTitle>
              <CardDescription>
                Sanitized output and security findings
              </CardDescription>
            </CardHeader>
            <CardContent>
              {!result ? (
                <div className="text-center py-8 text-muted-foreground border-2 border-dashed border-muted rounded-lg">
                  <Shield className="h-12 w-12 mx-auto mb-3 opacity-50" />
                  <p>Enter AI output above and click "Sanitize Output" to begin analysis</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {/* Severity Summary */}
                  <Alert className={`${
                    result.severity === 'high' ? 'border-red-200 bg-red-50' :
                    result.severity === 'moderate' ? 'border-yellow-200 bg-yellow-50' :
                    result.severity === 'low' ? 'border-blue-200 bg-blue-50' :
                    'border-green-200 bg-green-50'
                  }`}>
                    <div className="flex items-center gap-2">
                      {getSeverityIcon(result.severity)}
                      <AlertTitle className="text-sm font-medium">
                        <SeverityBadge severity={result.severity} />
                      </AlertTitle>
                    </div>
                    <AlertDescription className="mt-2">
                      {getSeverityMessage(result.severity, result.issues.length)}
                    </AlertDescription>
                  </Alert>

                  {/* Issues List - Show based on mode */}
                  {(expertMode || result.issues.length > 0) && (
                    <IssuesList issues={result.issues} expertMode={expertMode} />
                  )}

                  {/* Output Display */}
                  <Tabs defaultValue="sanitized" className="w-full">
                    <TabsList className="grid w-full grid-cols-2">
                      <TabsTrigger value="sanitized">Sanitized Output</TabsTrigger>
                      <TabsTrigger value="comparison">Before/After</TabsTrigger>
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
                          <h4 className="font-medium text-sm mb-2 text-red-600">Original (Potentially Unsafe)</h4>
                          <OutputDisplay 
                            content={result.originalInput} 
                            type="original"
                          />
                        </div>
                        <div>
                          <h4 className="font-medium text-sm mb-2 text-green-600">Sanitized (Safe)</h4>
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
                    <Alert>
                      <Info className="h-4 w-4" />
                      <AlertTitle>Recommendation</AlertTitle>
                      <AlertDescription>{result.guidance}</AlertDescription>
                    </Alert>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Educational Footer */}
        <div className="mt-12 text-center">
          <Card className="bg-gradient-to-r from-blue-50 to-indigo-50 border-blue-200">
            <CardContent className="pt-6">
              <div className="flex items-center justify-center gap-2 mb-3">
                <Shield className="h-5 w-5 text-blue-600" />
                <h3 className="font-semibold text-blue-900">Why Sanitize AI Outputs?</h3>
              </div>
              <p className="text-sm text-blue-800 max-w-4xl mx-auto">
                AI models can sometimes generate malicious content that looks harmless but contains hidden security threats. 
                This tool helps identify and neutralize XSS attacks, code injections, and other security vulnerabilities 
                in AI-generated text, keeping your applications and users safe.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default Index;
