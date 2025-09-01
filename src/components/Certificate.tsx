import { useState, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Download, Award, Share2, Printer } from 'lucide-react';
import { GameState } from '@/types/game';
import { toast } from 'sonner';
import html2canvas from 'html2canvas';
import jsPDF from 'jspdf';

interface CertificateProps {
  gameState: GameState;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  onClose?: () => void;
}

export function Certificate({ gameState, open, onOpenChange, onClose }: CertificateProps) {
  const [name, setName] = useState('');
  const [generating, setGenerating] = useState(false);
  const certificateRef = useRef<HTMLDivElement>(null);

  if (!open) return null;

  const completedLevels = gameState.levelProgress.filter(p => p.completed).length;
  const completionDate = new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
  
  const totalTime = gameState.levelProgress.reduce((acc, level) => acc + level.timeSpent, 0);
  const formattedTime = `${Math.floor(totalTime / 3600000)}h ${Math.floor((totalTime % 3600000) / 60000)}m`;

  const generatePDF = async () => {
    if (!name.trim()) {
      toast.error('Please enter your name for the certificate');
      return;
    }

    if (!certificateRef.current) return;

    setGenerating(true);

    try {
      const canvas = await html2canvas(certificateRef.current, {
        scale: 2,
        logging: false,
        backgroundColor: '#0a0a0a',
      });

      const imgData = canvas.toDataURL('image/png');
      const pdf = new jsPDF({
        orientation: 'landscape',
        unit: 'mm',
        format: 'a4',
      });

      const pdfWidth = pdf.internal.pageSize.getWidth();
      const pdfHeight = pdf.internal.pageSize.getHeight();
      
      pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight);
      pdf.save(`jailbreak-certificate-${name.replace(/\s+/g, '-').toLowerCase()}.pdf`);
      
      toast.success('Certificate downloaded successfully!');
    } catch (error) {
      console.error('Failed to generate certificate:', error);
      toast.error('Failed to generate certificate');
    } finally {
      setGenerating(false);
    }
  };

  const shareOnSocial = () => {
    if (!name.trim()) {
      toast.error('Please enter your name first');
      return;
    }

    const text = `I just completed ${completedLevels} levels of the Jailbreak Training Simulator with a score of ${gameState.score.toLocaleString()} points! 🎯🛡️`;
    const url = window.location.origin;

    if (navigator.share) {
      navigator.share({
        title: 'Jailbreak Training Certificate',
        text,
        url,
      }).catch(console.error);
    } else {
      // Fallback to Twitter
      const twitterUrl = `https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}&url=${encodeURIComponent(url)}`;
      window.open(twitterUrl, '_blank');
    }
  };

  const getCertificationLevel = () => {
    if (completedLevels === 20) return 'MASTER';
    if (completedLevels >= 15) return 'EXPERT';
    if (completedLevels >= 10) return 'ADVANCED';
    if (completedLevels >= 5) return 'INTERMEDIATE';
    return 'BEGINNER';
  };

  return (
    <Card className="border-terminal-green/30 bg-card max-w-4xl mx-auto">
      <CardHeader>
        <CardTitle className="text-xl font-mono text-terminal-green flex items-center gap-2 terminal-green-glow">
          <Award className="h-6 w-6" />
          CERTIFICATION_GENERATOR
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Name Input */}
        <div className="space-y-2">
          <Label htmlFor="name" className="text-sm font-mono text-terminal-green">
            ENTER_YOUR_NAME
          </Label>
          <Input
            id="name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="John Doe"
            className="font-mono bg-terminal-bg border-terminal-green/30 text-terminal-green"
            maxLength={50}
          />
        </div>

        {/* Certificate Preview */}
        <div
          ref={certificateRef}
          className="relative p-8 border-4 border-terminal-green/50 bg-gradient-to-br from-terminal-bg via-terminal-bg to-terminal-green/10 rounded-lg"
          style={{ minHeight: '500px' }}
        >
          {/* Border decoration */}
          <div className="absolute inset-2 border-2 border-terminal-green/20 rounded pointer-events-none"></div>
          
          {/* Certificate Content */}
          <div className="relative z-10 text-center space-y-6 py-8">
            {/* Header */}
            <div className="space-y-2">
              <h1 className="text-4xl font-bold text-terminal-green terminal-green-glow font-mono">
                CERTIFICATE OF COMPLETION
              </h1>
              <div className="text-sm font-mono text-terminal-green/70">
                JAILBREAK TRAINING SIMULATOR
              </div>
            </div>

            {/* Recipient */}
            <div className="py-6">
              <p className="text-sm font-mono text-terminal-green/80 mb-2">
                THIS CERTIFIES THAT
              </p>
              <h2 className="text-3xl font-bold text-terminal-green font-mono terminal-green-glow">
                {name || '[YOUR NAME]'}
              </h2>
            </div>

            {/* Achievement */}
            <div className="space-y-4">
              <p className="text-sm font-mono text-terminal-green/80">
                HAS SUCCESSFULLY COMPLETED
              </p>
              <div className="text-2xl font-bold text-terminal-green font-mono">
                {completedLevels} / 20 LEVELS
              </div>
              <div className="flex justify-center gap-8 text-sm font-mono">
                <div>
                  <span className="text-terminal-green/70">SCORE:</span>{' '}
                  <span className="text-terminal-green font-bold">
                    {gameState.score.toLocaleString()}
                  </span>
                </div>
                <div>
                  <span className="text-terminal-green/70">TIME:</span>{' '}
                  <span className="text-terminal-green font-bold">{formattedTime}</span>
                </div>
                <div>
                  <span className="text-terminal-green/70">HINTS:</span>{' '}
                  <span className="text-terminal-green font-bold">{gameState.hintsUsed}</span>
                </div>
              </div>
            </div>

            {/* Certification Level */}
            <div className="py-4">
              <div className="inline-block px-6 py-2 border-2 border-terminal-green/50 rounded">
                <span className="text-xl font-bold text-terminal-green font-mono terminal-green-glow">
                  {getCertificationLevel()} LEVEL
                </span>
              </div>
            </div>

            {/* Date and Signature */}
            <div className="pt-8 space-y-4">
              <div className="text-sm font-mono text-terminal-green/70">
                ISSUED ON: {completionDate}
              </div>
              <div className="text-xs font-mono text-terminal-green/50">
                CERTIFICATE ID: {Date.now().toString(36).toUpperCase()}
              </div>
              <div className="pt-4">
                <div className="text-sm font-mono text-terminal-green/70">
                  _____________________
                </div>
                <div className="text-xs font-mono text-terminal-green/50 mt-1">
                  TRAINING DIRECTOR
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap gap-2">
          <Button
            onClick={generatePDF}
            disabled={!name.trim() || generating}
            className="font-mono bg-terminal-green text-terminal-bg hover:bg-terminal-green/80"
          >
            {generating ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-terminal-bg mr-2" />
                GENERATING...
              </>
            ) : (
              <>
                <Download className="h-4 w-4 mr-2" />
                DOWNLOAD_PDF
              </>
            )}
          </Button>
          <Button
            onClick={shareOnSocial}
            disabled={!name.trim()}
            variant="outline"
            className="font-mono border-terminal-green/30 text-terminal-green hover:bg-terminal-green/10"
          >
            <Share2 className="h-4 w-4 mr-2" />
            SHARE
          </Button>
          <Button
            onClick={() => window.print()}
            variant="outline"
            className="font-mono border-terminal-green/30 text-terminal-green hover:bg-terminal-green/10"
          >
            <Printer className="h-4 w-4 mr-2" />
            PRINT
          </Button>
          {onClose && (
            <Button
              onClick={onClose}
              variant="ghost"
              className="font-mono text-terminal-green hover:bg-terminal-green/10"
            >
              CLOSE
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
