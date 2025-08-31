
import React, { useEffect, useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, Activity } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { SecurityMetrics } from '@/types/sanitization';
import { SecurityMonitor as SecurityMonitorClass } from '@/lib/security-utils';

interface SecurityEvent {
  type: string;
  message: string;
  timestamp: number;
  severity: 'low' | 'medium' | 'high';
}

export const SecurityMonitor: React.FC = () => {
  const [metrics, setMetrics] = useState<SecurityMetrics | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [isOnline, setIsOnline] = useState(navigator.onLine);

  useEffect(() => {
    const securityMonitor = new SecurityMonitorClass();
    
    // Load initial metrics
    setMetrics(securityMonitor.getMetrics());

    // Listen for security events from service worker
    const handleMessage = (event: MessageEvent) => {
      if (event.data.type === 'SECURITY_EVENT') {
        const newEvent: SecurityEvent = {
          type: event.data.data.type,
          message: event.data.data.message,
          timestamp: event.data.data.timestamp,
          severity: 'medium'
        };
        
        setEvents(prev => [newEvent, ...prev.slice(0, 9)]); // Keep last 10 events
      }
    };

    // Listen for online/offline events
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);

    navigator.serviceWorker?.addEventListener('message', handleMessage);
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    // Periodic metrics update
    const interval = setInterval(() => {
      setMetrics(securityMonitor.getMetrics());
    }, 30000); // Update every 30 seconds

    return () => {
      navigator.serviceWorker?.removeEventListener('message', handleMessage);
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
      clearInterval(interval);
    };
  }, []);

  const getSecurityStatus = () => {
    if (!metrics) return { status: 'unknown', color: 'bg-gray-500' };
    
    const threatRate = metrics.totalScans > 0 ? metrics.threatsBlocked / metrics.totalScans : 0;
    
    if (threatRate > 0.1) return { status: 'high-risk', color: 'bg-red-500' };
    if (threatRate > 0.05) return { status: 'medium-risk', color: 'bg-yellow-500' };
    return { status: 'secure', color: 'bg-green-500' };
  };

  const securityStatus = getSecurityStatus();

  return (
    <div className="fixed bottom-4 right-4 z-50">
      <Card className="w-80 bg-black/90 border-terminal-green/30 backdrop-blur-sm">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-terminal-green text-sm">
            <Shield className="h-4 w-4" />
            Security Monitor
            <Badge 
              variant="outline" 
              className={`${securityStatus.color} text-white border-none`}
            >
              {securityStatus.status}
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {/* Connection Status */}
          <div className="flex items-center justify-between text-xs">
            <span className="text-gray-400">Connection:</span>
            <div className="flex items-center gap-1">
              <Activity className={`h-3 w-3 ${isOnline ? 'text-green-400' : 'text-red-400'}`} />
              <span className={isOnline ? 'text-green-400' : 'text-red-400'}>
                {isOnline ? 'Online' : 'Offline'}
              </span>
            </div>
          </div>

          {/* Security Metrics */}
          {metrics && (
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div>
                <span className="text-gray-400">Total Scans:</span>
                <div className="text-terminal-green font-mono">{metrics.totalScans}</div>
              </div>
              <div>
                <span className="text-gray-400">Threats Blocked:</span>
                <div className="text-red-400 font-mono">{metrics.threatsBlocked}</div>
              </div>
            </div>
          )}

          {/* Recent Security Events */}
          {events.length > 0 && (
            <div>
              <div className="text-xs text-gray-400 mb-1">Recent Events:</div>
              <div className="space-y-1 max-h-24 overflow-y-auto">
                {events.slice(0, 3).map((event, index) => (
                  <div key={index} className="flex items-center gap-2 text-xs">
                    <AlertTriangle className="h-3 w-3 text-yellow-400 flex-shrink-0" />
                    <span className="text-gray-300 truncate">{event.type}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Security Actions */}
          <div className="flex gap-2 pt-2 border-t border-gray-700">
            <button
              onClick={() => {
                navigator.serviceWorker?.controller?.postMessage({
                  type: 'SECURITY_SCAN'
                });
              }}
              className="text-xs text-terminal-green hover:text-terminal-green/80 transition-colors"
            >
              Manual Scan
            </button>
            <button
              onClick={() => {
                navigator.serviceWorker?.controller?.postMessage({
                  type: 'CLEAR_CACHE'
                });
              }}
              className="text-xs text-gray-400 hover:text-gray-300 transition-colors"
            >
              Clear Cache
            </button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
