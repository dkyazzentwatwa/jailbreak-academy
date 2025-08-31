import React, { Component, ErrorInfo, ReactNode } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  static getDerivedStateFromError(error: Error): State {
    return {
      hasError: true,
      error,
      errorInfo: null,
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo);
    
    // Log error to analytics service in production
    if (import.meta.env.PROD) {
      // apiService.trackEvent('error_boundary', {
      //   error: error.toString(),
      //   componentStack: errorInfo.componentStack,
      // });
    }
    
    this.setState({
      error,
      errorInfo,
    });
  }

  handleReset = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
    });
  };

  handleReload = () => {
    window.location.reload();
  };

  handleGoHome = () => {
    window.location.href = '/';
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return <>{this.props.fallback}</>;
      }

      return (
        <div className="min-h-screen bg-terminal-bg text-terminal-green font-mono flex items-center justify-center p-4">
          <Card className="max-w-2xl w-full border-terminal-green/30 bg-card">
            <CardHeader>
              <CardTitle className="text-xl font-mono text-red-400 flex items-center gap-2">
                <AlertTriangle className="h-6 w-6" />
                SYSTEM_ERROR_DETECTED
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="p-4 rounded border border-red-400/30 bg-red-900/10">
                <p className="text-sm font-mono text-red-400 mb-2">
                  ERROR_MESSAGE:
                </p>
                <p className="text-xs font-mono text-muted-foreground">
                  {this.state.error?.message || 'Unknown error occurred'}
                </p>
              </div>

              {import.meta.env.DEV && this.state.errorInfo && (
                <div className="p-4 rounded border border-terminal-green/20 bg-terminal-bg">
                  <p className="text-sm font-mono text-terminal-green mb-2">
                    STACK_TRACE:
                  </p>
                  <pre className="text-xs font-mono text-muted-foreground overflow-auto max-h-48">
                    {this.state.error?.stack}
                  </pre>
                  <p className="text-sm font-mono text-terminal-green mt-4 mb-2">
                    COMPONENT_STACK:
                  </p>
                  <pre className="text-xs font-mono text-muted-foreground overflow-auto max-h-48">
                    {this.state.errorInfo.componentStack}
                  </pre>
                </div>
              )}

              <div className="flex items-center gap-2">
                <Button
                  onClick={this.handleReset}
                  variant="outline"
                  className="font-mono text-xs"
                >
                  <RefreshCw className="h-4 w-4 mr-2" />
                  TRY_AGAIN
                </Button>
                <Button
                  onClick={this.handleReload}
                  variant="outline"
                  className="font-mono text-xs"
                >
                  <RefreshCw className="h-4 w-4 mr-2" />
                  RELOAD_PAGE
                </Button>
                <Button
                  onClick={this.handleGoHome}
                  variant="outline"
                  className="font-mono text-xs"
                >
                  <Home className="h-4 w-4 mr-2" />
                  GO_HOME
                </Button>
              </div>

              <div className="mt-4 p-3 rounded border border-terminal-green/20 bg-terminal-bg">
                <p className="text-xs font-mono text-muted-foreground">
                  If this error persists, please report it to the development team.
                  Error ID: {Date.now().toString(36).toUpperCase()}
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      );
    }

    return this.props.children;
  }
}