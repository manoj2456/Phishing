import React from 'react';
import { URLScanner } from '../components/URLScanner';
import { ResultCard } from '../components/ResultCard';
import { ScanResult } from '../types';
import { Shield, RefreshCw } from 'lucide-react';

interface ScannerProps {
  onAnalyze: (url: string) => Promise<void>;
  isLoading: boolean;
  error: string | null;
  setError: (err: string | null) => void;
  result: ScanResult | null;
  onReset: () => void;
}

export const Scanner: React.FC<ScannerProps> = ({
  onAnalyze,
  isLoading,
  error,
  setError,
  result,
  onReset,
}) => {
  return (
    <div className="space-y-10 pb-16">
      {/* Header */}
      <div className="max-w-4xl mx-auto text-center space-y-3">
        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-medium">
          <Shield className="w-3.5 h-3.5" />
          <span>Real-Time Heuristic & ML Inspection</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Website Security Scanner
        </h1>
        <p className="text-sm text-slate-400 max-w-xl mx-auto">
          Submit any web address to calculate lexical indicators, evaluate threat probability, and inspect security characteristics.
        </p>
      </div>

      {/* Input Form */}
      <URLScanner
        onAnalyze={onAnalyze}
        isLoading={isLoading}
        error={error}
        setError={setError}
      />

      {/* Analysis Results Display */}
      {result && (
        <div className="pt-6 border-t border-slate-800/80 space-y-6">
          <div className="flex items-center justify-between max-w-5xl mx-auto px-2">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <span>Security Assessment Report</span>
            </h2>
            <button
              onClick={onReset}
              className="text-xs text-slate-400 hover:text-cyan-400 flex items-center gap-1 px-3 py-1.5 rounded-lg border border-slate-800 hover:border-slate-700 bg-slate-900/40 transition-colors"
            >
              <RefreshCw className="w-3 h-3" />
              <span>Reset Scanner</span>
            </button>
          </div>

          <ResultCard result={result} />
        </div>
      )}
    </div>
  );
};
