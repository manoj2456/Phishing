import React, { useState } from 'react';
import { Search, Loader2, AlertCircle, ShieldAlert, CheckCircle2, Sparkles, ArrowRight } from 'lucide-react';
import { SAMPLE_URLS, PresetUrl } from '../data/sampleUrls';

interface URLScannerProps {
  onAnalyze: (url: string) => Promise<void>;
  isLoading: boolean;
  error: string | null;
  setError: (err: string | null) => void;
}

export const URLScanner: React.FC<URLScannerProps> = ({
  onAnalyze,
  isLoading,
  error,
  setError,
}) => {
  const [urlInput, setUrlInput] = useState('');

  const validateUrl = (raw: string): string | null => {
    const trimmed = raw.trim();
    if (!trimmed) {
      return 'Please enter a valid website URL.';
    }

    if (trimmed.length > 2048) {
      return 'URL is too long. Maximum allowed length is 2048 characters.';
    }

    const lower = trimmed.toLowerCase();
    const unsupportedSchemes = ['ftp://', 'file://', 'javascript:', 'data:', 'mailto:', 'ws://', 'wss://'];
    for (const scheme of unsupportedSchemes) {
      if (lower.startsWith(scheme)) {
        return `Unsupported protocol '${scheme}'. PhishGuard analyzes HTTP and HTTPS URLs only.`;
      }
    }

    let urlToTest = trimmed;
    if (!lower.startsWith('http://') && !lower.startsWith('https://')) {
      urlToTest = 'http://' + trimmed;
    }

    try {
      const parsed = new URL(urlToTest);
      const hostname = (parsed.hostname || '').trim();
      if (!hostname) {
        return 'Invalid URL: Hostname is missing.';
      }
      const isIp = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(hostname) || (hostname.startsWith('[') && hostname.endsWith(']'));
      if (!isIp && !hostname.includes('.') && hostname !== 'localhost') {
        return 'Invalid URL: Domain must contain at least one dot (e.g. example.com).';
      }
    } catch (e) {
      return 'Invalid URL format. Please ensure the address is formatted properly.';
    }

    return null;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const validationError = validateUrl(urlInput);
    if (validationError) {
      setError(validationError);
      return;
    }
    setError(null);
    onAnalyze(urlInput.trim());
  };

  const handleSelectPreset = (preset: PresetUrl) => {
    setUrlInput(preset.url);
    setError(null);
    onAnalyze(preset.url);
  };

  return (
    <div className="w-full max-w-4xl mx-auto">
      <form onSubmit={handleSubmit} className="relative">
        <div className="relative flex flex-col sm:flex-row items-stretch sm:items-center bg-slate-900/90 border border-slate-700/80 rounded-2xl p-2 shadow-2xl shadow-cyan-950/20 focus-within:border-cyan-500/80 focus-within:ring-2 focus-within:ring-cyan-500/20 transition-all">
          <div className="flex items-center flex-1 px-3 py-2">
            <Search className="w-5 h-5 text-slate-400 shrink-0 mr-3" />
            <input
              type="text"
              value={urlInput}
              onChange={(e) => {
                setUrlInput(e.target.value);
                if (error) setError(null);
              }}
              placeholder="Enter website URL (e.g., https://example.com or suspicious link)..."
              disabled={isLoading}
              className="w-full bg-transparent text-slate-100 placeholder:text-slate-500 text-sm sm:text-base focus:outline-none font-mono"
            />
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="mt-2 sm:mt-0 px-6 py-3 bg-cyan-500 hover:bg-cyan-400 disabled:bg-slate-800 disabled:text-slate-500 text-slate-950 font-bold rounded-xl transition-all shadow-md shadow-cyan-500/25 flex items-center justify-center gap-2 whitespace-nowrap shrink-0 text-sm cursor-pointer disabled:cursor-not-allowed"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Scanning URL...</span>
              </>
            ) : (
              <>
                <span>Analyze Website</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>
      </form>

      {/* Validation Error Message */}
      {error && (
        <div className="mt-3 flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-xl text-red-400 text-xs sm:text-sm animate-fadeIn">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Test Sample Presets for College Presentation */}
      <div className="mt-4 pt-4 border-t border-slate-800/60">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs text-slate-400 font-medium flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            Quick Demo Presets for College Evaluation:
          </span>
          <span className="text-[11px] text-slate-400 hidden sm:inline">
            Click to auto-load & analyze
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
          {SAMPLE_URLS.map((sample) => {
            const badgeColor =
              sample.expected === 'SAFE'
                ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'
                : sample.expected === 'SUSPICIOUS'
                ? 'text-amber-400 bg-amber-500/10 border-amber-500/20'
                : 'text-red-400 bg-red-500/10 border-red-500/20';

            return (
              <button
                key={sample.name}
                type="button"
                onClick={() => handleSelectPreset(sample)}
                disabled={isLoading}
                className="text-left p-2.5 rounded-xl bg-slate-900/50 hover:bg-slate-800/80 border border-slate-800 hover:border-slate-700 transition-all group"
              >
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="font-semibold text-slate-200 group-hover:text-cyan-400 transition-colors truncate">
                    {sample.name}
                  </span>
                  <span className={`text-[10px] px-1.5 py-0.2 rounded border font-mono ${badgeColor}`}>
                    {sample.expected}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 truncate font-mono">
                  {sample.url}
                </p>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
};
