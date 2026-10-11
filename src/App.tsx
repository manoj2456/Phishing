import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { Home } from './pages/Home';
import { Scanner } from './pages/Scanner';
import { History } from './pages/History';
import { SecurityTips } from './pages/SecurityTips';
import { About } from './pages/About';
import { VivaGuide } from './pages/VivaGuide';
import { ScanResult, ScanHistoryItem } from './types';
import { Shield, Heart, Terminal, ExternalLink } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('home');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);

  // Fetch scan history on load
  const loadHistory = async () => {
    try {
      const res = await fetch('/api/history');
      if (res.ok) {
        const data = await res.json();
        if (data.success && Array.isArray(data.history)) {
          setHistory(data.history);
        }
      }
    } catch (e) {
      console.warn('Could not fetch history:', e);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  const handleAnalyze = async (url: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || 'Unable to analyze the URL right now. Please try again.');
      }

      setLastResult(data);
      // Refresh history list
      loadHistory();
    } catch (err: any) {
      setError(err.message || 'Unable to analyze the URL right now. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleClearHistory = async () => {
    try {
      setIsLoading(true);
      const res = await fetch('/api/history/clear', { method: 'POST' });
      if (res.ok) {
        setHistory([]);
      }
    } catch (err) {
      console.error('Failed to clear history:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSelectUrlFromHistory = (url: string) => {
    setActiveTab('scanner');
    handleAnalyze(url);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 pt-6 sm:pt-8">
        {activeTab === 'home' && (
          <Home
            onAnalyze={handleAnalyze}
            isLoading={isLoading}
            error={error}
            setError={setError}
            lastResult={lastResult}
            setActiveTab={setActiveTab}
          />
        )}

        {activeTab === 'scanner' && (
          <Scanner
            onAnalyze={handleAnalyze}
            isLoading={isLoading}
            error={error}
            setError={setError}
            result={lastResult}
            onReset={() => {
              setLastResult(null);
              setError(null);
            }}
          />
        )}

        {activeTab === 'history' && (
          <History
            history={history}
            onClearHistory={handleClearHistory}
            onSelectUrl={handleSelectUrlFromHistory}
            isLoading={isLoading}
          />
        )}

        {activeTab === 'tips' && <SecurityTips />}

        {activeTab === 'about' && <About />}

        {activeTab === 'viva' && <VivaGuide />}
      </main>

      {/* Footer */}
      <footer className="mt-auto border-t border-slate-900 bg-slate-950/80 py-8 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <span className="font-semibold text-slate-300">PhishGuard</span>
            <span>·</span>
            <span>College CSE Mini Project</span>
            <span>·</span>
            <span>Educational Cybersecurity Tool</span>
          </div>

          <div className="text-center sm:text-right">
            <span>Safe URL analysis only. Never interact with or submit credentials to suspicious pages.</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
