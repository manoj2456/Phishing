import React from 'react';
import { ShieldCheck, Cpu, BookOpen, ArrowRight, Lock, CheckCircle2, AlertOctagon } from 'lucide-react';
import { URLScanner } from '../components/URLScanner';
import { ScanResult } from '../types';
import heroImage from '../assets/images/hero_cyber_security_1791721594222.jpg';

interface HomeProps {
  onAnalyze: (url: string) => Promise<void>;
  isLoading: boolean;
  error: string | null;
  setError: (err: string | null) => void;
  lastResult: ScanResult | null;
  setActiveTab: (tab: string) => void;
}

export const Home: React.FC<HomeProps> = ({
  onAnalyze,
  isLoading,
  error,
  setError,
  lastResult,
  setActiveTab,
}) => {
  return (
    <div className="space-y-16 pb-12">
      {/* Hero Section */}
      <section className="relative pt-8 sm:pt-14 pb-8">
        <div className="max-w-5xl mx-auto text-center space-y-6">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-medium">
            <Lock className="w-3.5 h-3.5" />
            <span>AI & Machine Learning Powered URL Defense</span>
          </div>

          <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-white leading-tight">
            Is This Website Safe?
          </h1>

          <p className="text-base sm:text-lg text-slate-400 max-w-2xl mx-auto leading-relaxed">
            Analyze a website URL and identify potential phishing indicators before you interact with it.
          </p>

          {/* Scanner Input Box */}
          <div className="pt-4 max-w-3xl mx-auto">
            <URLScanner
              onAnalyze={async (url) => {
                await onAnalyze(url);
                setActiveTab('scanner');
              }}
              isLoading={isLoading}
              error={error}
              setError={setError}
            />
          </div>
        </div>

        {/* Hero Visual Banner */}
        <div className="max-w-5xl mx-auto mt-12 rounded-2xl overflow-hidden border border-slate-800 shadow-2xl relative group">
          <img
            src={heroImage}
            alt="Cybersecurity digital defense matrix"
            referrerPolicy="no-referrer"
            className="w-full h-64 sm:h-80 object-cover object-center filter brightness-90 group-hover:scale-[1.01] transition-transform duration-700"
          />
          <div className="absolute inset-0 bg-gradient-to-t from-slate-950 via-slate-950/40 to-transparent flex items-end p-6 sm:p-8">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between w-full gap-4">
              <div>
                <h2 className="text-lg sm:text-xl font-bold text-white">
                  PhishGuard Engine Architecture
                </h2>
                <p className="text-xs sm:text-sm text-slate-300">
                  20 lexical heuristics combined with Random Forest ML ensemble
                </p>
              </div>
              <button
                onClick={() => setActiveTab('viva')}
                className="px-4 py-2 bg-slate-900/90 hover:bg-slate-800 text-xs sm:text-sm text-cyan-300 font-semibold rounded-lg border border-cyan-500/30 flex items-center gap-1.5 transition-colors whitespace-nowrap"
              >
                <span>View Viva Guide</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* 3 Core Feature Cards specified in Section 12 */}
      <section className="max-w-5xl mx-auto">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Card 1: URL Analysis */}
          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800/80 hover:border-slate-700 transition-all flex flex-col justify-between">
            <div className="space-y-3">
              <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center text-xl">
                🔒
              </div>
              <h3 className="text-lg font-bold text-white">URL Analysis</h3>
              <p className="text-sm text-slate-400 leading-relaxed">
                Extracts and evaluates 20 structural attributes: length, subdomains, special characters, ports, and brand spoofing patterns.
              </p>
            </div>
            <button
              onClick={() => setActiveTab('scanner')}
              className="mt-6 inline-flex items-center gap-1.5 text-xs font-semibold text-cyan-400 hover:text-cyan-300"
            >
              <span>Test URL characteristics</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Card 2: Machine Learning */}
          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800/80 hover:border-slate-700 transition-all flex flex-col justify-between">
            <div className="space-y-3">
              <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center text-xl">
                🤖
              </div>
              <h3 className="text-lg font-bold text-white">Machine Learning</h3>
              <p className="text-sm text-slate-400 leading-relaxed">
                Uses a trained Random Forest classification model to output statistical risk scores and confidence probabilities.
              </p>
            </div>
            <button
              onClick={() => setActiveTab('about')}
              className="mt-6 inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400 hover:text-emerald-300"
            >
              <span>Explore ML model details</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Card 3: Security Awareness */}
          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800/80 hover:border-slate-700 transition-all flex flex-col justify-between">
            <div className="space-y-3">
              <div className="w-12 h-12 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400 flex items-center justify-center text-xl">
                🛡
              </div>
              <h3 className="text-lg font-bold text-white">Security Awareness</h3>
              <p className="text-sm text-slate-400 leading-relaxed">
                Learn practical tips to recognize phishing traps, understand deceptive social engineering, and defend credentials.
              </p>
            </div>
            <button
              onClick={() => setActiveTab('tips')}
              className="mt-6 inline-flex items-center gap-1.5 text-xs font-semibold text-purple-400 hover:text-purple-300"
            >
              <span>Read cybersecurity tips</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </section>

      {/* College Project Quick Verification Strip */}
      <section className="max-w-5xl mx-auto p-6 rounded-2xl bg-slate-900/40 border border-slate-800">
        <div className="flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="space-y-1 text-center md:text-left">
            <h4 className="text-sm font-semibold text-white">
              CSE Mini Project Academic Objectives
            </h4>
            <p className="text-xs text-slate-400">
              Demonstrates safe static URL feature extraction without crawling or executing malicious remote content.
            </p>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            <div className="px-3 py-1.5 rounded-lg bg-slate-800 text-xs font-mono text-cyan-400 border border-slate-700">
              Random Forest · 20 Features · SQLite
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};
