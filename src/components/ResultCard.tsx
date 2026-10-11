import React, { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle,
  Shield,
  ShieldAlert,
  ShieldCheck,
  HelpCircle,
  Info,
  ChevronDown,
  ChevronUp,
  Table as TableIcon,
  Calculator,
  Lock,
  Unlock,
  AlertOctagon,
  Code2
} from 'lucide-react';
import { ScanResult } from '../types';
import { RiskMeter } from './RiskMeter';
import { FeatureChart } from './FeatureChart';

interface ResultCardProps {
  result: ScanResult;
}

export const ResultCard: React.FC<ResultCardProps> = ({ result }) => {
  const [showRawFeatures, setShowRawFeatures] = useState(false);
  const [showScoreMath, setShowScoreMath] = useState(true);

  const isPhishing = result.classification === 'PHISHING';
  const isSuspicious = result.classification === 'SUSPICIOUS';
  const isSafe = result.classification === 'SAFE';
  const isUnknown = result.classification === 'UNKNOWN';

  let statusHeaderBg = 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400';
  let StatusIcon = ShieldCheck;

  if (isPhishing) {
    statusHeaderBg = 'bg-red-500/10 border-red-500/30 text-red-400';
    StatusIcon = ShieldAlert;
  } else if (isSuspicious) {
    statusHeaderBg = 'bg-amber-500/10 border-amber-500/30 text-amber-400';
    StatusIcon = AlertTriangle;
  } else if (isUnknown) {
    statusHeaderBg = 'bg-slate-700/20 border-slate-700/40 text-slate-300';
    StatusIcon = HelpCircle;
  }

  return (
    <div className="w-full max-w-5xl mx-auto space-y-6 animate-fadeIn">
      {/* 1. Header Card: WEBSITE SECURITY ANALYSIS (Section 4) */}
      <div className={`p-6 rounded-2xl border ${statusHeaderBg} space-y-4`}>
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-start gap-3.5">
            <div className="p-2.5 rounded-xl bg-slate-950/60 border border-current shrink-0 mt-0.5">
              <StatusIcon className="w-7 h-7" />
            </div>
            <div>
              <span className="text-[11px] font-mono uppercase tracking-widest text-slate-400 block mb-0.5">
                WEBSITE SECURITY ANALYSIS
              </span>
              <h2 className="text-xl sm:text-2xl font-extrabold tracking-tight">
                {result.classification_label || `${result.classification} — ${result.risk_level} RISK`}
              </h2>
              <div className="flex flex-wrap items-center gap-2 mt-2 text-xs text-slate-300">
                <span className="px-2 py-0.5 rounded bg-slate-950/60 border border-slate-800 font-mono">
                  Risk Level: <strong className="text-white">{result.risk_level}</strong>
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-950/60 border border-slate-800 font-mono">
                  Risk Score: <strong className="text-white">{result.risk_score}/100</strong>
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-950/60 border border-slate-800 font-mono">
                  Confidence: <strong className="text-white">{Math.round(result.confidence * 100)}%</strong>
                </span>
              </div>
            </div>
          </div>

          {/* Scanned URL preview */}
          <div className="w-full md:w-auto p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 text-left md:text-right shrink-0">
            <div className="text-[11px] text-slate-400 font-medium">Scanned URL</div>
            <div className="text-xs sm:text-sm font-mono text-cyan-300 font-semibold truncate max-w-md mt-0.5">
              {result.url}
            </div>
            <div className="text-[10px] text-slate-500 font-mono mt-1">
              Analysis Engine: {result.analysis_type}
            </div>
          </div>
        </div>
      </div>

      {/* Main 2-Column Section: Left is Visual Risk Meter, Right is Why We Gave This Result */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column (5 cols): Risk Meter & Score Explanation */}
        <div className="lg:col-span-5 space-y-6">
          <RiskMeter
            score={result.risk_score}
            classification={result.classification}
            riskLevel={result.risk_level}
            confidence={result.confidence}
          />

          {/* How was this score calculated? (Section 2) */}
          <div className="p-5 bg-slate-900/60 border border-slate-800/80 rounded-2xl space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                <Calculator className="w-4 h-4 text-cyan-400" />
                <span>How was this score calculated?</span>
              </h3>
              <button
                onClick={() => setShowScoreMath(!showScoreMath)}
                className="text-[11px] text-slate-400 hover:text-cyan-400 transition-colors cursor-pointer"
              >
                {showScoreMath ? 'Collapse' : 'Expand'}
              </button>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Calculated using calibrated heuristic rules and lexical indicators. Points are capped to avoid double-counting correlated signals.
            </p>

            {showScoreMath && (
              <div className="space-y-2 pt-2 border-t border-slate-800/80">
                {result.score_breakdown && result.score_breakdown.length > 0 ? (
                  result.score_breakdown.map((item, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800/80 flex items-start justify-between text-xs gap-2"
                    >
                      <div className="space-y-0.5">
                        <span className="font-semibold text-slate-200 block">
                          {item.factor}
                        </span>
                        <span className="text-[11px] text-slate-400 block leading-tight">
                          {item.reason}
                        </span>
                      </div>
                      <span className="font-mono font-bold text-amber-400 shrink-0 text-xs px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/20">
                        +{item.points} pts
                      </span>
                    </div>
                  ))
                ) : (
                  <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 text-xs text-emerald-400 flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 shrink-0" />
                    <span>0 penalty points accumulated. Normal baseline characteristics maintained.</span>
                  </div>
                )}
                <div className="pt-2 flex items-center justify-between text-xs font-mono border-t border-slate-800/60 text-slate-400">
                  <span>Cumulative Risk Metric:</span>
                  <span className="font-bold text-white text-sm">
                    {result.risk_score} / 100
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right Column (7 cols): Detected Indicators (Section 5) & Security Recommendations (Section 7) */}
        <div className="lg:col-span-7 space-y-6">
          {/* Section 5: "Why did we give this result?" */}
          <div className="p-6 bg-slate-900/60 border border-slate-800/80 rounded-2xl space-y-4">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Info className="w-5 h-5 text-cyan-400" />
                <span>Why did we give this result?</span>
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Transparent evidence extracted from the URL's structural, lexical, and host attributes.
              </p>
            </div>

            {/* Warning Indicators */}
            <div className="space-y-2">
              <span className="text-xs font-bold text-red-400 uppercase tracking-wider flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                <span>Potential Warning Indicators ({result.indicators.length})</span>
              </span>
              {result.indicators.length > 0 ? (
                <ul className="space-y-2">
                  {result.indicators.map((ind, idx) => (
                    <li
                      key={idx}
                      className="flex items-start gap-2.5 p-3 rounded-xl bg-red-500/5 border border-red-500/20 text-xs sm:text-sm text-red-300"
                    >
                      <span className="text-red-400 font-bold shrink-0 mt-0.5">⚠</span>
                      <span>{ind}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 text-xs text-slate-400">
                  No abnormal warning indicators identified for this URL.
                </div>
              )}
            </div>

            {/* Positive Indicators */}
            <div className="space-y-2 pt-2 border-t border-slate-800/80">
              <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                <span>Positive Indicators ({result.positive_indicators.length})</span>
              </span>
              {result.positive_indicators.length > 0 ? (
                <ul className="space-y-2">
                  {result.positive_indicators.map((ind, idx) => (
                    <li
                      key={idx}
                      className="flex items-start gap-2.5 p-3 rounded-xl bg-emerald-500/5 border border-emerald-500/20 text-xs sm:text-sm text-emerald-300"
                    >
                      <span className="text-emerald-400 font-bold shrink-0 mt-0.5">✓</span>
                      <span>{ind}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 text-xs text-slate-400">
                  None verified.
                </div>
              )}
              {/* Mandatory Section 5 explanation note */}
              <p className="text-[11px] text-slate-400 italic pt-1">
                * Note: Positive indicators reflect standard URL syntax, but do not prove that a website is definitely legitimate.
              </p>
            </div>
          </div>

          {/* Section 7: Security Recommendations */}
          <div className="p-6 bg-slate-900/60 border border-slate-800/80 rounded-2xl space-y-3">
            <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
              <Shield className="w-4 h-4" />
              <span>Cybersecurity Safety Recommendations</span>
            </h3>
            <ul className="space-y-2 text-xs sm:text-sm text-slate-300">
              {result.recommendations.map((rec, i) => (
                <li key={i} className="flex items-start gap-2.5 p-2.5 rounded-xl bg-slate-950/40 border border-slate-800/60">
                  <span className="text-cyan-400 font-bold shrink-0 mt-0.5">•</span>
                  <span>{rec}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      {/* 2. Detailed URL Characteristics Table (Section 1 and Section 4) */}
      <div className="p-6 bg-slate-900/60 border border-slate-800/80 rounded-2xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <TableIcon className="w-5 h-5 text-cyan-400" />
              <span>URL Characteristics Analysis Table</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Evaluated characteristics extracted directly from the actual submitted URL:
            </p>
          </div>
          <span className="text-xs font-mono text-cyan-400 px-2.5 py-1 rounded bg-cyan-500/10 border border-cyan-500/20">
            15 Monitored Dimensions
          </span>
        </div>

        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left border-collapse text-xs sm:text-sm">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/80 text-slate-400 text-xs font-semibold uppercase tracking-wider font-mono">
                <th className="py-3 px-4">Feature Dimension</th>
                <th className="py-3 px-4">Actual Result</th>
                <th className="py-3 px-4">Evaluation Context</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {result.characteristics_table && result.characteristics_table.length > 0 ? (
                result.characteristics_table.map((row, idx) => {
                  let badge = 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
                  if (row.category === 'danger') {
                    badge = 'text-red-400 bg-red-500/10 border-red-500/30';
                  } else if (row.category === 'warning') {
                    badge = 'text-amber-400 bg-amber-500/10 border-amber-500/30';
                  } else if (row.category === 'neutral') {
                    badge = 'text-slate-300 bg-slate-800/40 border-slate-700';
                  }

                  return (
                    <tr key={idx} className="hover:bg-slate-850/50 transition-colors">
                      <td className="py-2.5 px-4 font-sans font-medium text-slate-200">
                        {row.feature}
                      </td>
                      <td className="py-2.5 px-4">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded border text-xs font-semibold ${badge}`}>
                          {row.actualResult}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 font-sans text-xs text-slate-400">
                        {row.detail || '—'}
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={3} className="py-6 text-center text-slate-500 font-sans">
                    Characteristic breakdown unavailable.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Feature Characteristic Visualization Chart */}
      <FeatureChart features={result.features} />

      {/* Collapsible Raw 20 Features Inspection Table for CSE Mini Project Viva */}
      <div className="bg-slate-900/60 border border-slate-800/80 rounded-2xl overflow-hidden">
        <button
          onClick={() => setShowRawFeatures(!showRawFeatures)}
          className="w-full px-6 py-4 flex items-center justify-between text-left hover:bg-slate-850/50 transition-colors cursor-pointer"
        >
          <div className="flex items-center gap-2.5">
            <Code2 className="w-4 h-4 text-cyan-400" />
            <span className="text-sm font-semibold text-slate-200">
              Inspect Raw 20 Machine Learning Features
            </span>
            <span className="text-xs text-slate-400 font-mono">
              [feature_extractor.py vector]
            </span>
          </div>
          {showRawFeatures ? (
            <ChevronUp className="w-4 h-4 text-slate-400" />
          ) : (
            <ChevronDown className="w-4 h-4 text-slate-400" />
          )}
        </button>

        {showRawFeatures && (
          <div className="p-6 border-t border-slate-800/80 bg-slate-950/60">
            <p className="text-xs text-slate-400 mb-4 font-sans">
              These 20 numerical parameters form the feature vector passed into the classifier during evaluation:
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3 text-xs">
              {Object.entries(result.features).map(([key, val]) => (
                <div
                  key={key}
                  className="p-3 bg-slate-900/80 border border-slate-800 rounded-xl flex flex-col justify-between"
                >
                  <span className="text-slate-400 font-mono truncate">{key}</span>
                  <span className="text-base font-bold text-cyan-400 font-mono mt-1">
                    {val}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Mandatory Disclaimer (Section 3 & 5) */}
      <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl flex items-start gap-3 text-xs text-slate-400">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <span className="leading-relaxed">
          <strong className="text-slate-200">Disclaimer:</strong> {result.disclaimer}
        </span>
      </div>
    </div>
  );
};
