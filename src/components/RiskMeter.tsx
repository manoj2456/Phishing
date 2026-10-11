import React from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle, HelpCircle } from 'lucide-react';
import { ClassificationType, RiskLevelType } from '../types';

interface RiskMeterProps {
  score: number;
  classification: ClassificationType;
  riskLevel: RiskLevelType;
  confidence: number;
  size?: number;
}

export const RiskMeter: React.FC<RiskMeterProps> = ({
  score,
  classification,
  riskLevel,
  confidence,
  size = 220,
}) => {
  const normalizedScore = Math.max(0, Math.min(100, Math.round(score)));

  // SVG parameters
  const strokeWidth = 14;
  const radius = (size - strokeWidth * 2) / 2;
  const circumference = 2 * Math.PI * radius;
  // Sweep angle of 270 degrees for an open gauge arc
  const arcLength = circumference * 0.75;
  const strokeDashoffset = arcLength - (arcLength * normalizedScore) / 100;

  // Colors based on classification and risk level (consistent with Section 2, 3, 6)
  let strokeColor = '#10B981'; // Green for low risk (0-30)
  let glowColor = 'rgba(16, 185, 129, 0.25)';
  let textColor = 'text-emerald-400';
  let badgeBg = 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400';
  let Icon = ShieldCheck;
  let statusLabel = 'LOW RISK';
  let shortExplanation = 'Low detected risk based on normal structural characteristics.';

  if (classification === 'PHISHING' || normalizedScore > 60) {
    strokeColor = '#EF4444'; // Red for high risk (61-100)
    glowColor = 'rgba(239, 68, 68, 0.25)';
    textColor = 'text-red-400';
    badgeBg = 'bg-red-500/10 border-red-500/30 text-red-400';
    Icon = ShieldAlert;
    statusLabel = 'HIGH RISK';
    shortExplanation = 'Strong phishing indicators or hostile patterns detected.';
  } else if (classification === 'SUSPICIOUS' || (normalizedScore > 30 && normalizedScore <= 60)) {
    strokeColor = '#F59E0B'; // Orange/yellow for medium risk (31-60)
    glowColor = 'rgba(245, 158, 11, 0.25)';
    textColor = 'text-amber-400';
    badgeBg = 'bg-amber-500/10 border-amber-500/30 text-amber-400';
    Icon = AlertTriangle;
    statusLabel = 'MEDIUM RISK';
    shortExplanation = 'Multiple anomalous characteristics; further verification recommended.';
  } else if (classification === 'UNKNOWN' || riskLevel === 'UNKNOWN') {
    strokeColor = '#64748B'; // Grey for unknown or unavailable assessment
    glowColor = 'rgba(100, 116, 139, 0.25)';
    textColor = 'text-slate-400';
    badgeBg = 'bg-slate-700/20 border-slate-700/40 text-slate-300';
    Icon = HelpCircle;
    statusLabel = 'UNKNOWN / NEEDS VERIFICATION';
    shortExplanation = 'Insufficient evidence or ambiguous structure to classify safely.';
  }

  return (
    <div className="flex flex-col items-center justify-center p-6 bg-slate-900/60 border border-slate-800/80 rounded-2xl relative overflow-hidden">
      {/* Background radial glow */}
      <div
        className="absolute inset-0 pointer-events-none opacity-40 blur-3xl transition-colors duration-500"
        style={{
          background: `radial-gradient(circle at 50% 50%, ${glowColor} 0%, transparent 70%)`,
        }}
      />

      <div className="relative" style={{ width: size, height: size }}>
        <svg
          width={size}
          height={size}
          viewBox={`0 0 ${size} ${size}`}
          className="rotate-135 transform transition-transform"
        >
          {/* Background track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="#1E293B"
            strokeWidth={strokeWidth}
            strokeDasharray={`${arcLength} ${circumference}`}
            strokeLinecap="round"
          />
          {/* Active progress arc */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={strokeColor}
            strokeWidth={strokeWidth}
            strokeDasharray={`${arcLength} ${circumference}`}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            style={{
              transition: 'stroke-dashoffset 0.8s ease-out, stroke 0.4s ease',
            }}
          />
        </svg>

        {/* Center Readout */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <Icon className={`w-8 h-8 mb-1 ${textColor}`} />
          <div className="flex items-baseline justify-center">
            <span className={`text-4xl font-extrabold tracking-tight font-mono tabular-nums ${textColor}`}>
              {normalizedScore}
            </span>
            <span className="text-sm font-semibold text-slate-500 ml-1 font-mono">
              /100
            </span>
          </div>
          <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider mt-0.5">
            Risk Score
          </span>
        </div>
      </div>

      {/* Explanation text consistent with score & badge */}
      <p className="text-xs text-center text-slate-300 mt-2 max-w-xs">
        {shortExplanation}
      </p>

      {/* Meta indicators below meter */}
      <div className="w-full mt-4 pt-4 border-t border-slate-800/80 flex items-center justify-between text-xs">
        <div className="flex items-center gap-1.5">
          <span className="text-slate-400">Risk Level:</span>
          <span className={`font-semibold px-2 py-0.5 rounded border text-[11px] font-mono ${badgeBg}`}>
            {statusLabel}
          </span>
        </div>
        <div className="flex items-center gap-1 text-slate-400 font-mono">
          <span>Confidence:</span>
          <span className="font-semibold text-slate-200 tabular-nums">
            {Math.round(confidence * 100)}%
          </span>
        </div>
      </div>
    </div>
  );
};
