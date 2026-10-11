import React from 'react';
import { ExtractedFeatures } from '../types';

interface FeatureChartProps {
  features: ExtractedFeatures;
}

interface ChartItem {
  label: string;
  value: number;
  max: number;
  unit: string;
  status: 'safe' | 'warning' | 'danger';
  thresholdNote: string;
}

export const FeatureChart: React.FC<FeatureChartProps> = ({ features }) => {
  // Map extracted features into comparative metrics
  const items: ChartItem[] = [
    {
      label: 'URL Length',
      value: features.url_length,
      max: 120,
      unit: 'chars',
      status: features.url_length > 75 ? 'danger' : features.url_length > 50 ? 'warning' : 'safe',
      thresholdNote: 'Safe: <54 chars | Phishing avg: >75 chars',
    },
    {
      label: 'Domain Length & Complexity',
      value: features.domain_length,
      max: 60,
      unit: 'chars',
      status: features.domain_length > 30 ? 'danger' : features.domain_length > 20 ? 'warning' : 'safe',
      thresholdNote: 'Normal domain length is usually 8–24 chars',
    },
    {
      label: 'Special Characters',
      value: features.num_special_chars,
      max: 20,
      unit: 'symbols',
      status: features.num_special_chars > 8 ? 'danger' : features.num_special_chars > 4 ? 'warning' : 'safe',
      thresholdNote: 'Excessive punctuation often hides payloads',
    },
    {
      label: 'Suspicious Keywords',
      value: features.suspicious_keyword_count,
      max: 5,
      unit: 'matches',
      status: features.suspicious_keyword_count >= 2 ? 'danger' : features.suspicious_keyword_count === 1 ? 'warning' : 'safe',
      thresholdNote: 'e.g. login, verify, banking, update, confirm',
    },
    {
      label: 'Subdomain Count',
      value: features.num_subdomains,
      max: 6,
      unit: 'levels',
      status: features.excessive_subdomains ? 'danger' : features.num_subdomains > 1 ? 'warning' : 'safe',
      thresholdNote: '>2 subdomains indicates deep masquerading',
    },
    {
      label: 'HTTPS Security',
      value: features.has_https ? 1 : 0,
      max: 1,
      unit: features.has_https ? 'SSL Active' : 'Plaintext HTTP',
      status: features.has_https ? 'safe' : 'danger',
      thresholdNote: 'HTTP lacks encryption; HTTPS is required baseline',
    },
  ];

  return (
    <div className="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-6">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-base font-semibold text-white">
            Feature Characteristic Breakdown
          </h3>
          <p className="text-xs text-slate-400">
            Key lexical dimensions extracted from the URL compared against baseline profiles
          </p>
        </div>
      </div>

      <div className="space-y-4">
        {items.map((item) => {
          const percentage = Math.min(100, Math.round((item.value / item.max) * 100));

          let barColor = 'bg-emerald-500';
          let textColor = 'text-emerald-400';
          let statusText = 'Normal';

          if (item.status === 'danger') {
            barColor = 'bg-red-500';
            textColor = 'text-red-400';
            statusText = 'High Risk';
          } else if (item.status === 'warning') {
            barColor = 'bg-amber-500';
            textColor = 'text-amber-400';
            statusText = 'Unusual';
          }

          return (
            <div key={item.label} className="group">
              <div className="flex items-center justify-between text-xs mb-1">
                <span className="font-medium text-slate-300">{item.label}</span>
                <div className="flex items-center gap-2 font-mono">
                  <span className="text-slate-400">{item.value} {item.unit}</span>
                  <span className={`text-[11px] font-semibold ${textColor}`}>
                    [{statusText}]
                  </span>
                </div>
              </div>

              {/* Progress track */}
              <div className="w-full h-2.5 bg-slate-800 rounded-full overflow-hidden p-0.5">
                <div
                  className={`h-full rounded-full transition-all duration-700 ease-out ${barColor}`}
                  style={{ width: `${Math.max(5, percentage)}%` }}
                />
              </div>

              <div className="mt-1 text-[11px] text-slate-500 flex justify-between">
                <span>{item.thresholdNote}</span>
                <span className="font-mono text-slate-500">Max ref: {item.max}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
