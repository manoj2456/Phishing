import React, { useState } from 'react';
import { Trash2, Download, Search, History as HistoryIcon, ArrowUpRight, ShieldCheck, ShieldAlert, AlertTriangle, HelpCircle } from 'lucide-react';
import { ScanHistoryItem } from '../types';

interface HistoryProps {
  history: ScanHistoryItem[];
  onClearHistory: () => Promise<void>;
  onSelectUrl: (url: string) => void;
  isLoading: boolean;
}

export const History: React.FC<HistoryProps> = ({
  history,
  onClearHistory,
  onSelectUrl,
  isLoading,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterStatus, setFilterStatus] = useState<string>('ALL');

  const filteredHistory = history.filter((item) => {
    const matchesSearch = item.url.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus = filterStatus === 'ALL' || item.classification === filterStatus;
    return matchesSearch && matchesStatus;
  });

  const handleExportCSV = () => {
    if (history.length === 0) return;
    const headers = ['ID', 'URL', 'Risk Score', 'Risk Level', 'Classification', 'Confidence', 'Scanned At', 'Main Indicators'];
    const rows = history.map((item) => [
      item.id,
      `"${item.url.replace(/"/g, '""')}"`,
      item.risk_score,
      item.risk_level || (item.risk_score <= 30 ? 'LOW' : item.risk_score <= 60 ? 'MEDIUM' : 'HIGH'),
      item.classification,
      `${Math.round(item.confidence * 100)}%`,
      `"${item.scanned_at}"`,
      `"${(item.main_indicators || []).join('; ').replace(/"/g, '""')}"`,
    ]);
    const csvContent = [headers.join(','), ...rows.map((e) => e.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `phishguard_scan_history_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-8 max-w-6xl mx-auto pb-16">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-medium mb-2">
            <HistoryIcon className="w-3.5 h-3.5" />
            <span>SQLite Database Log</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Scan History
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Persisted record of analyzed URLs, risk metrics, and detected indicators. Passwords and sensitive data are never stored.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportCSV}
            disabled={history.length === 0}
            className="px-3.5 py-2 bg-slate-900 border border-slate-700 hover:border-slate-600 disabled:opacity-40 text-slate-300 text-xs font-semibold rounded-xl flex items-center gap-1.5 transition-colors cursor-pointer disabled:cursor-not-allowed"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={onClearHistory}
            disabled={history.length === 0 || isLoading}
            className="px-3.5 py-2 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 disabled:opacity-40 text-red-400 text-xs font-semibold rounded-xl flex items-center gap-1.5 transition-colors cursor-pointer disabled:cursor-not-allowed"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear History</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 bg-slate-900/60 border border-slate-800/80 rounded-2xl flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by URL or domain..."
            className="w-full pl-9 pr-3 py-2 bg-slate-950/60 border border-slate-800 rounded-xl text-xs sm:text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        {/* Filter Segmented Buttons */}
        <div className="flex items-center gap-1 p-1 bg-slate-950/80 border border-slate-800 rounded-xl shrink-0 overflow-x-auto">
          {['ALL', 'SAFE', 'SUSPICIOUS', 'PHISHING'].map((status) => (
            <button
              key={status}
              onClick={() => setFilterStatus(status)}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors whitespace-nowrap cursor-pointer ${
                filterStatus === status
                  ? 'bg-slate-800 text-cyan-400 border border-slate-700/60 shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {status}
            </button>
          ))}
        </div>
      </div>

      {/* History Table */}
      <div className="bg-slate-900/60 border border-slate-800/80 rounded-2xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs sm:text-sm">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/80 text-slate-400 text-xs font-medium uppercase font-mono tracking-wider">
                <th className="py-3.5 px-4">Scanned URL</th>
                <th className="py-3.5 px-4 text-center">Score & Level</th>
                <th className="py-3.5 px-4">Classification</th>
                <th className="py-3.5 px-4">Main Detected Indicators</th>
                <th className="py-3.5 px-4 text-right">Date & Time</th>
                <th className="py-3.5 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredHistory.length > 0 ? (
                filteredHistory.map((item) => {
                  let badge = 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
                  let Icon = ShieldCheck;
                  const itemRiskLevel = item.risk_level || (item.risk_score <= 30 ? 'LOW' : item.risk_score <= 60 ? 'MEDIUM' : 'HIGH');

                  if (item.classification === 'PHISHING') {
                    badge = 'text-red-400 bg-red-500/10 border-red-500/30';
                    Icon = ShieldAlert;
                  } else if (item.classification === 'SUSPICIOUS') {
                    badge = 'text-amber-400 bg-amber-500/10 border-amber-500/30';
                    Icon = AlertTriangle;
                  } else if (item.classification === 'UNKNOWN') {
                    badge = 'text-slate-300 bg-slate-700/20 border-slate-700';
                    Icon = HelpCircle;
                  }

                  return (
                    <tr
                      key={item.id}
                      className="hover:bg-slate-850/60 transition-colors group"
                    >
                      <td className="py-3.5 px-4 max-w-xs sm:max-w-sm truncate text-slate-200">
                        <span className="font-sans font-medium text-slate-200 block truncate" title={item.url}>
                          {item.url}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 text-center">
                        <span className="tabular-nums font-bold text-slate-100 text-sm">
                          {item.risk_score}
                        </span>
                        <span className="text-[11px] text-slate-500">/100</span>
                        <div className="text-[10px] text-slate-400 uppercase tracking-wider font-sans">
                          {itemRiskLevel}
                        </div>
                      </td>
                      <td className="py-3.5 px-4">
                        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-[11px] font-sans font-semibold ${badge}`}>
                          <Icon className="w-3 h-3" />
                          <span>{item.classification}</span>
                        </span>
                      </td>
                      <td className="py-3.5 px-4 font-sans text-xs text-slate-300 max-w-xs">
                        {item.main_indicators && item.main_indicators.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {item.main_indicators.map((ind, i) => (
                              <span key={i} className="text-[11px] px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 truncate max-w-[200px]" title={ind}>
                                {ind}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span className="text-slate-500 text-xs italic">Normal profile</span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 text-right text-slate-400 text-xs tabular-nums font-sans whitespace-nowrap">
                        {item.scanned_at}
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={() => onSelectUrl(item.url)}
                          className="px-2.5 py-1 text-xs font-sans text-cyan-400 hover:text-cyan-300 hover:bg-cyan-500/10 rounded border border-cyan-500/20 transition-colors inline-flex items-center gap-1 cursor-pointer"
                        >
                          <span>Re-Scan</span>
                          <ArrowUpRight className="w-3 h-3" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500 font-sans">
                    {searchQuery
                      ? 'No scan records match your search criteria.'
                      : 'No URLs scanned yet. Run a scan from the Scanner page!'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
