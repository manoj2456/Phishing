import React from 'react';
import { Shield, Cpu, Database, Layout, GitBranch, Layers, Sparkles, AlertCircle } from 'lucide-react';

export const About: React.FC = () => {
  return (
    <div className="space-y-12 max-w-5xl mx-auto pb-16">
      {/* Title */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-medium">
          <Shield className="w-3.5 h-3.5" />
          <span>Department of Computer Science & Engineering</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          About PhishGuard
        </h1>
        <p className="text-sm text-slate-400 max-w-2xl mx-auto">
          An educational cybersecurity mini-project implementing machine learning and lexical heuristic analysis to detect deceptive web links.
        </p>
      </div>

      {/* Project Meta Card */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 grid grid-cols-2 sm:grid-cols-4 gap-4 text-center sm:text-left">
        <div>
          <span className="text-[11px] text-slate-400 uppercase font-mono">Project Title</span>
          <p className="text-base font-bold text-white mt-0.5">PhishGuard</p>
        </div>
        <div>
          <span className="text-[11px] text-slate-400 uppercase font-mono">Project Type</span>
          <p className="text-base font-bold text-cyan-400 mt-0.5">CSE Mini Project</p>
        </div>
        <div>
          <span className="text-[11px] text-slate-400 uppercase font-mono">Architecture</span>
          <p className="text-base font-bold text-white mt-0.5">React + Flask + ML</p>
        </div>
        <div>
          <span className="text-[11px] text-slate-400 uppercase font-mono">Primary Model</span>
          <p className="text-base font-bold text-emerald-400 mt-0.5">Random Forest</p>
        </div>
      </div>

      {/* Problem Statement & Proposed Solution */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-red-400" />
            <span>Problem Statement</span>
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 leading-relaxed">
            Phishing continues to be one of the most widespread initial access vectors for cyberattacks. Conventional blacklists cannot keep pace with ephemeral phishing domains generated automatically every minute. Inexperienced internet users often mistake HTTPS encryption for complete website legitimacy, leading to credential harvesting and financial fraud.
          </p>
        </div>

        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            <span>Proposed Solution</span>
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 leading-relaxed">
            PhishGuard introduces a multi-tier defense architecture. By safely parsing the syntactic, lexical, and structural characteristics of a candidate URL—without executing remote scripts or downloading untrusted files—the system extracts 20 key features, evaluates them via a trained Random Forest model, and returns an explainable risk assessment.
          </p>
        </div>
      </div>

      {/* Technology Stack Grid */}
      <div className="space-y-4">
        <h2 className="text-lg font-bold text-white">System Technologies</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-5 rounded-2xl bg-slate-900/50 border border-slate-800 space-y-2">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 text-cyan-400 flex items-center justify-center">
              <Layout className="w-4 h-4" />
            </div>
            <h3 className="text-sm font-bold text-white">Frontend</h3>
            <p className="text-xs text-slate-400">
              React 19, Vite, Tailwind CSS, Lucide icons, responsive dark-navy theme.
            </p>
          </div>

          <div className="p-5 rounded-2xl bg-slate-900/50 border border-slate-800 space-y-2">
            <div className="w-8 h-8 rounded-lg bg-blue-500/10 text-blue-400 flex items-center justify-center">
              <Cpu className="w-4 h-4" />
            </div>
            <h3 className="text-sm font-bold text-white">Backend</h3>
            <p className="text-xs text-slate-400">
              Python Flask / REST API with JSON contract, input sanitization, and health check.
            </p>
          </div>

          <div className="p-5 rounded-2xl bg-slate-900/50 border border-slate-800 space-y-2">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 text-emerald-400 flex items-center justify-center">
              <GitBranch className="w-4 h-4" />
            </div>
            <h3 className="text-sm font-bold text-white">Machine Learning</h3>
            <p className="text-xs text-slate-400">
              Random Forest Classifier, scikit-learn, 20 extracted features, Confusion Matrix.
            </p>
          </div>

          <div className="p-5 rounded-2xl bg-slate-900/50 border border-slate-800 space-y-2">
            <div className="w-8 h-8 rounded-lg bg-purple-500/10 text-purple-400 flex items-center justify-center">
              <Database className="w-4 h-4" />
            </div>
            <h3 className="text-sm font-bold text-white">Database</h3>
            <p className="text-xs text-slate-400">
              SQLite relational database storing scan records without sensitive credentials.
            </p>
          </div>
        </div>
      </div>

      {/* Machine Learning Approach */}
      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <Layers className="w-5 h-5 text-cyan-400" />
          <span>Machine Learning Methodology</span>
        </h2>
        <div className="space-y-3 text-xs sm:text-sm text-slate-300 leading-relaxed">
          <p>
            1. <strong>Dataset Ingestion:</strong> The pipeline loads labeled records of known benign and malicious URLs from <code className="text-cyan-300">phishing_urls.csv</code>.
          </p>
          <p>
            2. <strong>Feature Engineering:</strong> The <code className="text-cyan-300">feature_extractor.py</code> module calculates 20 numerical parameters capturing domain complexity, path depth, character distributions, and lure keywords.
          </p>
          <p>
            3. <strong>Ensemble Training:</strong> A Random Forest classifier builds multiple decision trees with bootstrapped subsets, aggregating predictions to prevent individual tree overfitting.
          </p>
          <p>
            4. <strong>Scoring & Output:</strong> Probability output is scaled to a risk metric (0–100), mapped into discrete risk classes, and supplemented with explainable warning cues.
          </p>
        </div>
      </div>

      {/* Limitations & Future Enhancements */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-amber-400" />
            <span>Current Limitations</span>
          </h2>
          <ul className="space-y-2 text-xs sm:text-sm text-slate-400 list-disc list-inside">
            <li>Relies on static URL lexical features without dynamic browser rendering.</li>
            <li>Does not inspect DOM content, rendered logos, or form submission targets.</li>
            <li>Advanced cloaking techniques targeting specific IP ranges are not evaluated.</li>
            <li>Demonstration dataset size is focused on core academic evaluation patterns.</li>
          </ul>
        </div>

        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <span>Future Enhancements</span>
          </h2>
          <ul className="space-y-2 text-xs sm:text-sm text-slate-400 list-disc list-inside">
            <li>Browser extension for automated real-time webpage verification.</li>
            <li>QR-code scanner module for mobile camera inputs.</li>
            <li>WHOIS registration age and DNS reputation checks.</li>
            <li>Deep Learning (LSTM / Transformer) sequence model for raw URL string embeddings.</li>
            <li>Multilingual safety education tips and localized lure keywords.</li>
          </ul>
        </div>
      </div>
    </div>
  );
};
