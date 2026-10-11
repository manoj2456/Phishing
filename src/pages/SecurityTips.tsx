import React, { useState } from 'react';
import {
  ShieldAlert,
  CheckCircle,
  KeyRound,
  Lock,
  Mail,
  AlertTriangle,
  Smartphone,
  Eye,
  RefreshCw,
  ExternalLink,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import conceptImage from '../assets/images/phishing_threat_concept_1791721606275.jpg';

export const SecurityTips: React.FC = () => {
  const [expandedTip, setExpandedTip] = useState<number | null>(null);

  const tips = [
    {
      id: 1,
      title: '1. Check the website domain carefully',
      summary: 'Inspect the exact characters in the address bar for typosquatting (e.g., paypa1.com or gooogle.com).',
      detail: 'Attackers frequently register lookalike domains substituting characters like numeric 1 for letter l, or adding hyphenated keywords like "paypal-security.com". Always read the domain name from right to left starting from the top-level domain.'
    },
    {
      id: 2,
      title: '2. Do not click suspicious links',
      summary: 'Instead of clicking directly on links in emails, SMS, or chat apps, manually type the known URL.',
      detail: 'Hover your cursor over hyperlinks before clicking to reveal the real destination address in the browser bottom corner. If it differs from what is displayed in the email text, do not click.'
    },
    {
      id: 3,
      title: '3. Never share OTPs (One-Time Passwords)',
      summary: 'Banks, payment apps, and tech companies will never ask you to disclose an SMS or authenticator OTP.',
      detail: 'An OTP is the final authorization step protecting your account. Sharing it enables an attacker to finalize fraudulent transactions or take over your profile.'
    },
    {
      id: 4,
      title: '4. Never share passwords through links received by email/SMS',
      summary: 'Legitimate service providers will never request passwords via incoming messages.',
      detail: 'If an email claims your account is suspended or locked, open your browser independently, navigate to the service homepage, and log in directly from there.'
    },
    {
      id: 5,
      title: '5. Check HTTPS, but remember HTTPS alone does not guarantee legitimacy',
      summary: 'Modern cybercriminals readily obtain free SSL certificates for malicious domains.',
      detail: 'The padlock icon only indicates that the connection between your device and the server is encrypted; it does NOT verify that the operator of the server is trustworthy. Over 80% of active phishing sites now utilize HTTPS.'
    },
    {
      id: 6,
      title: '6. Be careful with urgent messages',
      summary: 'Phishing lures deliberately manufacture panic or excitement ("Account suspended within 24 hours!").',
      detail: 'Cybercriminals rely on emotional urgency to bypass critical thinking. When faced with an alarming message demanding immediate action, pause and verify through official channels.'
    },
    {
      id: 7,
      title: '7. Avoid downloading unknown files',
      summary: 'Do not open invoice PDFs, zip archives, or executable scripts from unfamiliar senders.',
      detail: 'Malicious attachments can install infostealers or keyloggers capable of capturing entered passwords even on genuine websites.'
    },
    {
      id: 8,
      title: '8. Use Multi-Factor Authentication (MFA)',
      summary: 'Enable hardware keys or app-based authenticators wherever available.',
      detail: 'Even if your credentials are inadvertently compromised on a rogue phishing portal, MFA prevents the attacker from gaining unauthorized account entry.'
    },
    {
      id: 9,
      title: '9. Verify important websites through official sources',
      summary: 'Confirm contact numbers and support URLs via official paperwork or verified apps.',
      detail: 'Never trust support phone numbers or help links embedded in unverified text messages or emails claiming to represent your financial institution.'
    },
    {
      id: 10,
      title: '10. Keep browsers and operating systems updated',
      summary: 'Software updates deliver vital browser-level protection and anti-phishing telemetry.',
      detail: 'Modern web browsers include integrated malicious domain filters (such as Google Safe Browsing and Microsoft SmartScreen) that receive hourly threat intelligence feeds.'
    }
  ];

  const attackTypes = [
    {
      type: 'Spear Phishing',
      desc: 'Highly targeted attacks customized with personal information about a specific individual or organization.'
    },
    {
      type: 'Smishing (SMS Phishing)',
      desc: 'Deceptive text messages containing malicious links, often claiming package deliveries or bank alerts.'
    },
    {
      type: 'Vishing (Voice Phishing)',
      desc: 'Fraudulent phone calls impersonating law enforcement, tax officials, or bank fraud departments.'
    },
    {
      type: 'Clone Phishing',
      desc: 'Cloning a genuine email previously received and replacing the valid link or attachment with a malicious copy.'
    },
    {
      type: 'Whaling',
      desc: 'Phishing attacks specifically aimed at high-profile executives, CFOs, or company directors.'
    }
  ];

  return (
    <div className="space-y-12 max-w-5xl mx-auto pb-16">
      {/* Title */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-medium">
          <KeyRound className="w-3.5 h-3.5" />
          <span>Cyber Defense Best Practices</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
          Cybersecurity Safety Tips
        </h1>
        <p className="text-sm text-slate-400 max-w-2xl mx-auto">
          Essential guidelines and defensive habits to identify and neutralize social engineering attacks.
        </p>
      </div>

      {/* What is Phishing Callout Section */}
      <div className="p-6 sm:p-8 rounded-2xl bg-slate-900/80 border border-cyan-500/30 relative overflow-hidden">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
          <div className="md:col-span-7 space-y-4">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-cyan-400" />
              <span>What is Phishing?</span>
            </h2>
            <p className="text-sm text-slate-300 leading-relaxed">
              Phishing is a cyber attack where criminals create fake websites or messages designed to trick users into revealing passwords, OTPs, banking information, or other sensitive information.
            </p>
            <p className="text-xs text-slate-400 leading-relaxed">
              These malicious websites often mimic familiar organizations—such as banks, email providers, or streaming services—using lookalike domain names and counterfeit user interfaces.
            </p>
          </div>
          <div className="md:col-span-5 rounded-xl overflow-hidden border border-slate-800">
            <img
              src={conceptImage}
              alt="Phishing Inspection Concept"
              referrerPolicy="no-referrer"
              className="w-full h-44 object-cover object-center filter brightness-95"
            />
          </div>
        </div>
      </div>

      {/* 10 Beginner-Friendly Safety Tips Accordion */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold text-white">
            10 Fundamental Defensive Principles
          </h2>
          <span className="text-xs text-slate-400">Click any tip to expand details</span>
        </div>

        <div className="grid grid-cols-1 gap-3">
          {tips.map((tip) => {
            const isExpanded = expandedTip === tip.id;
            return (
              <div
                key={tip.id}
                className="bg-slate-900/60 border border-slate-800/80 rounded-xl overflow-hidden transition-all hover:border-slate-700"
              >
                <button
                  type="button"
                  onClick={() => setExpandedTip(isExpanded ? null : tip.id)}
                  className="w-full p-4 flex items-start justify-between text-left gap-4 cursor-pointer"
                >
                  <div className="space-y-1">
                    <h3 className="text-sm font-semibold text-slate-200">
                      {tip.title}
                    </h3>
                    <p className="text-xs text-slate-400">
                      {tip.summary}
                    </p>
                  </div>
                  <div className="text-slate-400 p-1">
                    {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </div>
                </button>

                {isExpanded && (
                  <div className="px-4 pb-4 pt-1 border-t border-slate-800/60 text-xs text-slate-300 leading-relaxed bg-slate-950/40">
                    <p>{tip.detail}</p>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Common Phishing Variations Section */}
      <div className="space-y-4">
        <h2 className="text-lg font-bold text-white">
          Common Forms of Phishing Attacks
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {attackTypes.map((atk) => (
            <div
              key={atk.type}
              className="p-5 rounded-2xl bg-slate-900/50 border border-slate-800/80 space-y-2"
            >
              <h3 className="text-sm font-bold text-cyan-400">
                {atk.type}
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                {atk.desc}
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
