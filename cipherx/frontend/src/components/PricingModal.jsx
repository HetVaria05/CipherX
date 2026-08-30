import React from 'react';
import { X, Check, Zap, Shield, Crown, Sparkles } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function PricingModal() {
  const { pricingModalOpen, setPricingModalOpen, user, openAuth } = useAuth();

  if (!pricingModalOpen) return null;

  const plans = [
    {
      name: 'Community Free',
      badge: 'Current Plan',
      price: '$0',
      period: 'forever',
      description: 'Essential heuristic protection and standard threat analysis.',
      features: [
        'Unlimited AI Heuristic scans',
        'Real-time phishing detection',
        '3 Advanced VirusTotal scans / day',
        'Basic DNS & network telemetry',
        'Community threat intel match',
      ],
      current: true,
      buttonText: 'Active Plan',
      buttonDisabled: true,
    },
    {
      name: 'CipherX Pro',
      badge: 'Most Popular',
      price: '$19',
      period: 'per month',
      highlight: true,
      description: 'Uncapped VirusTotal enterprise intelligence & deep payload scans.',
      features: [
        'Unlimited Advanced VirusTotal v3 scans',
        'Dedicated live-sandbox detonation',
        'Zero-rate-limit quota',
        'Full TLS certificate chain inspector',
        'Instant webhook & API integrations',
        'Priority threat response queue',
      ],
      current: false,
      buttonText: 'Upgrade to Pro',
      buttonDisabled: false,
    },
    {
      name: 'Enterprise SOC',
      badge: 'Custom',
      price: '$99',
      period: 'per month',
      description: 'Dedicated threat intelligence pipelines for security teams.',
      features: [
        'Everything in Pro',
        'Custom domain blocklist feed (RPZ/SIEM)',
        'Automated brand impersonation takedowns',
        'SLA 99.99% uptime guarantee',
        '24/7 dedicated cybersecurity engineer',
      ],
      current: false,
      buttonText: 'Contact Security Team',
      buttonDisabled: false,
    },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-4xl bg-vt-800 border border-vt-700 rounded-3xl shadow-2xl p-6 md:p-8 text-vt-text max-h-[90vh] overflow-y-auto">
        {/* Close Button */}
        <button
          onClick={() => setPricingModalOpen(false)}
          className="absolute top-5 right-5 text-vt-text hover:text-white p-2 rounded-xl hover:bg-vt-700/50 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Header */}
        <div className="text-center max-w-xl mx-auto mb-8">
          <span className="text-xs uppercase font-bold tracking-widest text-vt-accent px-3 py-1 rounded-full bg-vt-accent/10 border border-vt-accent/30 inline-block mb-2">
            Scan Quota & Plans
          </span>
          <h2 className="text-3xl font-extrabold text-vt-heading">Upgrade Your Threat Intelligence</h2>
          <p className="text-sm text-vt-text/80 mt-2">
            You receive 3 free Advanced VirusTotal scans daily. Unlock unlimited scans with CipherX Pro.
          </p>
        </div>

        {/* Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {plans.map((plan, i) => (
            <div
              key={i}
              className={`rounded-2xl p-6 flex flex-col justify-between transition-all ${
                plan.highlight
                  ? 'bg-gradient-to-b from-blue-950/40 to-vt-900 border-2 border-vt-accent shadow-[0_0_30px_rgba(46,96,255,0.2)]'
                  : 'bg-vt-900/80 border border-vt-700/70'
              }`}
            >
              <div>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-mono font-bold uppercase tracking-wider text-vt-text">
                    {plan.name}
                  </span>
                  <span
                    className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded-full ${
                      plan.highlight
                        ? 'bg-vt-accent text-white'
                        : 'bg-vt-800 text-vt-text border border-vt-700'
                    }`}
                  >
                    {plan.badge}
                  </span>
                </div>

                <div className="mb-4">
                  <span className="text-3xl font-extrabold text-white font-mono">{plan.price}</span>
                  <span className="text-xs text-vt-text/70 ml-1">/{plan.period}</span>
                </div>

                <p className="text-xs text-vt-text/80 mb-6 leading-relaxed">{plan.description}</p>

                <ul className="space-y-2.5 mb-6 text-xs text-vt-text">
                  {plan.features.map((feat, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <Check className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                      <span>{feat}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <button
                disabled={plan.buttonDisabled}
                onClick={() => {
                  if (!user) {
                    setPricingModalOpen(false);
                    openAuth('signup');
                  } else {
                    alert(`Selected ${plan.name}. Payment checkout flow sandbox ready.`);
                  }
                }}
                className={`w-full py-3 rounded-xl text-xs font-bold transition-colors flex items-center justify-center gap-1.5 ${
                  plan.highlight
                    ? 'bg-vt-accent hover:bg-blue-600 text-white shadow-lg shadow-blue-500/25'
                    : plan.buttonDisabled
                    ? 'bg-vt-800 text-vt-text/40 border border-vt-700/50 cursor-default'
                    : 'bg-vt-800 hover:bg-vt-700 text-white border border-vt-700'
                }`}
              >
                {plan.highlight && <Crown className="w-3.5 h-3.5" />}
                {plan.buttonText}
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
