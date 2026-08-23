import React from 'react';
import { ShieldAlert, ShieldCheck, Shield, AlertTriangle, AlertOctagon, CheckCircle2 } from 'lucide-react';
import clsx from 'clsx';

const getRiskColor = (classification) => {
  switch (classification) {
    case 'LOW': return 'text-green-500';
    case 'SUSPICIOUS': return 'text-yellow-500';
    case 'HIGH': return 'text-orange-500';
    case 'CRITICAL': return 'text-red-600';
    default: return 'text-slate-400';
  }
};

const getRiskBg = (classification) => {
  switch (classification) {
    case 'LOW': return 'bg-green-500/10 border-green-500/20';
    case 'SUSPICIOUS': return 'bg-yellow-500/10 border-yellow-500/20';
    case 'HIGH': return 'bg-orange-500/10 border-orange-500/20';
    case 'CRITICAL': return 'bg-red-600/10 border-red-600/20';
    default: return 'bg-slate-800 border-slate-700';
  }
};

const RiskIcon = ({ classification, className }) => {
  switch (classification) {
    case 'LOW': return <ShieldCheck className={className} />;
    case 'SUSPICIOUS': return <AlertTriangle className={className} />;
    case 'HIGH': return <ShieldAlert className={className} />;
    case 'CRITICAL': return <AlertOctagon className={className} />;
    default: return <Shield className={className} />;
  }
};

export default function ResultDashboard({ result }) {
  if (!result) return null;

  const {
    url,
    normalized_url,
    risk_score,
    classification,
    confidence,
    signals,
    features,
    adversarial_findings,
    brand_analysis,
    explanation
  } = result;

  return (
    <div className="w-full max-w-5xl mx-auto mt-8 space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      
      {/* Header Panel */}
      <div className={clsx("p-6 rounded-xl border", getRiskBg(classification))}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="flex items-center gap-4">
            <div className={clsx("p-4 rounded-full bg-dark-900 shadow-inner", getRiskColor(classification))}>
              <RiskIcon classification={classification} className="w-10 h-10" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-slate-400 tracking-wider uppercase mb-1">CipherX Analysis</h2>
              <div className="flex items-baseline gap-3">
                <span className={clsx("text-4xl font-bold tracking-tight", getRiskColor(classification))}>
                  {risk_score}/100
                </span>
                <span className={clsx("text-xl font-medium tracking-wide", getRiskColor(classification))}>
                  {classification}
                </span>
              </div>
            </div>
          </div>
          
          <div className="bg-dark-900/50 p-4 rounded-lg border border-slate-700/50 text-right">
            <p className="text-sm text-slate-400 mb-1">Confidence Score</p>
            <p className="text-2xl font-semibold text-slate-200">{(confidence * 100).toFixed(0)}%</p>
          </div>
        </div>
        
        <div className="mt-6 pt-6 border-t border-slate-700/50">
          <p className="text-sm text-slate-400 mb-1">Analyzed URL</p>
          <p className="text-slate-200 font-mono text-sm break-all">{url}</p>
          {normalized_url && normalized_url !== url && (
            <>
              <p className="text-sm text-slate-400 mb-1 mt-4">Normalized URL</p>
              <p className="text-slate-300 font-mono text-sm break-all">{normalized_url}</p>
            </>
          )}
        </div>
        
        {explanation && (
          <div className="mt-4 bg-dark-900/40 p-4 rounded-lg border border-slate-700/30">
            <p className="text-slate-300 text-sm leading-relaxed">{explanation}</p>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Evidence Column */}
        <div className="space-y-6">
          <div className="bg-dark-800 p-6 rounded-xl border border-slate-700 shadow-sm">
            <h3 className="text-lg font-semibold text-slate-200 mb-4 flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-indigo-400" />
              Evidence & Signals
            </h3>
            {signals && signals.length > 0 ? (
              <ul className="space-y-3">
                {signals.map((sig, i) => (
                  <li key={i} className="flex items-start gap-3 text-sm text-slate-300">
                    <span className="mt-0.5">
                      {sig.severity === 'high' ? (
                        <AlertOctagon className="w-4 h-4 text-red-500" />
                      ) : sig.severity === 'medium' ? (
                        <AlertTriangle className="w-4 h-4 text-yellow-500" />
                      ) : (
                        <CheckCircle2 className="w-4 h-4 text-green-500" />
                      )}
                    </span>
                    <span>
                      <span className="block">{sig.name || sig.signal}</span>
                      {sig.reason && <span className="block text-slate-500 text-xs mt-0.5">{sig.reason}</span>}
                      {typeof sig.score === 'number' && (
                        <span className="block text-slate-500 text-xs mt-0.5">Risk contribution: +{sig.score}</span>
                      )}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-slate-500">No specific evidence signals generated.</p>
            )}
          </div>

          {brand_analysis && (brand_analysis.impersonated_brand || brand_analysis.best_match) && (
            <div className="bg-dark-800 p-6 rounded-xl border border-slate-700 shadow-sm">
              <h3 className="text-lg font-semibold text-slate-200 mb-4">Brand Analysis</h3>
              <div className="space-y-2 text-sm text-slate-300">
                {brand_analysis.best_match?.official_domain_matches && (
                  <div className="flex justify-between">
                    <span className="text-slate-400">Official Domain:</span>
                    <span className="font-medium text-green-400">{brand_analysis.best_match.official_domain}</span>
                  </div>
                )}
                <div className="flex justify-between">
                  <span className="text-slate-400">Detected Brand:</span>
                  <span className="font-medium text-orange-400">
                    {brand_analysis.impersonated_brand || brand_analysis.best_match?.detected_brand || 'None'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Similarity Score:</span>
                  <span>{(brand_analysis.similarity_score * 100).toFixed(0)}%</span>
                </div>
                {brand_analysis.best_match && !brand_analysis.best_match.official_domain_matches && (
                  <>
                    <div className="flex justify-between gap-4">
                      <span className="text-slate-400">Analyzed Domain:</span>
                      <span className="font-mono text-right break-all">{brand_analysis.best_match.analyzed_domain}</span>
                    </div>
                    <div className="flex justify-between gap-4">
                      <span className="text-slate-400">Official Domain:</span>
                      <span className="font-mono text-right break-all">{brand_analysis.best_match.official_domain}</span>
                    </div>
                  </>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Features & Adversarial Column */}
        <div className="space-y-6">
          {adversarial_findings && adversarial_findings.length > 0 && (
            <div className="bg-dark-800 p-6 rounded-xl border border-red-900/50 shadow-sm relative overflow-hidden">
              <div className="absolute top-0 left-0 w-1 h-full bg-red-600"></div>
              <h3 className="text-lg font-semibold text-red-400 mb-4 flex items-center gap-2">
                <AlertOctagon className="w-5 h-5" />
                Adversarial Findings
              </h3>
              <ul className="space-y-2">
                {adversarial_findings.map((finding, i) => (
                  <li key={i} className="text-sm text-slate-300 flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-red-500"></span>
                    <span>
                      <span className="block">{finding.technique ? finding.technique.replace(/_/g, ' ') : String(finding)}</span>
                      {finding.reason && <span className="block text-slate-500 text-xs mt-0.5">{finding.reason}</span>}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="bg-dark-800 p-6 rounded-xl border border-slate-700 shadow-sm">
            <h3 className="text-lg font-semibold text-slate-200 mb-4">Extracted Features</h3>
            {features ? (
              <div className="grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
                {Object.entries(features).map(([key, val]) => (
                  <div key={key} className="flex flex-col">
                    <span className="text-slate-500 text-xs uppercase tracking-wider">{key.replace(/_/g, ' ')}</span>
                    <span className="text-slate-200 font-mono mt-1">
                      {typeof val === 'boolean' ? (val ? 'True' : 'False') : val}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-slate-500">No feature data available.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
