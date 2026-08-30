import React from 'react';
import { ShieldAlert, ShieldCheck, Shield, AlertTriangle, AlertOctagon, CheckCircle2, Database, Globe, Network, Radio } from 'lucide-react';
import clsx from 'clsx';
import { useLanguage } from '../context/LanguageContext';

const getRiskColor = (classification) => {
  switch (classification) {
    case 'LOW': return 'text-emerald-500 dark:text-emerald-400';
    case 'SUSPICIOUS': return 'text-amber-500 dark:text-amber-400';
    case 'HIGH': return 'text-orange-500 dark:text-orange-400';
    case 'CRITICAL': return 'text-red-500 dark:text-red-400';
    default: return 'text-vt-text';
  }
};

const getRiskBg = (classification) => {
  switch (classification) {
    case 'LOW': return 'bg-emerald-500/10 border-emerald-500/30';
    case 'SUSPICIOUS': return 'bg-amber-500/10 border-amber-500/30';
    case 'HIGH': return 'bg-orange-500/15 border-orange-500/30';
    case 'CRITICAL': return 'bg-red-500/15 border-red-500/30';
    default: return 'bg-vt-800 border-vt-700';
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
  const { t } = useLanguage();
  if (!result) return null;

  const {
    url,
    risk_score,
    classification,
    confidence,
    signals,
    explanation
  } = result;

  const baseAnalysis = result.base_analysis || {};
  const features = result.features || baseAnalysis.features;
  const adversarial_findings = result.adversarial_findings || baseAnalysis.adversarial_findings;
  const brand_analysis = result.brand_analysis || baseAnalysis.brand_analysis;

  const threatIntelMatch = features?.threat_intel_match;
  const networkData = result.network || (result.advanced && result.advanced.network) || baseAnalysis.network;

  return (
    <div className="w-full max-w-4xl mx-auto space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500 text-vt-text">
      
      {/* Header Panel */}
      <div className={clsx("p-6 rounded-2xl border backdrop-blur-sm", getRiskBg(classification))}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="flex items-center gap-4">
            <div className={clsx("p-4 rounded-2xl bg-vt-900 border border-vt-700 shadow-inner", getRiskColor(classification))}>
              <RiskIcon classification={classification} className="w-10 h-10" />
            </div>
            <div>
              <h2 className="text-xs font-bold text-vt-text tracking-widest uppercase mb-1">{t('res_base_engine')}</h2>
              <div className="flex items-baseline gap-3">
                <span className={clsx("text-4xl font-extrabold tracking-tight", getRiskColor(classification))}>
                  {risk_score}/100
                </span>
                <span className={clsx("text-lg font-bold tracking-wide uppercase px-2.5 py-0.5 rounded-full bg-vt-900 border border-vt-700", getRiskColor(classification))}>
                  {classification}
                </span>
              </div>
            </div>
          </div>
          
          <div className="bg-vt-900/90 p-4 rounded-xl border border-vt-700/60 text-right">
            <p className="text-xs text-vt-text uppercase tracking-wider mb-1">{t('res_confidence')}</p>
            <p className="text-2xl font-bold text-vt-heading">{(confidence * 100).toFixed(0)}%</p>
          </div>
        </div>
        
        {/* Threat Intel Match Alert Banner */}
        {threatIntelMatch && (
          <div className="mt-5 p-4 rounded-xl bg-red-950/60 border border-red-500/50 flex items-start gap-3">
            <Database className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-red-300 text-sm">{t('res_intel_match_title')}</span>
                <span className="text-xs px-2 py-0.5 rounded bg-red-900/80 text-red-200 border border-red-700 font-mono">
                  {threatIntelMatch.source}
                </span>
              </div>
              <p className="text-xs text-red-200/90 mt-1">
                Identified as <strong className="text-white">{threatIntelMatch.threat_type || 'Malicious URL'}</strong>
                {threatIntelMatch.family && ` (Threat Family: ${threatIntelMatch.family})`}.
              </p>
            </div>
          </div>
        )}

        <div className="mt-6 pt-5 border-t border-vt-700/60">
          <p className="text-xs text-vt-text uppercase tracking-wider mb-1">{t('tab_url')}</p>
          <p className="text-vt-heading font-mono text-sm break-all">{url}</p>
        </div>
        
        {explanation && (
          <div className="mt-4 bg-vt-900/80 p-4 rounded-xl border border-vt-700/60">
            <p className="text-vt-heading text-sm leading-relaxed">{t(explanation)}</p>
          </div>
        )}
      </div>

      {/* Main Analysis Sections - Stacked Layout */}
      <div className="space-y-6">
        
        {/* Adversarial Findings (Top priority alert if present) */}
        {adversarial_findings && adversarial_findings.length > 0 && (
          <div className="bg-vt-800 p-6 rounded-2xl border border-red-500/40 shadow-lg relative overflow-hidden">
            <div className="absolute top-0 left-0 w-1.5 h-full bg-red-500"></div>
            <h3 className="text-md font-bold text-red-500 dark:text-red-400 mb-4 flex items-center gap-2">
              <AlertOctagon className="w-5 h-5" />
              {t('res_adversarial_title')}
            </h3>
            <ul className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {adversarial_findings.map((finding, i) => (
                <li key={i} className="text-sm bg-red-500/10 p-3.5 rounded-xl border border-red-500/20">
                  <span className="font-bold text-red-600 dark:text-red-300 block text-xs capitalize">
                    {finding.technique ? finding.technique.replace(/_/g, ' ') : String(finding)}
                  </span>
                  {finding.reason && <span className="block text-vt-text text-xs mt-1">{t(finding.reason)}</span>}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Full-Width Evidence & Signals */}
        <div className="bg-vt-800 p-6 rounded-2xl border border-vt-700 shadow-lg">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-md font-bold text-vt-heading flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-vt-accent" />
              {t('res_evidence_title')} ({signals ? signals.length : 0})
            </h3>
            {signals && signals.length > 0 && (
              <span className="text-xs px-2.5 py-1 rounded-full bg-vt-900 border border-vt-700 text-vt-text font-mono">
                {signals.length} {t('res_signals_triggered')}
              </span>
            )}
          </div>

          {signals && signals.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {signals.map((sig, i) => (
                <div key={i} className="flex items-start gap-3.5 text-sm bg-vt-900/80 p-4 rounded-xl border border-vt-700/60 hover:border-vt-accent/50 transition-colors">
                  <span className="mt-0.5 flex-shrink-0">
                    {sig.severity === 'critical' || sig.severity === 'high' ? (
                      <AlertOctagon className="w-4 h-4 text-red-500" />
                    ) : sig.severity === 'medium' ? (
                      <AlertTriangle className="w-4 h-4 text-amber-500" />
                    ) : (
                      <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                    )}
                  </span>
                  <div className="flex-1">
                    <div className="flex justify-between items-center">
                      <span className="font-semibold text-vt-heading text-xs">{t(sig.name || sig.signal)}</span>
                      {typeof sig.score === 'number' && (
                        <span className="text-xs font-mono text-vt-accent font-semibold px-2 py-0.5 rounded bg-vt-800 border border-vt-700">+{sig.score}</span>
                      )}
                    </div>
                    {sig.reason && <span className="block text-vt-text text-xs mt-1.5 leading-relaxed">{t(sig.reason)}</span>}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30">
              <p className="text-sm text-emerald-600 dark:text-emerald-400 flex items-center gap-2 font-medium">
                <CheckCircle2 className="w-4 h-4" /> {t('res_no_signals')}
              </p>
            </div>
          )}
        </div>

        {/* Brand & Impersonation Analysis (if applicable) */}
        {brand_analysis && (brand_analysis.impersonated_brand || brand_analysis.best_match) && (
          <div className="bg-vt-800 p-6 rounded-2xl border border-vt-700 shadow-lg">
            <h3 className="text-md font-bold text-vt-heading mb-4 flex items-center gap-2">
              <Globe className="w-5 h-5 text-vt-accent" />
              {t('res_brand_title')}
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
              <div className="bg-vt-900/80 p-3.5 rounded-xl border border-vt-700/60">
                <span className="text-vt-text text-xs block mb-1">{t('res_brand_target')}</span>
                <span className="font-bold text-vt-heading text-sm">
                  {brand_analysis.impersonated_brand || brand_analysis.best_match?.detected_brand || 'None'}
                </span>
              </div>
              <div className="bg-vt-900/80 p-3.5 rounded-xl border border-vt-700/60">
                <span className="text-vt-text text-xs block mb-1">{t('res_brand_match')}</span>
                <span className="font-mono font-bold text-vt-heading text-sm">
                  {((brand_analysis.similarity_score ?? 0) * 100).toFixed(0)}%
                </span>
              </div>
              {brand_analysis.best_match && (
                <div className="bg-vt-900/80 p-3.5 rounded-xl border border-vt-700/60">
                  <span className="text-vt-text text-xs block mb-1">{t('res_brand_official')}</span>
                  <span className="font-mono text-emerald-500 dark:text-emerald-400 text-sm font-semibold">{brand_analysis.best_match.official_domain}</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Advanced Intelligence Section (VirusTotal) */}
        {result.advanced && result.advanced.virustotal && (
          <div className="space-y-6">
            <div className="bg-vt-800 p-6 rounded-2xl border border-vt-700 shadow-lg">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6">
                <div>
                  <h3 className="text-md font-bold text-vt-heading flex items-center gap-2">
                    <Radio className="w-5 h-5 text-vt-accent" />
                    {t('res_vt_title')}
                  </h3>
                  <p className="text-xs text-vt-text/70 mt-0.5">
                    Multi-engine antivirus & blacklisting vendor consensus
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono uppercase px-2.5 py-1 rounded bg-vt-900 border border-vt-700 text-vt-text">
                    {t('res_vt_status')}: {result.advanced.virustotal.status || 'unknown'}
                  </span>
                </div>
              </div>

              {result.advanced.virustotal.stats ? (
                <div className="space-y-6">
                  {/* VirusTotal Specific Risk Score Banner */}
                  <div className="p-4 rounded-xl bg-vt-900/90 border border-vt-700/80 flex flex-col sm:flex-row items-center justify-between gap-4">
                    <div className="flex items-center gap-3.5">
                      <div className={clsx(
                        "w-12 h-12 rounded-xl flex items-center justify-center font-mono font-bold text-lg border",
                        (result.advanced.virustotal.vt_risk_score ?? 0) >= 40
                          ? "bg-red-500/10 text-red-400 border-red-500/30"
                          : (result.advanced.virustotal.vt_risk_score ?? 0) > 0
                          ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                          : "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                      )}>
                        {result.advanced.virustotal.vt_risk_score ?? 0}
                      </div>
                      <div>
                        <span className="text-xs text-vt-text uppercase font-bold tracking-wider block">VirusTotal Threat Score</span>
                        <span className="text-sm font-semibold text-vt-heading">
                          {(result.advanced.virustotal.vt_risk_score ?? 0) >= 40
                            ? 'High Vendor Consensus Threat'
                            : (result.advanced.virustotal.vt_risk_score ?? 0) > 0
                            ? 'Suspicious Vendor Flagging'
                            : 'Clean Consensus'}
                        </span>
                      </div>
                    </div>

                    <div className="text-right sm:border-l sm:border-vt-700/60 sm:pl-4 text-xs text-vt-text font-mono">
                      <div>Reputation: <strong className="text-vt-heading">{result.advanced.virustotal.reputation ?? 0}</strong></div>
                      <div>Engines Queried: <strong className="text-vt-heading">{result.advanced.virustotal.stats.total || 0}</strong></div>
                    </div>
                  </div>

                  {/* 4 Core Detection Stat Boxes */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
                    <div className="bg-vt-900/80 p-3.5 rounded-xl border border-red-500/30">
                      <span className="text-xs text-red-500 dark:text-red-400 block font-semibold mb-1">{t('res_vt_malicious')}</span>
                      <span className="text-2xl font-bold text-red-500 dark:text-red-400 font-mono">
                        {result.advanced.virustotal.stats.malicious || 0}
                      </span>
                    </div>
                    <div className="bg-vt-900/80 p-3.5 rounded-xl border border-amber-500/30">
                      <span className="text-xs text-amber-500 dark:text-amber-400 block font-semibold mb-1">{t('res_vt_suspicious')}</span>
                      <span className="text-2xl font-bold text-amber-500 dark:text-amber-400 font-mono">
                        {result.advanced.virustotal.stats.suspicious || 0}
                      </span>
                    </div>
                    <div className="bg-vt-900/80 p-3.5 rounded-xl border border-emerald-500/30">
                      <span className="text-xs text-emerald-500 dark:text-emerald-400 block font-semibold mb-1">{t('res_vt_harmless')}</span>
                      <span className="text-2xl font-bold text-emerald-500 dark:text-emerald-400 font-mono">
                        {result.advanced.virustotal.stats.harmless || 0}
                      </span>
                    </div>
                    <div className="bg-vt-900/80 p-3.5 rounded-xl border border-vt-700/50">
                      <span className="text-xs text-vt-text block font-semibold mb-1">{t('res_vt_undetected')}</span>
                      <span className="text-2xl font-bold text-vt-heading font-mono">
                        {result.advanced.virustotal.stats.undetected || 0}
                      </span>
                    </div>
                  </div>

                  {/* Flagged Security Engines List if any */}
                  {result.advanced.virustotal.flagged_engines && result.advanced.virustotal.flagged_engines.length > 0 && (
                    <div className="p-4 rounded-xl bg-vt-900/90 border border-red-500/30 space-y-3">
                      <span className="text-xs font-bold uppercase tracking-wider text-red-400 flex items-center gap-1.5">
                        <AlertOctagon className="w-4 h-4 text-red-500" />
                        Flagged Security Vendors ({result.advanced.virustotal.flagged_engines.length})
                      </span>
                      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
                        {result.advanced.virustotal.flagged_engines.map((eng, idx) => (
                          <div key={idx} className="p-2.5 rounded-lg bg-vt-800 border border-red-500/20 flex flex-col justify-between">
                            <span className="text-xs font-bold text-white font-mono">{eng.engine}</span>
                            <span className="text-[11px] text-red-300 capitalize mt-1 font-mono">
                              {eng.result || eng.category}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Categories & Tags */}
                  {((result.advanced.virustotal.tags && result.advanced.virustotal.tags.length > 0) || (result.advanced.virustotal.categories && Object.keys(result.advanced.virustotal.categories).length > 0)) && (
                    <div className="p-4 rounded-xl bg-vt-900/60 border border-vt-700/60 flex flex-wrap gap-2 items-center">
                      <span className="text-xs font-semibold text-vt-text uppercase tracking-wider mr-2">Identified Tags:</span>
                      {result.advanced.virustotal.tags?.map((tag, i) => (
                        <span key={`tag-${i}`} className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-vt-800 text-vt-accent border border-vt-700">
                          #{tag}
                        </span>
                      ))}
                      {Object.entries(result.advanced.virustotal.categories || {}).map(([catEngine, catName], i) => (
                        <span key={`cat-${i}`} className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-vt-800 text-vt-text border border-vt-700">
                          {catEngine}: {catName}
                        </span>
                      ))}
                    </div>
                  )}

                  {result.advanced.virustotal.permalink && (
                    <div className="pt-2">
                      <a
                        href={result.advanced.virustotal.permalink}
                        target="_blank"
                        rel="noreferrer"
                        className="text-xs text-vt-accent hover:underline inline-flex items-center gap-1 font-mono"
                      >
                        {t('res_vt_link')} &rarr;
                      </a>
                    </div>
                  )}
                </div>
              ) : (
                <div className="space-y-1">
                  <p className="text-xs text-vt-text leading-relaxed">
                    {t(result.advanced.virustotal.summary || t('res_vt_no_stats'))}
                  </p>
                  {result.advanced.virustotal.error && (
                    <p className="text-[11px] font-mono text-red-400/90 bg-red-950/40 p-2 rounded border border-red-800/40">
                      {result.advanced.virustotal.error}
                    </p>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Network & Infrastructure Intel */}
        {networkData && networkData.status !== 'disabled' && (
          <div className="bg-vt-800 p-6 rounded-2xl border border-vt-700 shadow-lg">
            <h3 className="text-md font-bold text-vt-heading mb-4 flex items-center gap-2">
              <Network className="w-5 h-5 text-vt-accent" />
              {t('res_net_title')}
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              {/* DNS & IPs */}
              <div className="bg-vt-900/80 p-4 rounded-xl border border-vt-700/60 space-y-2">
                <span className="text-vt-text uppercase font-bold tracking-wider block">{t('res_net_dns')}</span>
                <p className="text-vt-heading font-mono">
                  {networkData.dns?.ips?.length > 0 
                    ? networkData.dns.ips.join(', ')
                    : t(networkData.dns?.summary || t('res_net_dns_none'))}
                </p>
                {networkData.dns?.minimum_ttl !== null && networkData.dns?.minimum_ttl !== undefined && (
                  <span className="text-vt-text block">
                    {t('res_net_min_ttl')}: <strong className="text-vt-heading">{networkData.dns.minimum_ttl}s</strong>
                  </span>
                )}
              </div>

              {/* TLS Certificate */}
              <div className="bg-vt-900/80 p-4 rounded-xl border border-vt-700/60 space-y-2">
                <span className="text-vt-text uppercase font-bold tracking-wider block">{t('res_net_tls')}</span>
                {networkData.tls_certificate?.subject ? (
                  <div>
                    <p className="text-vt-heading font-mono truncate">
                      {t('res_net_tls_sub')}: {typeof networkData.tls_certificate.subject === 'object' ? (networkData.tls_certificate.subject.commonName || networkData.tls_certificate.subject.organizationName || JSON.stringify(networkData.tls_certificate.subject)) : String(networkData.tls_certificate.subject)}
                    </p>
                    <p className="text-vt-text">
                      {t('res_net_tls_iss')}: {typeof networkData.tls_certificate.issuer === 'object' ? (networkData.tls_certificate.issuer.organizationName || networkData.tls_certificate.issuer.commonName || JSON.stringify(networkData.tls_certificate.issuer)) : (networkData.tls_certificate.issuer || 'N/A')}
                    </p>
                    <p className="text-vt-text">{t('res_net_tls_age')}: {networkData.tls_certificate.age_days ?? 'N/A'} {t('res_net_tls_days')}</p>
                  </div>
                ) : (
                  <p className="text-vt-text">{t(networkData.tls_certificate?.summary || t('res_net_tls_none'))}</p>
                )}
              </div>

              {/* WHOIS / RDAP */}
              <div className="bg-vt-900/80 p-4 rounded-xl border border-vt-700/60 space-y-2">
                <span className="text-vt-text uppercase font-bold tracking-wider block">{t('res_net_rdap')}</span>
                <p className="text-vt-heading">{t('res_net_rdap_reg')}: {networkData.whois_rdap?.registrar || 'N/A'}</p>
                <p className="text-vt-text">{t('res_net_rdap_age')}: {networkData.whois_rdap?.age_days ? `${networkData.whois_rdap.age_days} ${t('res_net_tls_days')}` : 'N/A'}</p>
              </div>

              {/* Redirects */}
              <div className="bg-vt-900/80 p-4 rounded-xl border border-vt-700/60 space-y-2">
                <span className="text-vt-text uppercase font-bold tracking-wider block">{t('res_net_trail')}</span>
                <p className="text-vt-heading">
                  {t('res_net_hops')}: {networkData.redirect_chain?.length || 0}
                </p>
                {networkData.redirect_chain?.length > 0 && (
                  <div className="space-y-1 font-mono text-[11px] text-vt-accent break-all">
                    {networkData.redirect_chain.map((hop, idx) => (
                      <div key={idx}>&rarr; {hop.url} ({hop.status_code})</div>
                    ))}
                  </div>
                )}
              </div>

              {/* Content Scan */}
              <div className="bg-vt-900/80 p-4 rounded-xl border border-vt-700/60 space-y-2 md:col-span-2">
                <span className="text-vt-text uppercase font-bold tracking-wider block">{t('res_net_content')}</span>
                {networkData.content_scan?.status === 'ok' ? (
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                    <div className="space-y-1">
                      <p className="text-vt-heading font-semibold truncate">
                        {networkData.content_scan.title || 'Untitled page'}
                      </p>
                      <p className="text-vt-text text-[11px] leading-relaxed">
                        {t(networkData.content_scan.summary || 'Content scan completed.')}
                      </p>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-[11px]">
                      <div className="rounded-lg border border-vt-700/60 bg-vt-900/70 p-2">
                        <span className="block text-vt-text uppercase tracking-wider">Forms</span>
                        <span className="text-vt-heading font-mono text-sm">{networkData.content_scan.form_count ?? 0}</span>
                      </div>
                      <div className="rounded-lg border border-vt-700/60 bg-vt-900/70 p-2">
                        <span className="block text-vt-text uppercase tracking-wider">Password fields</span>
                        <span className="text-vt-heading font-mono text-sm">{networkData.content_scan.password_field_count ?? 0}</span>
                      </div>
                      <div className="rounded-lg border border-vt-700/60 bg-vt-900/70 p-2">
                        <span className="block text-vt-text uppercase tracking-wider">External scripts</span>
                        <span className="text-vt-heading font-mono text-sm">{networkData.content_scan.external_script_count ?? 0}</span>
                      </div>
                      <div className="rounded-lg border border-vt-700/60 bg-vt-900/70 p-2">
                        <span className="block text-vt-text uppercase tracking-wider">Meta refresh</span>
                        <span className="text-vt-heading font-mono text-sm">{networkData.content_scan.meta_refresh_count ?? 0}</span>
                      </div>
                    </div>
                    {networkData.content_scan.findings?.length > 0 && (
                      <div className="lg:col-span-2 flex flex-wrap gap-2 pt-1">
                        {networkData.content_scan.findings.map((finding, idx) => (
                          <span key={idx} className="inline-flex items-center gap-1 px-2 py-1 rounded-full border border-amber-500/30 bg-amber-500/10 text-amber-300 text-[10px] font-mono uppercase tracking-wider">
                            {finding.signal.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ) : (
                  <p className="text-vt-text text-[11px] leading-relaxed">
                    {t(networkData.content_scan?.summary || t('res_net_content_none'))}
                  </p>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Extracted Heuristic Features Below */}
        <div className="bg-vt-800 p-6 rounded-2xl border border-vt-700 shadow-lg">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-md font-bold text-vt-heading">{t('res_features_title')}</h3>
            <span className="text-xs text-vt-text font-mono">{t('res_features_sub')}</span>
          </div>
          {features ? (
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3 text-xs">
              {Object.entries(features)
                .filter(([key, val]) => (
                  key !== 'threat_intel_match'
                  && key !== 'encoded_values'
                  && key !== 'suspicious_keywords'
                  && key !== 'embedded_urls'
                  && key !== 'embedded_domains'
                  && typeof val !== 'object'
                ))
                .map(([key, val]) => (
                  <div key={key} className="bg-vt-900/80 p-3 rounded-xl border border-vt-700/60 flex flex-col justify-between">
                    <span className="text-vt-text text-[10px] uppercase font-bold tracking-wider mb-1">{key.replace(/_/g, ' ')}</span>
                    <span className="text-vt-heading font-mono font-semibold text-sm truncate">
                      {typeof val === 'boolean' ? (val ? 'True' : 'False') : String(val)}
                    </span>
                  </div>
                ))}
            </div>
          ) : (
            <p className="text-sm text-vt-text">{t('res_features_none')}</p>
          )}
        </div>

      </div>
    </div>
  );
}
