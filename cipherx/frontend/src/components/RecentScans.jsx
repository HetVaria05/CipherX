import React, { useEffect, useState } from 'react';
import { History, ShieldCheck, ShieldAlert, AlertTriangle, AlertOctagon, RefreshCw } from 'lucide-react';
import { fetchRecentScans } from '../services/api';
import { useLanguage } from '../context/LanguageContext';

const getBadge = (classification) => {
  switch (classification) {
    case 'LOW':
      return { bg: 'bg-emerald-500/15 border-emerald-500/30 text-emerald-600 dark:text-emerald-400', icon: ShieldCheck };
    case 'SUSPICIOUS':
      return { bg: 'bg-amber-500/15 border-amber-500/30 text-amber-600 dark:text-amber-400', icon: AlertTriangle };
    case 'HIGH':
      return { bg: 'bg-orange-500/15 border-orange-500/30 text-orange-600 dark:text-orange-400', icon: ShieldAlert };
    case 'CRITICAL':
      return { bg: 'bg-red-500/15 border-red-500/30 text-red-600 dark:text-red-400', icon: AlertOctagon };
    default:
      return { bg: 'bg-vt-800 border-vt-700 text-vt-text', icon: ShieldCheck };
  }
};

export default function RecentScans({ onSelectUrl }) {
  const { t } = useLanguage();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(false);

  const loadScans = async () => {
    setLoading(true);
    const data = await fetchRecentScans(6);
    setScans(data || []);
    setLoading(false);
  };

  useEffect(() => {
    loadScans();
  }, []);

  if (!scans || scans.length === 0) {
    return null;
  }

  return (
    <div className="w-full max-w-3xl mt-12 bg-vt-800 border border-vt-700 rounded-2xl p-6 shadow-xl backdrop-blur-sm">
      <div className="flex items-center justify-between mb-4 border-b border-vt-700 pb-3">
        <div className="flex items-center gap-2">
          <History className="w-4 h-4 text-vt-accent" />
          <h3 className="text-sm font-bold text-vt-heading uppercase tracking-wider">{t('recent_title')}</h3>
        </div>
        <button
          onClick={loadScans}
          disabled={loading}
          className="text-xs text-vt-text hover:text-vt-heading flex items-center gap-1.5 transition-colors disabled:opacity-50"
          title="Refresh recent scans"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-vt-accent' : ''}`} />
          <span>{t('recent_refresh')}</span>
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {scans.map((scan, idx) => {
          const badge = getBadge(scan.classification);
          const IconComponent = badge.icon;
          return (
            <div
              key={scan.id || idx}
              onClick={() => onSelectUrl && onSelectUrl(scan.url)}
              className="p-3.5 bg-vt-900 hover:bg-vt-900/80 border border-vt-700/80 hover:border-vt-accent/50 rounded-xl flex items-center justify-between gap-3 transition-all cursor-pointer group shadow-sm"
            >
              <div className="min-w-0 flex-1">
                <p className="text-xs font-mono text-vt-heading truncate group-hover:text-vt-accent transition-colors font-medium">
                  {scan.url}
                </p>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-[11px] text-vt-text">{t('recent_score')}: {scan.risk_score}/100</span>
                  {scan.detected_brand && (
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-orange-500/10 text-orange-600 dark:text-orange-400 border border-orange-500/30">
                      {scan.detected_brand}
                    </span>
                  )}
                  {scan.threat_intel_source && (
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/30">
                      {scan.threat_intel_source}
                    </span>
                  )}
                </div>
              </div>

              <div className={`px-2.5 py-1 rounded-lg border text-xs font-bold flex items-center gap-1 flex-shrink-0 ${badge.bg}`}>
                <IconComponent className="w-3.5 h-3.5" />
                <span>{scan.classification}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
