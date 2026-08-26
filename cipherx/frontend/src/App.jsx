import React, { useState } from 'react';
import { Search, Loader2, Zap, FileText, QrCode, MessageSquareText, ShieldAlert, Fingerprint } from 'lucide-react';
import ResultDashboard from './components/ResultDashboard';
import RecentScans from './components/RecentScans';
import Navbar from './components/Navbar';
import FeaturesSection from './components/FeaturesSection';
import ChatbotWidget from './components/ChatbotWidget';
import { analyzeUrl, advancedAnalyzeUrl } from './services/api';
import { useLanguage } from './context/LanguageContext';

function App() {
  const { t } = useLanguage();
  const [activeTab, setActiveTab] = useState('URL');
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [recentRefreshKey, setRecentRefreshKey] = useState(0);

  // Advanced analysis states
  const [advancedLoading, setAdvancedLoading] = useState(false);

  const handleAnalyze = async (e, customUrl) => {
    if (e && e.preventDefault) e.preventDefault();
    const targetUrl = customUrl || url;
    if (!targetUrl.trim()) {
      setError('Please enter a URL to analyze.');
      return;
    }
    
    setError('');
    setResult(null);
    setLoading(true);

    try {
      const data = await analyzeUrl(targetUrl);
      setResult(data);
      setRecentRefreshKey(prev => prev + 1);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleAdvancedAnalyze = async (targetUrl) => {
    setError('');
    setAdvancedLoading(true);
    try {
      // Backend will use its configured free tier VT API key
      const data = await advancedAnalyzeUrl({
        url: targetUrl,
        virustotal_api_key: null,
        use_virustotal: true,
        submit_to_virustotal: false,
        include_network: true,
      });
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setAdvancedLoading(false);
    }
  };

  const handleSelectRecentUrl = (selectedUrl) => {
    setUrl(selectedUrl);
    handleAnalyze(null, selectedUrl);
  };

  // Monitor modal state & Live Protection Simulation state
  const [showMonitor, setShowMonitor] = useState(false);
  const [liveShieldEnabled, setLiveShieldEnabled] = useState(true);
  const [showBlockScreen, setShowBlockScreen] = useState(false);
  const [simulatedThreatUrl, setSimulatedThreatUrl] = useState('https://amaz0n-security-login.xyz/verify-account');

  return (
    <div className="min-h-screen bg-vt-900 text-vt-text font-sans flex flex-col relative transition-colors">
      <Navbar onOpenMonitor={() => setShowMonitor(true)} />

      {/* Red Screen Interstitial Warning Simulation */}
      {showBlockScreen && (
        <div className="fixed inset-0 bg-[#d93025] text-white z-[9999] flex flex-col items-center justify-center p-6 animate-in fade-in zoom-in-95 duration-200">
          <div className="max-w-2xl w-full space-y-6">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-white/20 rounded-2xl">
                <ShieldAlert className="w-16 h-16 text-white" />
              </div>
              <div>
                <span className="text-xs uppercase tracking-widest bg-black/30 px-3 py-1 rounded-full font-mono font-bold">
                  {t('block_badge')}
                </span>
                <h1 className="text-3xl md:text-4xl font-extrabold mt-1">{t('block_title')}</h1>
              </div>
            </div>

            <div className="bg-black/20 p-5 rounded-2xl border border-white/20 text-white/90 text-sm leading-relaxed space-y-3">
              <p>
                {t('block_desc_1')} <strong className="font-mono text-white underline break-all">{simulatedThreatUrl}</strong> {t('block_desc_2')} <strong>{t('block_desc_3')}</strong> {t('block_desc_4')}
              </p>
              <div className="pt-2 border-t border-white/20 text-xs grid grid-cols-1 sm:grid-cols-2 gap-2 font-mono">
                <div>• {t('block_reason_threat')}</div>
                <div>• {t('block_reason_heur')}</div>
                <div>• {t('block_reason_lat')} 11ms</div>
                <div>• {t('block_reason_stat')}</div>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-2">
              <button
                onClick={() => setShowBlockScreen(false)}
                className="w-full sm:w-auto px-8 py-3 bg-white text-[#d93025] hover:bg-slate-100 font-bold rounded-xl shadow-lg transition-all text-sm"
              >
                {t('block_btn_back')}
              </button>
              <button
                onClick={() => setShowBlockScreen(false)}
                className="text-xs text-white/70 hover:text-white underline underline-offset-4"
              >
                {t('block_btn_proceed')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Threat Monitor & Live Protection Modal */}
      {showMonitor && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4 animate-in fade-in duration-200">
          <div className="bg-vt-800 border border-vt-700 w-full max-w-2xl rounded-2xl p-6 shadow-2xl relative">
            <div className="flex items-center justify-between border-b border-vt-700 pb-4 mb-4">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-vt-accent/20 text-vt-accent">
                  <ShieldAlert className="w-6 h-6" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-white">{t('monitor_title')}</h3>
                  <p className="text-xs text-vt-text/70">{t('monitor_subtitle')}</p>
                </div>
              </div>
              <button 
                onClick={() => setShowMonitor(false)}
                className="text-vt-text hover:text-white px-3 py-1 rounded-lg hover:bg-vt-700 transition-colors text-sm font-bold"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4 text-sm">
              {/* Active Protection Switcher */}
              <div className="p-4 rounded-xl bg-vt-900 border border-vt-700/60 flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-white">{t('monitor_active_title')}</span>
                    <span className={`inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full font-mono ${liveShieldEnabled ? 'bg-green-500/20 text-green-400' : 'bg-vt-700 text-vt-text'}`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${liveShieldEnabled ? 'bg-green-400 animate-pulse' : 'bg-vt-text'}`}></span> 
                      {liveShieldEnabled ? t('monitor_active_status_on') : t('monitor_active_status_off')}
                    </span>
                  </div>
                  <p className="text-xs text-vt-text/80 mt-1 leading-relaxed">
                    {t('monitor_active_desc')}
                  </p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer ml-4">
                  <input 
                    type="checkbox" 
                    checked={liveShieldEnabled} 
                    onChange={(e) => setLiveShieldEnabled(e.target.checked)} 
                    className="sr-only peer"
                  />
                  <div className="w-11 h-6 bg-vt-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-vt-accent"></div>
                </label>
              </div>

              {/* Performance & Signatures Grid */}
              <div className="grid grid-cols-2 gap-3 text-center">
                <div className="bg-vt-900 p-3.5 rounded-xl border border-vt-700/50">
                  <span className="text-xs text-vt-text/60 uppercase tracking-wider block mb-1">{t('monitor_sigs_title')}</span>
                  <span className="text-2xl font-mono font-bold text-white">15,000+</span>
                  <span className="text-[10px] text-vt-text/50 block mt-0.5">{t('monitor_sigs_desc')}</span>
                </div>
                <div className="bg-vt-900 p-3.5 rounded-xl border border-vt-700/50">
                  <span className="text-xs text-vt-text/60 uppercase tracking-wider block mb-1">{t('monitor_latency_title')}</span>
                  <span className="text-2xl font-mono font-bold text-green-400">&lt; 15ms</span>
                  <span className="text-[10px] text-vt-text/50 block mt-0.5">{t('monitor_latency_desc')}</span>
                </div>
              </div>

              {/* Test Interstitial Simulation Box */}
              <div className="p-4 rounded-xl bg-vt-900/80 border border-vt-accent/30 space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs uppercase font-bold text-vt-accent tracking-wider">{t('monitor_test_title')}</h4>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-vt-accent/10 text-vt-accent font-mono">{t('monitor_test_badge')}</span>
                </div>
                <p className="text-xs text-vt-text/80">
                  {t('monitor_test_desc')}
                </p>
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    value={simulatedThreatUrl}
                    onChange={(e) => setSimulatedThreatUrl(e.target.value)}
                    className="flex-1 bg-vt-800 border border-vt-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-vt-accent"
                  />
                  <button
                    onClick={() => {
                      setShowMonitor(false);
                      setShowBlockScreen(true);
                    }}
                    className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-bold transition-colors whitespace-nowrap"
                  >
                    {t('monitor_test_btn')}
                  </button>
                </div>
              </div>
            </div>

            <div className="mt-6 flex justify-end">
              <button
                onClick={() => setShowMonitor(false)}
                className="px-6 py-2 rounded-full bg-vt-accent hover:bg-blue-600 text-white text-sm font-medium transition-colors"
              >
                {t('monitor_btn_done')}
              </button>
            </div>
          </div>
        </div>
      )}

      <main className="flex-1 flex flex-col items-center pt-16 w-full">
        {/* Hero Section */}
        <div className="w-full text-center space-y-6 mb-12 flex flex-col items-center">
          <div className="flex items-center gap-4 text-vt-heading">
            <ShieldAlert className="w-16 h-16 text-vt-accent" />
            <h1 className="text-5xl md:text-6xl font-bold tracking-tight text-vt-heading">{t('hero_title')}</h1>
          </div>
          <p className="text-[15px] text-vt-text max-w-2xl mx-auto px-4">
            {t('hero_subtitle')}
          </p>
        </div>

        {/* Tabs */}
        <div className="flex items-center justify-center border-b border-vt-700 w-full max-w-3xl mb-12">
           <button 
             onClick={() => setActiveTab('FILE')}
             className={`px-8 py-4 text-sm font-semibold tracking-widest transition-colors relative ${activeTab === 'FILE' ? 'text-vt-heading' : 'text-vt-text hover:text-vt-heading'}`}
           >
             {t('tab_file')}
             {activeTab === 'FILE' && <div className="absolute bottom-[-1px] left-0 w-full h-[2px] bg-vt-accent"></div>}
           </button>
           <button 
             onClick={() => setActiveTab('URL')}
             className={`px-8 py-4 text-sm font-semibold tracking-widest transition-colors relative ${activeTab === 'URL' ? 'text-vt-heading' : 'text-vt-text hover:text-vt-heading'}`}
           >
             {t('tab_url')}
             {activeTab === 'URL' && <div className="absolute bottom-[-1px] left-0 w-full h-[2px] bg-vt-accent"></div>}
           </button>
           <button 
             onClick={() => setActiveTab('QR')}
             className={`px-8 py-4 text-sm font-semibold tracking-widest transition-colors relative ${activeTab === 'QR' ? 'text-vt-heading' : 'text-vt-text hover:text-vt-heading'}`}
           >
             {t('tab_qr')}
             {activeTab === 'QR' && <div className="absolute bottom-[-1px] left-0 w-full h-[2px] bg-vt-accent"></div>}
           </button>
           <button 
             onClick={() => setActiveTab('SMS')}
             className={`px-8 py-4 text-sm font-semibold tracking-widest transition-colors relative ${activeTab === 'SMS' ? 'text-vt-heading' : 'text-vt-text hover:text-vt-heading'}`}
           >
             {t('tab_sms')}
             {activeTab === 'SMS' && <div className="absolute bottom-[-1px] left-0 w-full h-[2px] bg-vt-accent"></div>}
           </button>
        </div>

        {/* Tab Content */}
        <div className="w-full max-w-3xl px-4 min-h-[300px]">
          
          {/* URL TAB */}
          {activeTab === 'URL' && (
            <div className="w-full animate-in fade-in zoom-in duration-300">
              <form onSubmit={handleAnalyze} className="space-y-6">
                <div className="relative shadow-2xl rounded-xl">
                  <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                    <Search className="h-5 w-5 text-vt-text" />
                  </div>
                  <input
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder={t('url_placeholder')}
                    className="block w-full pl-12 pr-4 py-5 bg-vt-800 border border-vt-700 rounded-xl text-vt-heading placeholder-vt-text focus:outline-none focus:ring-1 focus:ring-vt-accent transition-all"
                    disabled={loading}
                  />
                </div>
                
                {error && (
                  <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm text-center">
                    {error}
                  </div>
                )}

                <div className="flex justify-center mt-8">
                  <button
                    type="submit"
                    disabled={loading}
                    className="flex items-center justify-center gap-2 bg-transparent border border-vt-accent text-vt-accent hover:bg-vt-accent/10 py-2.5 px-8 rounded-full font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                    {t('url_analyze')}
                  </button>
                </div>
              </form>

              {/* Loading State */}
              {loading && (
                <div className="mt-12 flex flex-col items-center gap-4 text-vt-text animate-pulse">
                  <Fingerprint className="w-12 h-12 text-vt-accent animate-pulse" />
                  <p className="text-sm">{t('url_analyzing')}</p>
                </div>
              )}

              {/* Results Dashboard */}
              {!loading && result && (
                <div className="mt-12 border-t border-vt-700 pt-8 space-y-6">
                  <ResultDashboard result={result} />
                  
                  {/* Option for Advanced Scan after initial scan */}
                  {!result.advanced && (
                    <div className="bg-vt-800 p-6 rounded-2xl border border-vt-700 shadow-lg text-center mt-6 animate-in fade-in duration-500">
                      <Zap className="w-10 h-10 text-vt-accent mx-auto mb-3" />
                      <h3 className="text-lg font-bold text-vt-heading mb-2">{t('res_adv_title')}</h3>
                      <p className="text-sm text-vt-text/80 mb-6 max-w-md mx-auto">
                        {t('res_adv_desc')}
                      </p>
                      <button
                        onClick={() => handleAdvancedAnalyze(result.url)}
                        disabled={advancedLoading}
                        className="inline-flex items-center justify-center gap-2 bg-vt-accent text-white hover:bg-vt-accent/90 py-2.5 px-8 rounded-full font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {advancedLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                        {advancedLoading ? t('res_adv_btn_running') : t('res_adv_btn_run')}
                      </button>
                    </div>
                  )}
                </div>
              )}

              {/* Recent Checks List */}
              <RecentScans key={recentRefreshKey} onSelectUrl={handleSelectRecentUrl} />
            </div>
          )}

          {/* QR TAB */}
          {activeTab === 'QR' && (
            <div className="w-full flex flex-col items-center justify-center animate-in fade-in zoom-in duration-300 py-12">
              <div className="relative mb-6">
                <QrCode className="w-24 h-24 text-vt-700" />
                <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[120%] h-1 bg-vt-accent/50 shadow-[0_0_15px_rgba(46,96,255,0.8)] animate-scan"></div>
              </div>
              <h2 className="text-2xl font-bold text-vt-heading mb-2">{t('qr_title')}</h2>
              <p className="text-vt-text text-center max-w-md mb-8">
                {t('qr_desc')}
              </p>
              <button disabled className="bg-vt-800 text-vt-text border border-vt-700 py-3 px-8 rounded-full font-medium opacity-50 cursor-not-allowed flex items-center gap-2">
                 <Loader2 className="w-4 h-4" /> {t('coming_soon_btn')}
              </button>
            </div>
          )}

          {/* SMS TAB */}
          {activeTab === 'SMS' && (
            <div className="w-full flex flex-col items-center justify-center animate-in fade-in zoom-in duration-300 py-12">
              <div className="relative mb-6">
                <MessageSquareText className="w-24 h-24 text-vt-700" />
                <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[120%] h-1 bg-vt-accent/50 shadow-[0_0_15px_rgba(46,96,255,0.8)] animate-scan"></div>
              </div>
              <h2 className="text-2xl font-bold text-vt-heading mb-2">{t('sms_title')}</h2>
              <p className="text-vt-text text-center max-w-md mb-8">
                {t('sms_desc')}
              </p>
              <button disabled className="bg-vt-800 text-vt-text border border-vt-700 py-3 px-8 rounded-full font-medium opacity-50 cursor-not-allowed flex items-center gap-2">
                 <Loader2 className="w-4 h-4" /> {t('coming_soon_btn')}
              </button>
            </div>
          )}

          {/* FILE TAB */}
          {activeTab === 'FILE' && (
            <div className="w-full flex flex-col items-center justify-center animate-in fade-in zoom-in duration-300 py-8">
              <div className="relative mb-6">
                <FileText className="w-20 h-20 text-vt-text" />
                <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-32 h-1 bg-vt-accent shadow-[0_0_15px_rgba(46,96,255,0.8)]"></div>
              </div>
              <button disabled className="bg-transparent border border-vt-accent text-vt-accent py-2.5 px-8 rounded-full font-medium opacity-50 cursor-not-allowed mb-8">
                {t('file_btn')}
              </button>
              <p className="text-xs text-vt-text text-center max-w-xl leading-relaxed">
                {t('url_disclaimer')}
              </p>
            </div>
          )}

        </div>

        {/* Bottom Features Section */}
        <FeaturesSection />

      </main>

      <ChatbotWidget />
    </div>
  );
}

export default App;
