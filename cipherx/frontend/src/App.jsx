import React, { useState } from 'react';
import { Shield, Search, Loader2, Zap } from 'lucide-react';
import ResultDashboard from './components/ResultDashboard';
import { analyzeUrl } from './services/api';

function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const handleAnalyze = async (e) => {
    e.preventDefault();
    if (!url.trim()) {
      setError('Please enter a URL to analyze.');
      return;
    }
    
    setError('');
    setResult(null);
    setLoading(true);

    try {
      const data = await analyzeUrl(url);
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleOneClickVerify = async () => {
    if (!url.trim()) {
      setError('Please enter a URL first.');
      return;
    }
    await handleAnalyze({ preventDefault: () => {} });
  };

  return (
    <div className="min-h-screen bg-dark-900 flex flex-col">
      {/* Navbar */}
      <nav className="border-b border-slate-800 bg-dark-900/50 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-indigo-500" />
            <span className="text-xl font-bold tracking-tight text-white">CipherX</span>
          </div>
          <div className="text-xs text-slate-500 font-mono">Prototype Foundation</div>
        </div>
      </nav>

      <main className="flex-1 flex flex-col items-center px-4 py-12 md:py-24 w-full">
        <div className="w-full max-w-3xl text-center space-y-4 mb-10">
          <h1 className="text-4xl md:text-5xl font-extrabold text-slate-100 tracking-tight">
            Threat Intelligence <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400">Detection</span>
          </h1>
          <p className="text-lg text-slate-400 max-w-2xl mx-auto">
            Explainable phishing and adversarial URL detection. Enter a URL below to run our engine analysis.
          </p>
        </div>

        {/* Input Card */}
        <div className="w-full max-w-3xl bg-dark-800 p-6 md:p-8 rounded-2xl border border-slate-700 shadow-xl">
          <form onSubmit={handleAnalyze} className="space-y-6">
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                <Search className="h-5 w-5 text-slate-500" />
              </div>
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com"
                className="block w-full pl-11 pr-4 py-4 bg-dark-900 border border-slate-600 rounded-xl text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all"
                disabled={loading}
              />
            </div>
            
            {error && (
              <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
                {error}
              </div>
            )}

            <div className="flex flex-col sm:flex-row gap-4">
              <button
                type="submit"
                disabled={loading}
                className="flex-1 flex items-center justify-center gap-2 bg-slate-700 hover:bg-slate-600 text-white py-3.5 px-6 rounded-xl font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Search className="w-5 h-5" />}
                Analyze URL
              </button>
              
              <button
                type="button"
                onClick={handleOneClickVerify}
                disabled={loading}
                className="flex-1 flex items-center justify-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white py-3.5 px-6 rounded-xl font-medium shadow-lg shadow-indigo-500/20 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Zap className="w-5 h-5" />}
                One-Click Verification
              </button>
            </div>
          </form>
        </div>

        {/* Loading State */}
        {loading && (
          <div className="mt-12 flex flex-col items-center gap-4 text-slate-400 animate-pulse">
            <Loader2 className="w-8 h-8 animate-spin text-indigo-500" />
            <p>Analyzing URL structure and extracting features...</p>
          </div>
        )}

        {/* Results Dashboard */}
        {!loading && result && <ResultDashboard result={result} />}
      </main>
    </div>
  );
}

export default App;
