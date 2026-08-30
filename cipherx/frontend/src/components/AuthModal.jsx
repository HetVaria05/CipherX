import React, { useState } from 'react';
import { X, Lock, Mail, User, Shield, AlertCircle, Loader2, Sparkles } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useLanguage } from '../context/LanguageContext';

export default function AuthModal() {
  const { authModalOpen, authMode, setAuthMode, closeAuth, handleSignIn, handleSignUp } = useAuth();
  const { t } = useLanguage();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  if (!authModalOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (authMode === 'signin') {
        await handleSignIn(email, password);
      } else {
        await handleSignUp(email, password, fullName);
      }
      setEmail('');
      setPassword('');
      setFullName('');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-md bg-vt-800 border border-vt-700 rounded-2xl shadow-2xl p-6 md:p-8 text-vt-text">
        {/* Close Button */}
        <button
          onClick={closeAuth}
          className="absolute top-4 right-4 text-vt-text hover:text-white p-1 rounded-lg hover:bg-vt-700/50 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Header */}
        <div className="text-center mb-6">
          <div className="inline-flex p-3 rounded-2xl bg-vt-accent/10 border border-vt-accent/30 text-vt-accent mb-3">
            <Shield className="w-8 h-8" />
          </div>
          <h2 className="text-2xl font-bold text-vt-heading">
            {authMode === 'signin' ? 'Sign In to CipherX' : 'Create Free Account'}
          </h2>
          <p className="text-xs text-vt-text/80 mt-1">
            {authMode === 'signin'
              ? 'Access higher advanced threat analysis quotas and scan history.'
              : 'Unlock 3 free advanced VirusTotal & network scans per day.'}
          </p>
        </div>

        {/* Error Notification */}
        {error && (
          <div className="mb-4 p-3 rounded-xl bg-red-500/10 border border-red-500/30 flex items-center gap-2 text-xs text-red-400">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          {authMode === 'signup' && (
            <div>
              <label className="block text-xs font-semibold text-vt-heading uppercase tracking-wider mb-1.5">
                Full Name
              </label>
              <div className="relative">
                <User className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-vt-text/60" />
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Alex Mercer"
                  className="w-full bg-vt-900 border border-vt-700 rounded-xl pl-10 pr-4 py-2.5 text-sm text-white focus:outline-none focus:border-vt-accent transition-colors"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-semibold text-vt-heading uppercase tracking-wider mb-1.5">
              Email Address
            </label>
            <div className="relative">
              <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-vt-text/60" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="name@company.com"
                className="w-full bg-vt-900 border border-vt-700 rounded-xl pl-10 pr-4 py-2.5 text-sm text-white focus:outline-none focus:border-vt-accent transition-colors"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-vt-heading uppercase tracking-wider mb-1.5">
              Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-vt-text/60" />
              <input
                type="password"
                required
                minLength={6}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full bg-vt-900 border border-vt-700 rounded-xl pl-10 pr-4 py-2.5 text-sm text-white focus:outline-none focus:border-vt-accent transition-colors"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full mt-2 bg-vt-accent hover:bg-blue-600 text-white font-medium py-3 rounded-xl transition-colors flex items-center justify-center gap-2 text-sm disabled:opacity-50"
          >
            {loading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Sparkles className="w-4 h-4" />
            )}
            {authMode === 'signin' ? 'Sign In' : 'Create Account'}
          </button>
        </form>

        {/* Divider */}
        <div className="relative my-5 flex items-center justify-center">
          <div className="border-t border-vt-700/80 w-full"></div>
          <span className="bg-vt-800 px-3 text-[11px] font-semibold uppercase tracking-wider text-vt-text/60 absolute">
            Or continue with
          </span>
        </div>

        {/* Google Sign In Button */}
        <button
          type="button"
          onClick={async () => {
            setError('');
            setLoading(true);
            try {
              // Simulated Google One-Tap / OAuth integration
              const demoGoogleEmail = prompt('Enter your Google Account email:', 'user@gmail.com');
              if (!demoGoogleEmail) {
                setLoading(false);
                return;
              }
              const defaultName = demoGoogleEmail.split('@')[0].replace(/[._]/g, ' ');
              await handleGoogleSignIn({
                email: demoGoogleEmail,
                fullName: defaultName.charAt(0).toUpperCase() + defaultName.slice(1),
                avatarUrl: `https://api.dicebear.com/7.x/bottts/svg?seed=${demoGoogleEmail}`,
                googleId: `g_${Date.now()}`,
              });
            } catch (err) {
              setError(err.message);
            } finally {
              setLoading(false);
            }
          }}
          disabled={loading}
          className="w-full py-2.5 px-4 bg-vt-900 hover:bg-vt-700/60 border border-vt-700 hover:border-vt-accent/50 text-white text-xs font-semibold rounded-xl transition-colors flex items-center justify-center gap-3 disabled:opacity-50 shadow-sm"
        >
          <svg className="w-4 h-4" viewBox="0 0 24 24">
            <path
              fill="#EA4335"
              d="M12 5c1.54 0 2.9.54 3.99 1.43l2.97-2.97C17.15 1.76 14.76 1 12 1 7.37 1 3.48 3.65 1.62 7.5l3.56 2.76C6.06 7.21 8.78 5 12 5z"
            />
            <path
              fill="#4285F4"
              d="M23.49 12.27c0-.79-.07-1.54-.19-2.27H12v4.51h6.47c-.29 1.48-1.14 2.73-2.4 3.58l3.71 2.88c2.16-1.99 3.71-4.93 3.71-8.7z"
            />
            <path
              fill="#FBBC05"
              d="M5.18 14.74c-.23-.69-.36-1.44-.36-2.21s.13-1.52.36-2.21L1.62 7.5C.59 9.57 0 11.72 0 14s.59 4.43 1.62 6.5l3.56-2.76z"
            />
            <path
              fill="#34A853"
              d="M12 23c3.24 0 5.95-1.08 7.93-2.91l-3.71-2.88c-1.07.72-2.45 1.16-4.22 1.16-3.22 0-5.94-2.21-6.82-5.26L1.62 16.5C3.48 20.35 7.37 23 12 23z"
            />
          </svg>
          <span>Sign in with Google</span>
        </button>

        {/* Switch Mode Footer */}
        <div className="mt-6 pt-4 border-t border-vt-700/60 text-center text-xs">
          {authMode === 'signin' ? (
            <p>
              Don't have an account?{' '}
              <button
                onClick={() => {
                  setError('');
                  setAuthMode('signup');
                }}
                className="text-vt-accent font-semibold hover:underline"
              >
                Sign up for free
              </button>
            </p>
          ) : (
            <p>
              Already have an account?{' '}
              <button
                onClick={() => {
                  setError('');
                  setAuthMode('signin');
                }}
                className="text-vt-accent font-semibold hover:underline"
              >
                Sign in
              </button>
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
