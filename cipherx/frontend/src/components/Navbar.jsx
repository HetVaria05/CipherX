import React, { useState, useEffect, useRef } from 'react';
import { Shield, Upload, Monitor, HelpCircle, Sun, Moon, Globe, ChevronDown, User, LogOut, Zap, Crown } from 'lucide-react';
import { useLanguage } from '../context/LanguageContext';
import { useAuth } from '../context/AuthContext';

const Navbar = ({ onOpenMonitor }) => {
  const { language, changeLanguage, t } = useLanguage();
  const { user, quota, openAuth, handleSignOut, setPricingModalOpen } = useAuth();
  const [showLangMenu, setShowLangMenu] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const langMenuRef = useRef(null);
  const userMenuRef = useRef(null);

  // Close dropdown on click outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (langMenuRef.current && !langMenuRef.current.contains(event.target)) {
        setShowLangMenu(false);
      }
      if (userMenuRef.current && !userMenuRef.current.contains(event.target)) {
        setShowUserMenu(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);
  const [isDark, setIsDark] = useState(() => {
    const saved = localStorage.getItem('cipherx_theme');
    return saved !== null ? saved === 'dark' : true;
  });

  useEffect(() => {
    if (isDark) {
      document.documentElement.classList.remove('light');
      document.documentElement.classList.add('dark');
      localStorage.setItem('cipherx_theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      document.documentElement.classList.add('light');
      localStorage.setItem('cipherx_theme', 'light');
    }
  }, [isDark]);

  const toggleTheme = () => {
    setIsDark(prev => !prev);
  };

  return (
    <nav className="border-b border-vt-700 bg-vt-800 text-vt-text sticky top-0 z-50 transition-colors">
      <div className="max-w-[1600px] mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        
        {/* Left: Logo */}
        <div className="flex items-center gap-3 cursor-pointer">
          <Shield className="w-8 h-8 text-vt-accent" />
          <span className="text-2xl font-bold tracking-tight text-vt-heading">CipherX</span>
        </div>

        {/* Center: Quota Indicator & Upgrade Banner */}
        <div className="flex items-center gap-3 hidden md:flex">
          <button
            onClick={() => setPricingModalOpen(true)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-vt-900 border border-vt-700 hover:border-vt-accent/60 transition-colors text-xs font-mono"
            title="View Scan Quota & Plans"
          >
            <span className="w-2 h-2 rounded-full bg-vt-accent animate-pulse"></span>
            <span className="text-vt-text/80">Advanced Scans:</span>
            <strong className={`font-bold ${quota.remaining === 0 ? 'text-red-400' : 'text-green-400'}`}>
              {quota.remaining}/{quota.total} left
            </strong>
            <span className="text-[10px] text-vt-accent font-semibold flex items-center gap-0.5 ml-1">
              <Crown className="w-3 h-3 text-amber-400" /> Premium
            </span>
          </button>
        </div>

        {/* Right: Icons & Auth */}
        <div className="flex items-center gap-4 text-sm font-medium">
          
          <div className="flex items-center gap-4 pr-4 border-r border-vt-700 text-vt-text">
            <button className="hover:text-white transition-colors" title={t('nav_upload')}>
              <Upload className="w-5 h-5" />
            </button>
            <button 
              onClick={onOpenMonitor}
              className="hover:text-white transition-colors" 
              title={t('nav_monitor')}
            >
              <Monitor className="w-5 h-5" />
            </button>
            <button 
              onClick={() => setPricingModalOpen(true)}
              className="hover:text-white transition-colors flex items-center gap-1 text-xs" 
              title="Pricing & Quota"
            >
              <Zap className="w-4 h-4 text-vt-accent" />
              <span className="hidden sm:inline">Plans</span>
            </button>
            <button className="hover:text-white transition-colors" title={t('nav_help')}>
              <HelpCircle className="w-5 h-5" />
            </button>
            <button 
              onClick={toggleTheme} 
              className="hover:text-white transition-colors p-1 rounded-md hover:bg-vt-700/50" 
              title={isDark ? t('nav_theme_light') : t('nav_theme_dark')}
            >
              {isDark ? <Sun className="w-5 h-5 text-yellow-400" /> : <Moon className="w-5 h-5 text-blue-600" />}
            </button>
            
            {/* Language Switcher */}
            <div className="relative" ref={langMenuRef}>
              <div 
                className="flex items-center gap-1 cursor-pointer hover:text-white transition-colors"
                onClick={() => setShowLangMenu(!showLangMenu)}
              >
                 <Globe className="w-4 h-4" />
                 <span className="uppercase">{language}</span>
                 <ChevronDown className="w-3 h-3" />
              </div>
              
              {showLangMenu && (
                <div className="absolute right-0 mt-2 w-32 bg-vt-800 border border-vt-700 rounded-lg shadow-xl overflow-hidden z-50">
                  <button 
                    onClick={() => { changeLanguage('en'); setShowLangMenu(false); }}
                    className={`w-full text-left px-4 py-2 text-sm hover:bg-vt-700 transition-colors ${language === 'en' ? 'text-white bg-vt-700/50' : 'text-vt-text'}`}
                  >
                    English
                  </button>
                  <button 
                    onClick={() => { changeLanguage('gu'); setShowLangMenu(false); }}
                    className={`w-full text-left px-4 py-2 text-sm hover:bg-vt-700 transition-colors ${language === 'gu' ? 'text-white bg-vt-700/50' : 'text-vt-text'}`}
                  >
                    ગુજરાતી
                  </button>
                  <button 
                    onClick={() => { changeLanguage('hi'); setShowLangMenu(false); }}
                    className={`w-full text-left px-4 py-2 text-sm hover:bg-vt-700 transition-colors ${language === 'hi' ? 'text-white bg-vt-700/50' : 'text-vt-text'}`}
                  >
                    हिन्दी
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* User Profile or Sign In / Sign Up */}
          {user ? (
            <div className="relative" ref={userMenuRef}>
              <button
                onClick={() => setShowUserMenu(!showUserMenu)}
                className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-vt-900 border border-vt-700 hover:border-vt-accent text-xs font-semibold text-white transition-colors"
              >
                <div className="w-5 h-5 rounded-full bg-vt-accent text-white flex items-center justify-center text-[10px] font-bold">
                  {user.full_name ? user.full_name.charAt(0).toUpperCase() : user.email.charAt(0).toUpperCase()}
                </div>
                <span className="max-w-[100px] truncate">{user.full_name || user.email.split('@')[0]}</span>
                <ChevronDown className="w-3 h-3 text-vt-text" />
              </button>

              {showUserMenu && (
                <div className="absolute right-0 mt-2 w-52 bg-vt-800 border border-vt-700 rounded-xl shadow-xl p-2 z-50 text-xs">
                  <div className="px-3 py-2 border-b border-vt-700/60 mb-1">
                    <p className="font-bold text-white truncate">{user.full_name || 'User'}</p>
                    <p className="text-vt-text/80 truncate">{user.email}</p>
                    <div className="mt-2 flex items-center justify-between text-[11px]">
                      <span className="text-vt-accent font-mono uppercase font-semibold">Tier: {user.tier || 'Free'}</span>
                      <span className="font-mono text-green-400">{quota.remaining}/{quota.total} left</span>
                    </div>
                  </div>
                  <button
                    onClick={() => {
                      setShowUserMenu(false);
                      setPricingModalOpen(true);
                    }}
                    className="w-full text-left px-3 py-2 rounded-lg hover:bg-vt-700 text-vt-heading flex items-center gap-2 transition-colors"
                  >
                    <Crown className="w-3.5 h-3.5 text-amber-400" /> Upgrade Plan
                  </button>
                  <button
                    onClick={() => {
                      setShowUserMenu(false);
                      handleSignOut();
                    }}
                    className="w-full text-left px-3 py-2 rounded-lg hover:bg-red-500/10 text-red-400 flex items-center gap-2 transition-colors"
                  >
                    <LogOut className="w-3.5 h-3.5" /> Sign Out
                  </button>
                </div>
              )}
            </div>
          ) : (
            <div className="flex items-center gap-3 pl-2">
              <button 
                onClick={() => openAuth('signin')}
                className="text-vt-heading hover:text-vt-accent transition-colors"
              >
                {t('nav_signin')}
              </button>
              <button 
                onClick={() => openAuth('signup')}
                className="bg-vt-accent hover:bg-blue-600 text-white px-4 py-1.5 rounded-full transition-colors font-medium"
              >
                {t('nav_signup')}
              </button>
            </div>
          )}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
