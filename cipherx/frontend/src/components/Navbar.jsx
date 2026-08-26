import React, { useState, useEffect, useRef } from 'react';
import { Shield, Upload, Monitor, HelpCircle, Sun, Moon, Globe, ChevronDown } from 'lucide-react';
import { useLanguage } from '../context/LanguageContext';

const Navbar = ({ onOpenMonitor }) => {
  const { language, changeLanguage, t } = useLanguage();
  const [showLangMenu, setShowLangMenu] = useState(false);
  const langMenuRef = useRef(null);

  // Close dropdown on click outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (langMenuRef.current && !langMenuRef.current.contains(event.target)) {
        setShowLangMenu(false);
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

        {/* Center: Clean spacing */}
        <div className="flex-1 flex justify-center max-w-2xl px-8 hidden md:flex">
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

          <div className="flex items-center gap-3 pl-2">
            <button className="text-vt-heading hover:text-vt-accent transition-colors">{t('nav_signin')}</button>
            <button className="bg-vt-accent hover:bg-blue-600 text-white px-4 py-1.5 rounded-full transition-colors font-medium">{t('nav_signup')}</button>
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
