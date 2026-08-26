import React from 'react';
import { MonitorPlay, Gamepad2, LineChart } from 'lucide-react';
import { useLanguage } from '../context/LanguageContext';

const FeaturesSection = () => {
  const { t } = useLanguage();
  return (
    <div className="w-full bg-vt-subtle py-16 mt-16 border-t border-vt-700 transition-colors">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-12 text-center">
          
          {/* Feature 1 */}
          <div className="flex flex-col items-center">
            <div className="w-16 h-16 rounded-2xl bg-blue-500/15 border border-blue-500/30 flex items-center justify-center mb-6 shadow-sm">
              <MonitorPlay className="w-8 h-8 text-blue-500 dark:text-blue-400" />
            </div>
            <h3 className="text-xl font-bold text-vt-heading mb-3">{t('feat_browser_title')}</h3>
            <p className="text-sm text-vt-text leading-relaxed max-w-xs">
              {t('feat_browser_desc')}
            </p>
          </div>

          {/* Feature 2 */}
          <div className="flex flex-col items-center">
            <div className="w-16 h-16 rounded-2xl bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center mb-6 shadow-sm">
              <Gamepad2 className="w-8 h-8 text-emerald-600 dark:text-emerald-400" />
            </div>
            <h3 className="text-xl font-bold text-vt-heading mb-3">{t('feat_game_title')}</h3>
            <p className="text-sm text-vt-text leading-relaxed max-w-xs">
              {t('feat_game_desc')}
            </p>
          </div>

          {/* Feature 3 */}
          <div className="flex flex-col items-center">
            <div className="w-16 h-16 rounded-2xl bg-rose-500/15 border border-rose-500/30 flex items-center justify-center mb-6 shadow-sm">
              <LineChart className="w-8 h-8 text-rose-600 dark:text-rose-400" />
            </div>
            <h3 className="text-xl font-bold text-vt-heading mb-3">{t('feat_analytics_title')}</h3>
            <p className="text-sm text-vt-text leading-relaxed max-w-xs">
              {t('feat_analytics_desc')}
            </p>
          </div>

        </div>
      </div>
    </div>
  );
};

export default FeaturesSection;
