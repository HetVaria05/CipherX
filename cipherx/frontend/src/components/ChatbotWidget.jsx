import React, { useState } from 'react';
import { MessageSquare, RefreshCcw, ArrowDownRight, CloudUpload, Headphones, BookOpen, Star, Mail, Send } from 'lucide-react';
import { useLanguage } from '../context/LanguageContext';

const ChatbotWidget = () => {
  const { t } = useLanguage();
  const [isOpen, setIsOpen] = useState(false);

  return (
    <>
      {/* Floating Action Button */}
      <button
        onClick={() => setIsOpen(true)}
        className={`fixed bottom-6 right-6 p-4 rounded-full bg-vt-accent hover:bg-blue-600 text-white shadow-xl transition-all z-50 ${isOpen ? 'scale-0' : 'scale-100'}`}
      >
        <MessageSquare className="w-7 h-7" />
      </button>

      {/* Chat Window */}
      <div className={`fixed bottom-6 right-6 w-96 max-w-[calc(100vw-2rem)] h-[550px] bg-vt-900 border border-vt-700 rounded-xl shadow-2xl flex flex-col overflow-hidden transition-all duration-300 z-50 ${isOpen ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10 pointer-events-none'}`}>

        {/* Header */}
        <div className="bg-[#4b6bfb] p-4 flex items-center justify-between text-white">
          <h3 className="text-lg font-medium">{t('chat_header')}</h3>
          <div className="flex gap-2 text-white/80">
            <button className="hover:text-white transition-colors"><RefreshCcw className="w-5 h-5" /></button>
            <button onClick={() => setIsOpen(false)} className="hover:text-white transition-colors"><ArrowDownRight className="w-5 h-5" /></button>
          </div>
        </div>

        {/* Chat Content */}
        <div className="flex-1 p-4 overflow-y-auto space-y-4">

          {/* Greeting Bubble */}
          <div className="bg-vt-800 p-4 rounded-xl text-sm leading-relaxed border border-vt-700 shadow-inner">
            <p className="mb-3 text-vt-heading font-medium">{t('chat_greet_1')}</p>
            <p className="text-vt-text">
              {t('chat_greet_2')} <span className="font-bold text-vt-heading">{t('chat_greet_3')}</span> {t('chat_greet_4')} <span className="font-bold text-vt-heading">{t('chat_greet_5')}</span>{t('chat_greet_6')}
            </p>
          </div>

          {/* Options Card */}
          <div className="bg-vt-800 rounded-xl border border-vt-700 overflow-hidden divide-y divide-vt-700 shadow-sm">
            <button className="w-full flex items-center gap-4 p-4 hover:bg-vt-900/60 transition-colors text-left group">
              <CloudUpload className="w-5 h-5 text-vt-text group-hover:text-vt-accent transition-colors" />
              <span className="text-sm text-vt-heading font-medium group-hover:text-vt-accent transition-colors">{t('chat_opt_1')}</span>
            </button>
            <button className="w-full flex items-center gap-4 p-4 hover:bg-vt-900/60 transition-colors text-left group">
              <Headphones className="w-5 h-5 text-vt-text group-hover:text-vt-accent transition-colors" />
              <span className="text-sm text-vt-heading font-medium group-hover:text-vt-accent transition-colors">{t('chat_opt_2')}</span>
            </button>
            <button className="w-full flex items-center gap-4 p-4 hover:bg-vt-900/60 transition-colors text-left group">
              <BookOpen className="w-5 h-5 text-vt-text group-hover:text-vt-accent transition-colors" />
              <span className="text-sm text-vt-heading font-medium group-hover:text-vt-accent transition-colors">{t('chat_opt_3')}</span>
            </button>
            <button className="w-full flex items-center gap-4 p-4 hover:bg-vt-900/60 transition-colors text-left group">
              <Star className="w-5 h-5 text-vt-text group-hover:text-vt-accent transition-colors" />
              <span className="text-sm text-vt-heading font-medium group-hover:text-vt-accent transition-colors">{t('chat_opt_4')}</span>
            </button>
            <button className="w-full flex items-center gap-4 p-4 hover:bg-vt-900/60 transition-colors text-left group">
              <Mail className="w-5 h-5 text-vt-text group-hover:text-vt-accent transition-colors" />
              <span className="text-sm text-vt-heading font-medium group-hover:text-vt-accent transition-colors">{t('chat_opt_5')}</span>
            </button>
          </div>

          <div className="text-center">
            <span className="inline-block bg-vt-800 border border-vt-700 text-xs px-3 py-1 rounded-full text-vt-text mt-2">{t('chat_soon')}</span>
          </div>
        </div>

        {/* Input Area */}
        <div className="p-3 border-t border-vt-700 bg-vt-800 flex items-center">
          <input
            type="text"
            placeholder={t('chat_input')}
            className="flex-1 bg-transparent border-none focus:outline-none text-sm text-vt-heading placeholder-vt-text px-2"
            disabled
          />
          <button className="p-2 text-vt-text opacity-50 cursor-not-allowed">
            <Send className="w-4 h-4" />
          </button>
        </div>

      </div>
    </>
  );
};

export default ChatbotWidget;
