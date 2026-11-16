import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { translate, type Language, type TranslationKey } from './translations';

interface I18nContextValue {
  lang: Language;
  setLang: (lang: Language) => void;
  isRtl: boolean;
  t: (key: TranslationKey, vars?: Record<string, string | number>) => string;
}

const STORAGE_KEY = 'packetscope_lang';

const I18nContext = createContext<I18nContextValue | null>(null);

function readInitialLanguage(): Language {
  if (typeof window === 'undefined') return 'en';
  const saved = window.localStorage.getItem(STORAGE_KEY);
  if (saved === 'en' || saved === 'ckb' || saved === 'ar') return saved;
  return 'en';
}

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangState] = useState<Language>(readInitialLanguage);
  const isRtl = lang === 'ckb' || lang === 'ar';

  useEffect(() => {
    if (typeof document !== 'undefined') {
      document.documentElement.lang = lang;
      document.documentElement.dir = isRtl ? 'rtl' : 'ltr';
    }
    if (typeof window !== 'undefined') {
      window.localStorage.setItem(STORAGE_KEY, lang);
    }
  }, [lang, isRtl]);

  const setLang = useCallback((next: Language) => {
    setLangState(next);
  }, []);

  const t = useCallback(
    (key: TranslationKey, vars?: Record<string, string | number>) => translate(lang, key, vars),
    [lang]
  );

  return (
    <I18nContext.Provider value={{ lang, setLang, isRtl, t }}>
      {children}
    </I18nContext.Provider>
  );
}

export function useI18n() {
  const ctx = useContext(I18nContext);
  if (!ctx) {
    throw new Error('useI18n must be used inside I18nProvider');
  }
  return ctx;
}

const LANGUAGE_OPTIONS: Array<{ code: Language; label: string }> = [
  { code: 'en', label: 'EN' },
  { code: 'ckb', label: 'کوردی' },
  { code: 'ar', label: 'العربية' },
];

export function LanguageSwitcher({ compact = false }: { compact?: boolean }) {
  const { lang, setLang, t } = useI18n();

  return (
    <div
      role="group"
      aria-label={t('languageLabel')}
      className="inline-flex items-center p-0.5 bg-[#070B14] border border-slate-800 rounded-lg shrink-0"
      dir="ltr"
    >
      {LANGUAGE_OPTIONS.map((opt) => {
        const active = lang === opt.code;
        return (
          <button
            key={opt.code}
            type="button"
            onClick={() => setLang(opt.code)}
            aria-pressed={active}
            className={`${
              compact ? 'px-2 py-1 text-[11px]' : 'px-2.5 py-1 text-xs'
            } font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
              active ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}
