import React, { createContext, useContext, useState, useCallback, useMemo } from 'react';
import { TRANSLATIONS, SUPPORTED_LANGS, DEFAULT_LANG } from '../i18n/translations';

const LanguageContext = createContext(null);
const STORAGE_KEY = 'fh.lang';

function readStoredLang() {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v && SUPPORTED_LANGS.includes(v)) return v;
  } catch { /* ignore */ }
  return DEFAULT_LANG;
}

export function LanguageProvider({ children }) {
  const [lang, setLangState] = useState(readStoredLang);

  const setLang = useCallback(next => {
    if (!SUPPORTED_LANGS.includes(next)) return;
    try { localStorage.setItem(STORAGE_KEY, next); } catch { /* ignore */ }
    document.documentElement.setAttribute('lang', next);
    setLangState(next);
  }, []);

  const t = useCallback((key, vars) => {
    const dict = TRANSLATIONS[lang] || TRANSLATIONS[DEFAULT_LANG];
    let str = dict[key] ?? TRANSLATIONS[DEFAULT_LANG][key] ?? key;
    if (vars) {
      for (const k of Object.keys(vars)) {
        str = str.replaceAll(`{${k}}`, String(vars[k]));
      }
    }
    return str;
  }, [lang]);

  const value = useMemo(() => ({ lang, setLang, t, langs: SUPPORTED_LANGS }), [lang, setLang, t]);

  return (
    <LanguageContext.Provider value={value}>
      {children}
    </LanguageContext.Provider>
  );
}

export function useTranslation() {
  const ctx = useContext(LanguageContext);
  if (!ctx) {
    return {
      lang: DEFAULT_LANG,
      setLang: () => {},
      t: k => TRANSLATIONS[DEFAULT_LANG][k] ?? k,
      langs: SUPPORTED_LANGS,
    };
  }
  return ctx;
}
