import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import LanguageDetector from 'i18next-browser-languagedetector'

import en from './locales/en.json'
import ptBR from './locales/pt-BR.json'
import es from './locales/es.json'

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      en:      { translation: en },
      'pt-BR': { translation: ptBR },
      es:      { translation: es },
    },
    // Idiomas suportados — qualquer outro (ex: "fr", "de") cai no fallback
    supportedLngs: ['en', 'pt-BR', 'es'],
    fallbackLng: 'en',
    defaultNS: 'translation',
    detection: {
      // No Capacitor/WebView: localStorage primeiro, depois navigator do device
      order: ['localStorage', 'navigator'],
      caches: ['localStorage'],
      // Chave dedicada para não colidir com outros apps
      lookupLocalStorage: 'ghostscan-lang',
    },
    interpolation: {
      escapeValue: false,
    },
  })

export default i18n
