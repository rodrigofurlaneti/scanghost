import type { CapacitorConfig } from '@capacitor/cli'

const config: CapacitorConfig = {
  appId: 'br.com.scanghost.app',
  appName: 'GhostScan',
  webDir: 'dist',

  // Android WebView serve os arquivos locais via scheme HTTPS → origin fica
  // "https://localhost", o que o nosso CORS da API permite.
  server: {
    androidScheme: 'https',
  },

  android: {
    // Permite que o WebView chame APIs HTTPS externas (nosso backend Azure)
    allowMixedContent: false,
    // Mantém as barras de status e navegação nativas transparentes
    backgroundColor: '#000000',
  },

  plugins: {
    // CapacitorHttp intercepta fetch/XMLHttpRequest e rota pelo plugin nativo,
    // eliminando problemas de CORS no APK sem precisar de CORS no servidor.
    CapacitorHttp: {
      enabled: true,
    },
  },
}

export default config
