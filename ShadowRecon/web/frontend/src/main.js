import { createApp } from 'vue'
import { createPinia } from 'pinia'
import PrimeVue from 'primevue/config'
import Aura from '@primeuix/themes/aura'
import { definePreset } from '@primeuix/themes'
import ToastService from 'primevue/toastservice'
import ConfirmationService from 'primevue/confirmationservice'
import 'primeicons/primeicons.css'
import router from './router.js'
import App from './App.vue'

const ShadowReconPreset = definePreset(Aura, {
  semantic: {
    primary: {
      50: '#e0faff',
      100: '#b3f0ff',
      200: '#80e5ff',
      300: '#4ddbff',
      400: '#26d1ff',
      500: '#00e5ff',
      600: '#00b8d4',
      700: '#0095a8',
      800: '#00707c',
      900: '#004d54',
      950: '#00333a',
    },
    colorScheme: {
      dark: {
        surface: {
          0: '#ffffff',
          50: '#f2f4f8',
          100: '#e0e0e0',
          200: '#b0b8c4',
          300: '#8899aa',
          400: '#556677',
          500: '#1e3a5f',
          600: '#111927',
          700: '#0f1a2e',
          800: '#0a0e17',
          900: '#080b12',
          950: '#04060a',
        },
      },
    },
  },
})

const app = createApp(App)
app.use(createPinia())
app.use(router)
app.use(PrimeVue, {
  theme: {
    preset: ShadowReconPreset,
    options: {
      darkModeSelector: '.app-dark',
    },
  },
})
app.use(ToastService)
app.use(ConfirmationService)
app.mount('#app')
