/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{vue,js,ts}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#0a0e17',
          surface: '#111927',
          'surface-2': '#0f1a2e',
          border: '#1e3a5f',
          accent: '#00e5ff',
          text: '#e0e0e0',
          muted: '#8899aa',
          'muted-2': '#556677',
          danger: '#ff1744',
          warning: '#ff9100',
          medium: '#ffd600',
          success: '#00c853',
          llm: '#7c4dff',
          'llm-light': '#b388ff',
        },
      },
      fontFamily: {
        sans: ['Segoe UI', 'system-ui', '-apple-system', 'sans-serif'],
      },
      animation: {
        'pulse-dot': 'pulse-dot 1s infinite',
      },
      keyframes: {
        'pulse-dot': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.4' },
        },
      },
    },
  },
  plugins: [],
}
