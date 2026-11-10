/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          darkest: '#080c14',
          card: '#0f172a',
          cardLight: '#1e293b',
          border: '#1e293b',
          borderLight: '#334155',
          accent: '#06b6d4',
          accentBlue: '#3b82f6',
          textMuted: '#94a3b8',
        }
      }
    },
  },
  plugins: [],
}
