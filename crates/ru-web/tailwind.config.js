/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.rs", "./index.html"],
  theme: {
    extend: {
      colors: {
        amber: {
          500: '#f59e0a',
          400: '#fbbf24',
        },
        blue: {
          500: '#3b82f6',
          400: '#60a5fa',
        },
        green: {
          500: '#22c55e',
          400: '#4ade80',
        },
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['IBM Plex Mono', 'monospace'],
      },
    },
  },
  plugins: [],
}
