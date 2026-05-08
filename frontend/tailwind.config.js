// File: frontend/tailwind.config.js
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#0a0e1a',
          surface: '#111827',
          card: '#1a2235',
          border: '#1e2d45',
          accent: '#00d4ff',
          green: '#00ff88',
          red: '#ff4444',
          yellow: '#ffd700',
          orange: '#ff8c00',
          purple: '#8b5cf6',
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'Consolas', 'monospace'],
        display: ['"Orbitron"', 'sans-serif'],
        body: ['"Inter"', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s infinite',
        'glow': 'glow 2s ease-in-out infinite',
        'blink': 'blink 1s step-end infinite',
      },
      keyframes: {
        glow: {
          '0%, 100%': { boxShadow: '0 0 5px #00d4ff, 0 0 10px #00d4ff' },
          '50%': { boxShadow: '0 0 20px #00d4ff, 0 0 40px #00d4ff' },
        },
        blink: {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: 0 },
        },
      },
    },
  },
  plugins: [],
};