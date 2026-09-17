/** @type {import('tailwindcss').Config} */
export default {
  content: ["./frontend/src/**/*.{html,ts,tsx}"],
  darkMode: ["class", '[data-theme="dark"]'],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["SFMono-Regular", "Cascadia Code", "Consolas", "monospace"],
      },
      boxShadow: {
        panel: "0 24px 70px rgba(2, 8, 23, 0.22)",
      },
    },
  },
  plugins: [],
};
