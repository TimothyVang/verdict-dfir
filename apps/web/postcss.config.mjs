// Tailwind v4 uses a PostCSS plugin instead of the v3 @tailwind
// directives. The single plugin entry below is enough; v4's
// CSS-first config lives in app/globals.css via @theme.
const config = {
  plugins: {
    "@tailwindcss/postcss": {},
  },
};

export default config;
