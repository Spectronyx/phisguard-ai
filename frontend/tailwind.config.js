/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        canvas: "#070b12",
        panel: "#0d1420",
        "panel-2": "#111a29",
        line: "#1e2a3d",
        ink: "#e6edf7",
        muted: "#8fa3bf",
        accent: "#22d3ee",
        safe: "#34d399",
        warn: "#fbbf24",
        danger: "#fb7185",
        violet: "#a78bfa",
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      boxShadow: {
        glow: "0 0 40px -12px rgba(34, 211, 238, 0.35)",
      },
    },
  },
  plugins: [],
};
