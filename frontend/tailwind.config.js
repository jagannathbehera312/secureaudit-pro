/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        soc: {
          bg: "#0B0F19",
          card: "#111827",
          panel: "#161F30",
          border: "#1E293B",
          cyan: "#06B6D4",
          violet: "#8B5CF6",
          critical: "#EF4444",
          high: "#F97316",
          medium: "#EAB308",
          low: "#10B981",
          info: "#3B82F6",
          text: "#F8FAFC",
          muted: "#94A3B8"
        }
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "Courier New", "monospace"]
      }
    },
  },
  plugins: [],
}
