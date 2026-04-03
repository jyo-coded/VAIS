/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#0D1117",
        card: "#161B22",
        border: "#21262D",
        primary: "#E6EDF3",
        muted: "#8B949E",
        accent: "var(--accent)", // Mapped to CSS variable
      },
    },
  },
  plugins: [],
}
