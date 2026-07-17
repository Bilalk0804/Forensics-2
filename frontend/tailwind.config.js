module.exports = {
  content: ["./src/**/*.{js,jsx}", "./public/index.html"],
  theme: {
    extend: {
      colors: {
        base: "#06080A",
        surface: "#0E1218",
        surface2: "#161B22",
        rule: "#2D333B",
        pri: "#E6EDF3",
        sec: "#8B949E",
        muted: "#484F58",
        accent: "#2F81F7",
        accent2: "#1F6FEB",
        low: "#3FB950",
        med: "#D29922",
        high: "#F78166",
        crit: "#F85149",
      },
      fontFamily: {
        display: ["Chivo", "sans-serif"],
        sans: ["IBM Plex Sans", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },
      borderRadius: {
        DEFAULT: "2px",
      },
      keyframes: {
        pulseRed: {
          "0%,100%": { boxShadow: "0 0 0 0 rgba(248,81,73,0.6)" },
          "50%": { boxShadow: "0 0 0 12px rgba(248,81,73,0)" },
        },
      },
      animation: {
        pulseRed: "pulseRed 1.6s infinite",
      },
    },
  },
  plugins: [],
};
