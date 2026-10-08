import { useCallback, useEffect, useState } from "react";

export type ThemeMode = "light" | "dark";

const STORAGE_KEY = "dnsguard-theme";

function initialTheme(): ThemeMode {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === "light" || saved === "dark") return saved;
  } catch {
    /* storage may be unavailable */
  }
  const prefersDark =
    typeof window !== "undefined" &&
    window.matchMedia?.("(prefers-color-scheme: dark)").matches;
  return prefersDark ? "dark" : "light";
}

/** Theme state synced to <html data-theme> and localStorage. */
export function useTheme(): { theme: ThemeMode; toggle: () => void } {
  const [theme, setTheme] = useState<ThemeMode>(initialTheme);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      /* ignore */
    }
  }, [theme]);

  const toggle = useCallback(
    () => setTheme((t) => (t === "dark" ? "light" : "dark")),
    [],
  );

  return { theme, toggle };
}

export interface ChartColors {
  series: string[];
  flagged: string;
  normal: string;
  grid: string;
  text: string;
  primary: string;
}

// Kept in sync with index.css so charts match the active theme without any
// dependence on when the DOM's data-theme attribute updates.
const PALETTES: Record<ThemeMode, ChartColors> = {
  light: {
    series: ["#e8690b", "#1e6fd9", "#1a7f37", "#8250df", "#c62828", "#b8860b", "#5b6470"],
    flagged: "#e8690b",
    normal: "#9fb0bf",
    grid: "#ece2d8",
    text: "#6b625b",
    primary: "#e8690b",
  },
  dark: {
    series: ["#2dd4bf", "#38bdf8", "#4ade80", "#a78bfa", "#fb7185", "#fbbf24", "#94a3b8"],
    flagged: "#2dd4bf",
    normal: "#46606a",
    grid: "#1b2824",
    text: "#8ba39b",
    primary: "#2dd4bf",
  },
};

/** Chart colours for the active theme. */
export function chartColors(theme: ThemeMode): ChartColors {
  return PALETTES[theme];
}
