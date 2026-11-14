const THEME_KEY = 'cerberus.theme'

export type Theme = 'light' | 'dark'

export function readStoredTheme(): Theme | null {
  try {
    const v = localStorage.getItem(THEME_KEY)
    if (v === 'light' || v === 'dark') return v
  } catch {
    /* ignore */
  }
  return null
}

export function systemTheme(): Theme {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

export function applyTheme(theme: Theme) {
  document.documentElement.setAttribute('data-theme', theme)
  try {
    localStorage.setItem(THEME_KEY, theme)
  } catch {
    /* ignore */
  }
}

export function initTheme(): Theme {
  const theme = readStoredTheme() ?? systemTheme()
  applyTheme(theme)
  return theme
}
