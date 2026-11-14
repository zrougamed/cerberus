import {
  Activity,
  AlertTriangle,
  HardDrive,
  LayoutDashboard,
  Menu,
  Moon,
  Pause,
  Play,
  Radar,
  ScrollText,
  Shield,
  Sun,
  LineChart,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { useLive } from '../lib/live'
import { cn } from '../lib/cn'
import { Logo } from './Logo'

const titles: Record<string, string> = {
  '/': 'Dashboard',
  '/analytics': 'Analytics',
  '/devices': 'Devices',
  '/alerts': 'Rule alerts',
  '/anomalies': 'Anomalies',
  '/policy': 'Policy',
  '/raw': 'Raw JSON',
}

const nav = [
  {
    group: 'Monitor',
    items: [
      { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
      { to: '/analytics', label: 'Analytics', icon: LineChart },
      { to: '/devices', label: 'Devices', icon: HardDrive },
      { to: '/alerts', label: 'Rule alerts', icon: AlertTriangle },
      { to: '/anomalies', label: 'Anomalies', icon: Radar },
    ],
  },
  {
    group: 'Response',
    items: [{ to: '/policy', label: 'Policy', icon: Shield }],
  },
  {
    group: 'Tools',
    items: [{ to: '/raw', label: 'Raw JSON', icon: ScrollText }],
  },
]

function useTheme() {
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    const attr = document.documentElement.getAttribute('data-theme')
    if (attr === 'light' || attr === 'dark') return attr
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  })

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

  return {
    theme,
    toggle: () => setTheme((t) => (t === 'dark' ? 'light' : 'dark')),
  }
}

export function Shell() {
  const { paused, setPaused, version } = useLive()
  const { theme, toggle } = useTheme()
  const location = useLocation()
  const [collapsed, setCollapsed] = useState(() => {
    try {
      const stored = sessionStorage.getItem('cerberus.sidebar.collapsed')
      if (stored === '1' || stored === '0') return stored === '1'
    } catch {
      /* ignore */
    }
    return window.matchMedia('(max-width: 759px)').matches
  })

  useEffect(() => {
    try {
      sessionStorage.setItem('cerberus.sidebar.collapsed', collapsed ? '1' : '0')
    } catch {
      /* ignore */
    }
  }, [collapsed])

  const path = location.pathname.startsWith('/device/')
    ? '/devices'
    : location.pathname.startsWith('/raw')
      ? '/raw'
      : location.pathname
  const title = titles[path] || 'Control Room'

  return (
    <div
      className={cn(
        'grid min-h-full',
        collapsed ? 'grid-cols-1' : 'md:grid-cols-[220px_minmax(0,1fr)] grid-cols-1',
      )}
    >
      <aside
        className={cn(
          'z-20 flex flex-col gap-2 border-r border-white/10 bg-[var(--sidebar)] p-3 text-[var(--sidebar-text)]',
          collapsed
            ? 'pointer-events-none fixed inset-y-0 left-0 w-[min(80vw,220px)] -translate-x-[110%] md:static md:w-0 md:p-0 md:overflow-hidden md:border-0'
            : 'fixed inset-y-0 left-0 w-[min(80vw,220px)] shadow-xl md:static md:shadow-none',
        )}
        aria-label="Primary"
      >
        <div className="mb-2 flex items-center gap-2.5 border-b border-white/10 px-2 pb-3">
          <Logo />
          <div>
            <p className="font-[family-name:var(--font-display)] text-lg font-bold leading-tight">Cerberus</p>
            <p className="text-xs text-[var(--sidebar-muted)]">Control Room</p>
          </div>
        </div>

        <nav className="flex flex-1 flex-col gap-0.5" aria-label="Main">
          {nav.map((section) => (
            <div key={section.group}>
              <p className="mb-1 mt-3 px-2 font-mono text-[0.7rem] tracking-wide text-[var(--sidebar-muted)]">
                {section.group}
              </p>
              {section.items.map((item) => {
                const Icon = item.icon
                return (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    end={item.end}
                    onClick={() => {
                      if (window.matchMedia('(max-width: 759px)').matches) setCollapsed(true)
                    }}
                    className={({ isActive }) =>
                      cn(
                        'flex items-center gap-2 rounded px-3 py-2.5 text-[0.95rem] font-semibold no-underline',
                        isActive
                          ? 'border-l-[3px] border-[#d4a017] bg-[#d4a017]/20 text-white'
                          : 'border-l-[3px] border-transparent text-[var(--sidebar-text)] hover:bg-white/10',
                      )
                    }
                  >
                    <Icon size={16} aria-hidden />
                    {item.label}
                  </NavLink>
                )
              })}
            </div>
          ))}
        </nav>

        <div className="mt-auto grid gap-2 border-t border-white/10 pt-3">
          <p className="break-all px-2 font-mono text-[0.7rem] text-[var(--sidebar-muted)]">
            Build: {version?.commit || '…'}
            {version?.date ? ` (${version.date})` : ''}
          </p>
          <button type="button" className="btn w-full text-sm text-[var(--sidebar-muted)]" onClick={() => setCollapsed(true)}>
            Hide menu
          </button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-col">
        <header className="sticky top-0 z-10 flex min-h-16 items-center justify-between gap-4 border-b border-[var(--line)] bg-[var(--surface)] px-5 py-3">
          <div className="flex min-w-0 items-center gap-3">
            <button type="button" className="btn" hidden={!collapsed} onClick={() => setCollapsed(false)}>
              <Menu size={16} aria-hidden />
              Show menu
            </button>
            <h1 className="m-0 font-[family-name:var(--font-display)] text-[clamp(1.25rem,2.5vw,1.65rem)] font-bold">
              {title}
            </h1>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              className={cn('btn', paused && 'border-[var(--signal)] bg-[var(--signal)] text-[#0c1016]')}
              onClick={() => setPaused(!paused)}
              aria-label={paused ? 'Resume live updates' : 'Pause live updates'}
            >
              {paused ? <Play size={16} aria-hidden /> : <Pause size={16} aria-hidden />}
              {paused ? 'Resume updates' : 'Pause updates'}
            </button>
            <button type="button" className="btn" onClick={toggle} aria-label="Toggle theme">
              {theme === 'dark' ? <Sun size={16} aria-hidden /> : <Moon size={16} aria-hidden />}
              {theme === 'dark' ? 'Light mode' : 'Dark mode'}
            </button>
          </div>
        </header>

        <main className="flex-1 p-4 md:p-5">
          {paused ? (
            <p className="mb-3 inline-flex items-center gap-2 rounded bg-[var(--signal)] px-2 py-1 font-mono text-xs font-bold uppercase text-[#0c1016]">
              <Activity size={12} aria-hidden /> Updates paused
            </p>
          ) : null}
          <Outlet />
        </main>
      </div>
    </div>
  )
}
