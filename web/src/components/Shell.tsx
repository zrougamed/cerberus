import {
  Activity,
  AlertTriangle,
  BookOpen,
  HardDrive,
  LayoutDashboard,
  LineChart,
  Menu,
  Moon,
  PanelLeftClose,
  Pause,
  Play,
  Radar,
  ScrollText,
  Shield,
  Sun,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { cn } from '../lib/cn'
import { useLive } from '../lib/live'
import { applyTheme, initTheme, type Theme } from '../lib/theme'
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

type NavItem = {
  to: string
  label: string
  icon: typeof LayoutDashboard
  end?: boolean
  external?: boolean
}

const nav: Array<{ group: string; items: NavItem[] }> = [
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
    items: [
      { to: '/raw', label: 'Raw JSON', icon: ScrollText },
      { to: '/docs', label: 'API docs', icon: BookOpen, external: true },
    ],
  },
]

function useTheme() {
  const [theme, setTheme] = useState<Theme>(() => initTheme())

  useEffect(() => {
    applyTheme(theme)
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
  const [open, setOpen] = useState(() => !window.matchMedia('(max-width: 759px)').matches)

  useEffect(() => {
    const mq = window.matchMedia('(max-width: 759px)')
    const onChange = () => {
      if (mq.matches) setOpen(false)
      else setOpen(true)
    }
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [])

  const path = location.pathname.startsWith('/device/')
    ? '/devices'
    : location.pathname.startsWith('/raw')
      ? '/raw'
      : location.pathname
  const title = titles[path] || 'Control Room'

  return (
    <div className="flex h-dvh overflow-hidden">
      {open ? (
        <button
          type="button"
          className="fixed inset-0 z-20 bg-black/40 md:hidden"
          aria-label="Close menu"
          onClick={() => setOpen(false)}
        />
      ) : null}

      <aside
        id="sidebar"
        className={cn(
          'z-30 flex h-dvh w-[220px] shrink-0 flex-col border-r border-white/10 bg-[var(--sidebar)] text-[var(--sidebar-text)] transition-[transform,margin] duration-200',
          'fixed inset-y-0 left-0 md:static',
          open ? 'translate-x-0' : 'pointer-events-none -translate-x-full md:w-0 md:overflow-hidden md:border-0 md:translate-x-0',
        )}
        aria-label="Primary"
        aria-hidden={!open}
      >
        <div
          className={cn(
            'flex h-full w-[220px] flex-col gap-2 p-3',
            !open && 'md:invisible',
          )}
        >
          <div className="flex shrink-0 items-center justify-between gap-2 border-b border-white/10 px-1 pb-3">
            <div className="flex min-w-0 items-center gap-2.5">
              <Logo />
              <div className="min-w-0">
                <p className="font-[family-name:var(--font-display)] text-lg font-bold leading-tight">Cerberus</p>
                <p className="text-xs text-[var(--sidebar-muted)]">Control Room</p>
              </div>
            </div>
            <button
              type="button"
              className="btn shrink-0 border-white/20 bg-transparent text-[var(--sidebar-text)]"
              aria-label="Hide menu"
              title="Hide menu"
              onClick={() => setOpen(false)}
            >
              <PanelLeftClose size={16} aria-hidden />
            </button>
          </div>

          <nav className="flex min-h-0 flex-1 flex-col gap-0.5 overflow-y-auto" aria-label="Main">
            {nav.map((section) => (
              <div key={section.group}>
                <p className="mb-1 mt-3 px-2 font-mono text-[0.7rem] tracking-wide text-[var(--sidebar-muted)]">
                  {section.group}
                </p>
                {section.items.map((item) => {
                  const Icon = item.icon
                  if (item.external) {
                    return (
                      <a
                        key={item.to}
                        href={item.to}
                        target="_blank"
                        rel="noreferrer"
                        className="flex items-center gap-2 rounded border-l-[3px] border-transparent px-3 py-2.5 text-[0.95rem] font-semibold text-[var(--sidebar-text)] no-underline hover:bg-white/10"
                      >
                        <Icon size={16} aria-hidden />
                        {item.label}
                      </a>
                    )
                  }
                  return (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      end={Boolean(item.end)}
                      onClick={() => {
                        if (window.matchMedia('(max-width: 759px)').matches) setOpen(false)
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

          <p className="shrink-0 break-all border-t border-white/10 px-2 pt-3 font-mono text-[0.7rem] text-[var(--sidebar-muted)]">
            Build: {version?.commit || '…'}
            {version?.date ? ` (${version.date})` : ''}
          </p>
        </div>
      </aside>

      <div className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
        <header className="flex shrink-0 items-center justify-between gap-4 border-b border-[var(--line)] bg-[var(--surface)] px-5 py-3">
          <div className="flex min-w-0 items-center gap-3">
            {!open ? (
              <button
                type="button"
                className="btn"
                onClick={() => setOpen(true)}
                aria-expanded={open}
                aria-controls="sidebar"
              >
                <Menu size={16} aria-hidden />
                Show menu
              </button>
            ) : null}
            <h1 className="m-0 truncate font-[family-name:var(--font-display)] text-[clamp(1.25rem,2.5vw,1.65rem)] font-bold">
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
              <span className="hidden sm:inline">{paused ? 'Resume updates' : 'Pause updates'}</span>
            </button>
            <button type="button" className="btn" onClick={toggle} aria-label="Toggle theme">
              {theme === 'dark' ? <Sun size={16} aria-hidden /> : <Moon size={16} aria-hidden />}
              <span className="hidden sm:inline">{theme === 'dark' ? 'Light mode' : 'Dark mode'}</span>
            </button>
          </div>
        </header>

        <main className="min-h-0 flex-1 overflow-y-auto p-4 md:p-5">
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
