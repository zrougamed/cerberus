import {
  Activity,
  AlertTriangle,
  Boxes,
  GitCompareArrows,
  Network,
  FileDown,
  BookOpen,
  HardDrive,
  LayoutDashboard,
  LineChart,
  LogIn,
  LogOut,
  Menu,
  Moon,
  PanelLeftClose,
  PanelLeftOpen,
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
import { useSession } from '../lib/session'
import { applyTheme, initTheme, type Theme } from '../lib/theme'
import { Logo } from './Logo'

const titles: Record<string, string> = {
  '/': 'Dashboard',
  '/analytics': 'Analytics',
  '/devices': 'Devices',
  '/assets': 'Assets',
  '/alerts': 'Rule alerts',
  '/anomalies': 'Anomalies',
  '/policy': 'Policy',
  '/baseline': 'Flow baseline',
  '/zones': 'Zones',
  '/captures': 'Packet captures',
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
      { to: '/assets', label: 'Assets', icon: Boxes },
      { to: '/zones', label: 'Zones', icon: Network },
      { to: '/alerts', label: 'Rule alerts', icon: AlertTriangle },
      { to: '/anomalies', label: 'Anomalies', icon: Radar },
    ],
  },
  {
    group: 'Response',
    items: [
      { to: '/policy', label: 'Policy', icon: Shield },
      { to: '/baseline', label: 'Flow baseline', icon: GitCompareArrows },
      { to: '/captures', label: 'Captures', icon: FileDown },
    ],
  },
  {
    group: 'Tools',
    items: [
      { to: '/raw', label: 'Raw JSON', icon: ScrollText },
      { to: '/docs', label: 'API docs', icon: BookOpen, external: true },
    ],
  },
]

const allNavItems = nav.flatMap((section) => section.items)

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

function navClass(isActive: boolean, collapsed: boolean) {
  return cn(
    'flex items-center rounded no-underline transition-colors',
    collapsed ? 'justify-center px-0 py-2.5' : 'gap-2 border-l-[3px] px-3 py-2.5 text-[0.95rem] font-semibold',
    isActive
      ? collapsed
        ? 'bg-[#d4a017]/25 text-white'
        : 'border-[#d4a017] bg-[#d4a017]/20 text-white'
      : collapsed
        ? 'text-[var(--sidebar-text)] hover:bg-white/10'
        : 'border-transparent text-[var(--sidebar-text)] hover:bg-white/10',
  )
}

export function Shell() {
  const { paused, setPaused, version } = useLive()
  const { theme, toggle } = useTheme()
  const { session, signOut } = useSession()
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
  const collapsed = !open

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
          'z-30 flex h-dvh shrink-0 flex-col border-r border-white/10 bg-[var(--sidebar)] text-[var(--sidebar-text)] transition-[width,transform] duration-200',
          'fixed inset-y-0 left-0 md:static md:translate-x-0',
          open ? 'w-[220px] translate-x-0' : 'w-[64px] -translate-x-full md:translate-x-0',
        )}
        aria-label="Primary"
        aria-expanded={open}
      >
        <div className={cn('flex h-full flex-col', open ? 'w-[220px] gap-2 p-3' : 'w-[64px] items-center gap-1 p-2')}>
          <div
            className={cn(
              'flex shrink-0 border-b border-white/10',
              open ? 'items-center justify-between gap-2 px-1 pb-3' : 'flex-col items-center gap-2 pb-2',
            )}
          >
            <div className={cn('flex min-w-0 items-center', open ? 'gap-2.5' : 'justify-center')}>
              <Logo className={open ? 'h-10 w-10' : 'h-9 w-9'} />
              {open ? (
                <div className="min-w-0">
                  <p className="font-[family-name:var(--font-display)] text-lg font-bold leading-tight">Cerberus</p>
                  <p className="text-xs text-[var(--sidebar-muted)]">Control Room</p>
                </div>
              ) : null}
            </div>
            <button
              type="button"
              className="btn shrink-0 border-white/20 bg-transparent text-[var(--sidebar-text)]"
              aria-label={open ? 'Collapse menu' : 'Expand menu'}
              title={open ? 'Collapse menu' : 'Expand menu'}
              onClick={() => setOpen((v) => !v)}
            >
              {open ? <PanelLeftClose size={16} aria-hidden /> : <PanelLeftOpen size={16} aria-hidden />}
            </button>
          </div>

          <nav className="flex min-h-0 flex-1 flex-col gap-0.5 overflow-y-auto" aria-label="Main">
            {open
              ? nav.map((section) => (
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
                            title={item.label}
                            className={navClass(false, false)}
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
                          title={item.label}
                          onClick={() => {
                            if (window.matchMedia('(max-width: 759px)').matches) setOpen(false)
                          }}
                          className={({ isActive }) => navClass(isActive, false)}
                        >
                          <Icon size={16} aria-hidden />
                          {item.label}
                        </NavLink>
                      )
                    })}
                  </div>
                ))
              : allNavItems.map((item) => {
                  const Icon = item.icon
                  if (item.external) {
                    return (
                      <a
                        key={item.to}
                        href={item.to}
                        target="_blank"
                        rel="noreferrer"
                        title={item.label}
                        aria-label={item.label}
                        className={navClass(false, true)}
                      >
                        <Icon size={18} aria-hidden />
                      </a>
                    )
                  }
                  return (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      end={Boolean(item.end)}
                      title={item.label}
                      aria-label={item.label}
                      className={({ isActive }) => navClass(isActive, true)}
                    >
                      <Icon size={18} aria-hidden />
                    </NavLink>
                  )
                })}
          </nav>

          {open ? (
            <p className="shrink-0 break-all border-t border-white/10 px-2 pt-3 font-mono text-[0.7rem] text-[var(--sidebar-muted)]">
              Build: {version?.commit || '…'}
              {version?.date ? ` (${version.date})` : ''}
            </p>
          ) : null}
        </div>
      </aside>

      <div className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
        <header className="flex shrink-0 items-center justify-between gap-4 border-b border-[var(--line)] bg-[var(--surface)] px-5 py-3">
          <div className="flex min-w-0 items-center gap-3">
            {collapsed ? (
              <button
                type="button"
                className="btn md:hidden"
                onClick={() => setOpen(true)}
                aria-expanded={open}
                aria-controls="sidebar"
              >
                <Menu size={16} aria-hidden />
                Menu
              </button>
            ) : null}
            <h1 className="m-0 truncate font-[family-name:var(--font-display)] text-[clamp(1.25rem,2.5vw,1.65rem)] font-bold">
              {title}
            </h1>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {session?.method === 'oidc' ? (
              <>
                <span className="hidden text-sm lg:inline">
                  {session.name} <span className="muted">({session.role})</span>
                </span>
                <button type="button" className="btn" onClick={() => void signOut()} aria-label={`Sign out ${session.name}`}>
                  <LogOut size={16} aria-hidden />
                  <span className="hidden sm:inline">Sign out</span>
                </button>
              </>
            ) : session?.oidc && session.login_url && !session.authenticated ? (
              <a className="btn no-underline" href={session.login_url}>
                <LogIn size={16} aria-hidden />
                <span className="hidden sm:inline">Sign in</span>
                <span className="sr-only sm:hidden">Sign in</span>
              </a>
            ) : null}
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

        <main tabIndex={0} className="min-h-0 flex-1 overflow-y-auto p-4 md:p-5">
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
