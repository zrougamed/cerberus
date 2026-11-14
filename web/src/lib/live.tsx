import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import {
  fetchAlerts,
  fetchAnomalies,
  fetchDevices,
  fetchPolicy,
  fetchPolicyLog,
  fetchSummary,
  fetchVersion,
} from './api'
import type {
  AlertEvent,
  AnomalySnapshot,
  DeviceSummary,
  PolicyLogEntry,
  PolicyState,
  Summary,
  VersionInfo,
} from './types'

type LiveState = {
  summary?: Summary
  devices?: DeviceSummary[]
  alerts?: AlertEvent[]
  anomalies?: AnomalySnapshot
  policy?: PolicyState
  policyError?: string
  policyLog?: PolicyLogEntry[]
  version?: VersionInfo
  paused: boolean
  setPaused: (v: boolean) => void
  refresh: () => Promise<void>
  reloadPolicy: () => Promise<void>
}

const LiveCtx = createContext<LiveState | null>(null)

export function LiveProvider({ children }: { children: ReactNode }) {
  const [summary, setSummary] = useState<Summary>()
  const [devices, setDevices] = useState<DeviceSummary[]>()
  const [alerts, setAlerts] = useState<AlertEvent[]>()
  const [anomalies, setAnomalies] = useState<AnomalySnapshot>()
  const [policy, setPolicy] = useState<PolicyState>()
  const [policyError, setPolicyError] = useState<string>()
  const [policyLog, setPolicyLog] = useState<PolicyLogEntry[]>()
  const [version, setVersion] = useState<VersionInfo>()
  const [paused, setPaused] = useState(false)

  const reloadPolicy = useCallback(async () => {
    try {
      const [st, log] = await Promise.all([fetchPolicy(), fetchPolicyLog()])
      setPolicy(st)
      setPolicyError(undefined)
      const entries = Array.isArray(log) ? log : log.entries || []
      setPolicyLog(entries)
    } catch (e) {
      setPolicyError(e instanceof Error ? e.message : 'Policy unavailable')
    }
  }, [])

  const refresh = useCallback(async () => {
    try {
      const [s, d, a, an] = await Promise.all([
        fetchSummary(),
        fetchDevices(),
        fetchAlerts(),
        fetchAnomalies(),
      ])
      setSummary(s)
      setDevices(d)
      setAlerts(a)
      setAnomalies(an)
    } catch {
      /* keep last good snapshot */
    }
    await reloadPolicy()
  }, [reloadPolicy])

  useEffect(() => {
    fetchVersion()
      .then(setVersion)
      .catch(() => setVersion({ commit: 'unknown', date: 'unknown' }))
  }, [])

  useEffect(() => {
    refresh()
    const id = window.setInterval(() => {
      if (!paused) void refresh()
    }, 3000)
    return () => window.clearInterval(id)
  }, [paused, refresh])

  const value = useMemo(
    () => ({
      summary,
      devices,
      alerts,
      anomalies,
      policy,
      policyError,
      policyLog,
      version,
      paused,
      setPaused,
      refresh,
      reloadPolicy,
    }),
    [
      summary,
      devices,
      alerts,
      anomalies,
      policy,
      policyError,
      policyLog,
      version,
      paused,
      refresh,
      reloadPolicy,
    ],
  )

  return <LiveCtx.Provider value={value}>{children}</LiveCtx.Provider>
}

export function useLive() {
  const ctx = useContext(LiveCtx)
  if (!ctx) throw new Error('useLive requires LiveProvider')
  return ctx
}
