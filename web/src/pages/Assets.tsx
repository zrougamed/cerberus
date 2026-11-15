import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Download } from 'lucide-react'
import { fetchAdvisoryStatus, fetchAssets, policyWrite } from '../lib/api'
import { useLive } from '../lib/live'
import { getToken } from '../lib/token'
import { cn } from '../lib/cn'
import type { AdvisoryStatus, AssetEntry } from '../lib/types'
import { SEVERITY_CLASS } from '../lib/severity'
import { TokenUnlock } from '../components/TokenUnlock'
import { protocolNames } from '../lib/protocols'

const ROLES: Record<string, string> = {
  controller: 'Controller',
  hmi: 'HMI',
  scada_server: 'SCADA server',
  engineering_workstation: 'Engineering workstation',
  gateway: 'Gateway',
  historian: 'Historian',
  other: 'Other',
}

const REFRESH_MS = 10_000

export function AssetsPage() {
  const { paused } = useLive()
  const [assets, setAssets] = useState<AssetEntry[] | null>(null)
  const [advisories, setAdvisories] = useState<AdvisoryStatus | null>(null)
  const [error, setError] = useState('')
  const [role, setRole] = useState('')
  const [protocol, setProtocol] = useState('')
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null)
  const [, setTick] = useState(0)
  const [reloadKey, setReloadKey] = useState(0)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const [next, adv] = await Promise.all([fetchAssets(), fetchAdvisoryStatus()])
        if (!cancelled) {
          setAssets(next)
          setAdvisories(adv)
          setError('')
        }
      } catch {
        if (!cancelled) setError('The asset list could not be loaded. Check that Cerberus is running.')
      }
    }
    void load()
    const id = paused ? undefined : window.setInterval(() => void load(), REFRESH_MS)
    return () => {
      cancelled = true
      window.clearInterval(id)
    }
  }, [paused, reloadKey])

  const protocols = useMemo(
    () => Array.from(new Set((assets || []).flatMap((a) => a.protocols))).sort(),
    [assets],
  )
  const rows = (assets || []).filter((a) => (!role || a.role === role) && (!protocol || a.protocols.includes(protocol)))
  const unlocked = Boolean(getToken())

  async function setOverride(a: AssetEntry, next: string) {
    const res = await policyWrite('PUT', `/api/v1/assets/${encodeURIComponent(a.mac)}/role`, { role: next })
    setMsg(
      res.ok
        ? { kind: 'ok', text: next ? `${a.ip} is now labelled ${ROLES[next]}.` : `${a.ip} is back to its inferred role.` }
        : { kind: 'err', text: res.error },
    )
    setReloadKey((n) => n + 1)
  }

  if (!assets && !error) return <p className="muted">Loading…</p>

  return (
    <div className="grid gap-3">
      <section className="panel grid gap-3">
        <div className="flex flex-wrap items-end gap-3">
          <div className="field min-w-[12rem]">
            <label htmlFor="asset-role">Role</label>
            <select id="asset-role" value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="">All roles</option>
              {Object.entries(ROLES).map(([v, l]) => (
                <option key={v} value={v}>
                  {l}
                </option>
              ))}
            </select>
          </div>
          <div className="field min-w-[12rem]">
            <label htmlFor="asset-protocol">Protocol</label>
            <select id="asset-protocol" value={protocol} onChange={(e) => setProtocol(e.target.value)}>
              <option value="">All protocols</option>
              {protocols.map((p) => (
                <option key={p} value={p}>
                  {protocolNames[p] || p}
                </option>
              ))}
            </select>
          </div>
          <a className="btn ml-auto no-underline" href="/api/v1/assets?format=csv" download>
            <Download size={16} aria-hidden="true" /> Download CSV
          </a>
        </div>
        {advisories ? (
          <p className={cn('m-0 text-sm', advisories.stale || advisories.error ? 'font-semibold text-[var(--danger)]' : 'muted')}>
            {advisories.loaded
              ? `Advisories: ${advisories.advisories.toLocaleString()} from ${advisories.source}, generated ${new Date(advisories.generated_at!).toLocaleDateString()}${
                  advisories.stale ? ` (${advisories.age_days} days old: regenerate the bundle with tools/advisorygen)` : ''
                }.`
              : advisories.error
                ? `The advisory bundle could not be loaded: ${advisories.error}`
                : 'No advisory bundle loaded. Build one with tools/advisorygen and point CERBERUS_ADVISORIES_FILE at it to see known vulnerabilities per device.'}
          </p>
        ) : null}
        <TokenUnlock id="assets-token" onChange={() => setTick((n) => n + 1)} />
      </section>

      {msg ? (
        <p
          role="status"
          className={cn(
            'm-0 rounded px-3 py-2 font-semibold',
            msg.kind === 'ok' ? 'bg-[var(--accent-soft)] text-[var(--accent)]' : 'bg-[var(--danger-soft)] text-[var(--danger)]',
          )}
        >
          {msg.text}
        </p>
      ) : null}
      {error ? <p className="m-0 rounded bg-[var(--danger-soft)] px-3 py-2 font-semibold text-[var(--danger)]">{error}</p> : null}

      <section className="panel overflow-x-auto" tabIndex={0} aria-label="Assets">
        {rows.length === 0 ? (
          <p className="muted m-0">
            {assets && assets.length
              ? 'No asset matches these filters.'
              : 'No industrial devices seen yet. Assets appear once Cerberus decodes Modbus, S7, DNP3, EtherNet/IP, BACnet, IEC 104, OPC UA or MQTT traffic.'}
          </p>
        ) : (
          <table className="w-full border-collapse text-sm">
            <caption className="muted pb-2 text-left">
              {rows.length} of {assets?.length} assets
            </caption>
            <thead>
              <tr className="border-b border-[var(--line)] text-left text-[var(--text-soft)]">
                <th className="px-2 py-2">Device</th>
                <th className="px-2 py-2">Role</th>
                <th className="px-2 py-2">Protocols</th>
                <th className="px-2 py-2">Vendor and model</th>
                <th className="px-2 py-2">Firmware</th>
                <th className="px-2 py-2">Advisories</th>
                <th className="px-2 py-2">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <tr key={a.mac} className="border-b border-[var(--line)] align-top">
                  <td className="px-2 py-2">
                    <Link className="font-mono font-bold text-[var(--accent)] no-underline" to={`/device/${encodeURIComponent(a.mac)}`}>
                      {a.ip}
                    </Link>
                    <div className="muted font-mono text-xs">{a.mac}</div>
                  </td>
                  <td className="px-2 py-2">
                    {unlocked ? (
                      <select
                        aria-label={`Role of ${a.ip}`}
                        className="min-h-[2.25rem] rounded border border-[var(--line)] bg-[var(--surface)] px-2 text-[var(--text)]"
                        value={a.role_source === 'override' ? a.role : ''}
                        onChange={(e) => void setOverride(a, e.target.value)}
                      >
                        <option value="">{a.role && a.role_source === 'inferred' ? `Inferred: ${ROLES[a.role]}` : 'Infer from traffic'}</option>
                        {Object.entries(ROLES).map(([v, l]) => (
                          <option key={v} value={v}>
                            {l}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <>
                        <span className="font-semibold">{ROLES[a.role] || 'Unknown'}</span>
                        {a.role_source ? <div className="muted text-xs">{a.role_source === 'override' ? 'Set by an operator' : 'Inferred from traffic'}</div> : null}
                      </>
                    )}
                  </td>
                  <td className="px-2 py-2">{a.protocols.map((p) => protocolNames[p] || p).join(', ') || '—'}</td>
                  <td className="px-2 py-2 [overflow-wrap:anywhere]">
                    {a.asset?.vendor || a.oui_vendor || '—'}
                    {a.asset?.model ? <div className="font-mono text-xs">{a.asset.model}</div> : null}
                  </td>
                  <td className="px-2 py-2 font-mono">{a.asset?.firmware || '—'}</td>
                  <td className="px-2 py-2">
                    {a.advisories > 0 ? (
                      <Link
                        to={`/device/${encodeURIComponent(a.mac)}`}
                        className={cn('inline-block rounded border px-2 py-0.5 text-xs font-bold no-underline', SEVERITY_CLASS[a.advisory_severity || 'medium'])}
                      >
                        {a.advisories}, {a.advisory_severity}
                      </Link>
                    ) : (
                      <span className="muted">{advisories?.loaded ? 'None known' : '—'}</span>
                    )}
                  </td>
                  <td className="px-2 py-2 text-[var(--text-soft)]">{new Date(a.last_seen).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  )
}
