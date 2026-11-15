import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useLive } from '../lib/live'
import type { DeviceSummary } from '../lib/types'

type Col = 'mac' | 'ip' | 'vendor' | 'dns_queries' | 'http_requests' | 'tls' | 'last_seen'

export function DevicesPage() {
  const { devices } = useLive()
  const [sort, setSort] = useState<{ col: Col; dir: 1 | -1 }>({ col: 'last_seen', dir: -1 })

  const rows = useMemo(() => {
    const list = [...(devices || [])]
    const { col, dir } = sort
    list.sort((a, b) => {
      const av = (a[col] ?? '') as string | number
      const bv = (b[col] ?? '') as string | number
      if (av < bv) return -dir
      if (av > bv) return dir
      return String(a.mac).localeCompare(String(b.mac))
    })
    return list
  }, [devices, sort])

  function header(col: Col, label: string) {
    const active = sort.col === col
    return (
      <th className="cursor-pointer px-2 py-2 text-left text-sm font-bold text-[var(--text-soft)]" onClick={() => setSort((s) => ({ col, dir: s.col === col ? (s.dir === 1 ? -1 : 1) : -1 }))}>
        {label}
        {active ? (sort.dir === 1 ? ' ▲' : ' ▼') : ''}
      </th>
    )
  }

  if (!devices) return <p className="muted">Loading…</p>
  if (!devices.length) return <p className="muted">No devices yet.</p>

  return (
    <section className="panel overflow-x-auto" tabIndex={0} aria-label="Devices">
      <p className="muted mb-3 text-sm">Select a device for full telemetry captured for that MAC.</p>
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-[var(--line)]">
            {header('mac', 'MAC')}
            {header('ip', 'IP')}
            {header('vendor', 'Vendor')}
            {header('dns_queries', 'DNS')}
            {header('http_requests', 'HTTP')}
            {header('tls', 'TLS')}
            {header('last_seen', 'Last seen')}
          </tr>
        </thead>
        <tbody>
          {rows.map((d: DeviceSummary) => (
            <tr key={d.mac} className="border-b border-[var(--line)]">
              <td className="px-2 py-2 font-mono">
                <Link className="font-bold text-[var(--accent)] no-underline hover:underline" to={`/device/${encodeURIComponent(d.mac)}`}>
                  {d.mac}
                </Link>
              </td>
              <td className="px-2 py-2 font-mono">{d.ip}</td>
              <td className="px-2 py-2">{d.vendor || 'Unknown'}{d.is_gateway ? <span className="badge ml-2">GW</span> : null}</td>
              <td className="px-2 py-2 text-right font-mono tabular-nums">{d.dns_queries || 0}</td>
              <td className="px-2 py-2 text-right font-mono tabular-nums">{d.http_requests || 0}</td>
              <td className="px-2 py-2 text-right font-mono tabular-nums">{d.tls || d.tls_connections || 0}</td>
              <td className="px-2 py-2 font-mono text-[var(--text-soft)]">
                {d.last_seen ? new Date(d.last_seen).toLocaleString() : '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}
