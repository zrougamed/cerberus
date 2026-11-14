import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { fetchZones } from '../lib/api'
import { useLive } from '../lib/live'
import { cn } from '../lib/cn'
import type { ZoneInfo, ZoneSummary } from '../lib/types'

const REFRESH_MS = 10_000
const MAX_CHIPS = 12

// Purdue reference model level names.
const LEVELS: Record<number, string> = {
  5: 'Enterprise network',
  4: 'Business planning and logistics',
  3: 'Site operations',
  2: 'Supervisory control',
  1: 'Basic control',
  0: 'Process',
}

function ZoneCard({ zone, devices }: { zone: ZoneInfo; devices: { mac: string; ip: string }[] }) {
  return (
    <article
      aria-labelledby={`zone-${zone.id}`}
      className={cn(
        'min-w-0 flex-1 basis-64 rounded border bg-[var(--surface)] p-3',
        zone.industrial ? 'border-[var(--accent)] border-l-[4px]' : 'border-[var(--line)]',
      )}
    >
      <div className="flex flex-wrap items-baseline gap-2">
        <h3 id={`zone-${zone.id}`} className="m-0 text-base font-bold">
          {zone.name}
        </h3>
        <span className="muted font-mono text-xs">{zone.id}</span>
        {!zone.enforce ? <span className="badge ml-auto">Watch only</span> : null}
      </div>
      <p className="muted m-0 mt-1 font-mono text-xs [overflow-wrap:anywhere]">{zone.cidrs.join(', ')}</p>
      <p className="m-0 mt-2 text-sm">
        <strong className="font-mono">{zone.devices}</strong> device{zone.devices === 1 ? '' : 's'}
      </p>
      {devices.length > 0 ? (
        <ul className="m-0 mt-2 flex list-none flex-wrap gap-1 p-0 font-mono text-xs">
          {devices.slice(0, MAX_CHIPS).map((d) => (
            <li key={d.mac}>
              <Link className="block rounded bg-[var(--surface-muted)] px-2 py-0.5 text-[var(--text)] no-underline" to={`/device/${encodeURIComponent(d.mac)}`}>
                {d.ip}
              </Link>
            </li>
          ))}
          {devices.length > MAX_CHIPS ? <li className="muted px-1 py-0.5">and {devices.length - MAX_CHIPS} more</li> : null}
        </ul>
      ) : null}
    </article>
  )
}

export function ZonesPage() {
  const { devices, paused } = useLive()
  const [data, setData] = useState<ZoneSummary | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const next = await fetchZones()
        if (!cancelled) {
          setData(next)
          setError('')
        }
      } catch {
        if (!cancelled) setError('Zones could not be loaded. Check that Cerberus is running.')
      }
    }
    void load()
    const id = paused ? undefined : window.setInterval(() => void load(), REFRESH_MS)
    return () => {
      cancelled = true
      window.clearInterval(id)
    }
  }, [paused])

  if (!data && !error) return <p className="muted">Loading…</p>
  if (error) return <p className="m-0 rounded bg-[var(--danger-soft)] px-3 py-2 font-semibold text-[var(--danger)]">{error}</p>
  if (!data || data.zones.length === 0) {
    return (
      <section className="panel grid gap-2">
        <h2 className="m-0 font-[family-name:var(--font-display)] text-lg font-bold">No zones defined</h2>
        <p className="m-0">
          Add a <code>segmentation</code> section to the alerts config with your zones (networks and Purdue level) and the conduits between them.
          Cerberus then alerts on traffic that crosses a zone boundary without a conduit. See <code>docs/industrial-protocols.md</code>.
        </p>
      </section>
    )
  }

  const byZone = new Map<string, { mac: string; ip: string }[]>()
  for (const d of devices || []) {
    if (!d.zone) continue
    const list = byZone.get(d.zone) || []
    list.push({ mac: d.mac, ip: d.ip })
    byZone.set(d.zone, list)
  }
  const names = new Map(data.zones.map((z) => [z.id, z.name]))
  const levels = Array.from(new Set(data.zones.map((z) => z.level))).sort((a, b) => b - a)
  const violations = Object.entries(data.violations || {}).sort((a, b) => b[1] - a[1])

  return (
    <div className="grid gap-3">
      <section className="panel grid gap-0 p-0" aria-labelledby="zones-heading">
        <h2 id="zones-heading" className="sr-only">
          Zones by Purdue level
        </h2>
        {levels.map((level) => (
          <div key={level} className="grid gap-2 border-b border-[var(--line)] p-3 last:border-b-0 sm:grid-cols-[11rem_1fr]">
            <div>
              <div className="font-mono text-2xl font-bold leading-none">L{level}</div>
              <div className="muted text-xs">{LEVELS[level]}</div>
            </div>
            <div className="flex flex-wrap gap-2">
              {data.zones
                .filter((z) => z.level === level)
                .map((z) => (
                  <ZoneCard key={z.id} zone={z} devices={(byZone.get(z.id) || []).sort((a, b) => a.ip.localeCompare(b.ip))} />
                ))}
            </div>
          </div>
        ))}
      </section>

      <div className="grid gap-3 lg:grid-cols-2">
        <section className="panel overflow-x-auto">
          <h2 className="m-0 mb-2 font-[family-name:var(--font-display)] text-lg font-bold">Traffic without a conduit</h2>
          {violations.length === 0 ? (
            <p className="muted m-0">None so far. Every packet between two zones matched a conduit.</p>
          ) : (
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-[var(--line)] text-left text-[var(--text-soft)]">
                  <th className="px-2 py-2">From</th>
                  <th className="px-2 py-2">To</th>
                  <th className="px-2 py-2 text-right">Packets</th>
                </tr>
              </thead>
              <tbody>
                {violations.map(([pair, n]) => {
                  const [from, to] = pair.split('>')
                  return (
                    <tr key={pair} className="border-b border-[var(--line)]">
                      <td className="px-2 py-2">{names.get(from) || from}</td>
                      <td className="px-2 py-2">{names.get(to) || to}</td>
                      <td className="px-2 py-2 text-right font-mono font-bold text-[var(--danger)]">{n}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </section>

        <section className="panel overflow-x-auto">
          <h2 className="m-0 mb-2 font-[family-name:var(--font-display)] text-lg font-bold">Conduits</h2>
          {data.conduits.length === 0 ? (
            <p className="muted m-0">No conduits: any traffic between two zones raises an alert.</p>
          ) : (
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-[var(--line)] text-left text-[var(--text-soft)]">
                  <th className="px-2 py-2">From</th>
                  <th className="px-2 py-2">To</th>
                  <th className="px-2 py-2">Ports</th>
                  <th className="px-2 py-2">Direction</th>
                </tr>
              </thead>
              <tbody>
                {data.conduits.map((c, i) => (
                  <tr key={i} className="border-b border-[var(--line)]">
                    <td className="px-2 py-2">{names.get(c.from) || c.from}</td>
                    <td className="px-2 py-2">{names.get(c.to) || c.to}</td>
                    <td className="px-2 py-2 font-mono">{c.ports && c.ports.length ? c.ports.join(', ') : 'any'}</td>
                    <td className="px-2 py-2">{c.bidirectional ? 'Either side opens' : 'Only "from" opens'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </div>
    </div>
  )
}
