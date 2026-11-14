import { Link, useParams } from 'react-router-dom'
import { useLive } from '../lib/live'

export function DeviceDetailPage() {
  const { mac = '' } = useParams()
  const decoded = decodeURIComponent(mac)
  const { devices } = useLive()
  const device = (devices || []).find((d) => d.mac === decoded)

  if (!devices) return <p className="muted">Loading…</p>
  if (!device) {
    return (
      <section className="panel">
        <p className="breadcrumb mb-3">
          <Link to="/devices" className="font-bold text-[var(--accent)] no-underline">
            All devices
          </Link>
        </p>
        <p className="muted">Device {decoded} was not found in the current inventory.</p>
      </section>
    )
  }

  const entries = Object.entries(device).filter(([, v]) => v !== null && v !== undefined && typeof v !== 'object')

  return (
    <div className="grid gap-3">
      <p className="m-0">
        <Link to="/devices" className="font-bold text-[var(--accent)] no-underline">
          All devices
        </Link>
      </p>
      <section className="panel">
        <h2 className="m-0 font-[family-name:var(--font-display)] text-xl font-bold">
          {device.ip} · {device.vendor || 'Unknown'}
        </h2>
        <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {entries.map(([k, v]) => (
            <div key={k} className="rounded border border-[var(--line)] border-l-[3px] border-l-[var(--accent)] bg-[var(--surface-muted)] p-3">
              <div className="font-mono text-xs text-[var(--text-soft)]">{k}</div>
              <div className="font-mono text-base font-bold">{String(v)}</div>
            </div>
          ))}
        </div>
        <p className="mt-4">
          <Link className="font-bold text-[var(--danger)] no-underline" to={`/policy`}>
            Open policy
          </Link>
        </p>
      </section>
    </div>
  )
}
