import { useLive } from '../lib/live'

export function AlertsPage() {
  const { alerts } = useLive()

  if (!alerts) return <p className="muted">Loading…</p>
  if (!alerts.length) return <section className="panel"><p className="muted m-0">No rule alerts yet.</p></section>

  return (
    <section className="panel overflow-x-auto">
      <p className="muted mb-3 text-sm">Threshold alerts from the monitor (DNS volume, TCP volume, target spread).</p>
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-[var(--line)] text-left text-[var(--text-soft)]">
            <th className="px-2 py-2">Time</th>
            <th className="px-2 py-2">Severity</th>
            <th className="px-2 py-2">Rule</th>
            <th className="px-2 py-2">Device</th>
            <th className="px-2 py-2">Message</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((a, i) => (
            <tr key={i} className="border-b border-[var(--line)]">
              <td className="px-2 py-2 font-mono text-[var(--text-soft)]">
                {a.time ? new Date(String(a.time)).toLocaleString() : '—'}
              </td>
              <td className="px-2 py-2"><span className="badge">{String(a.severity || 'info')}</span></td>
              <td className="px-2 py-2 font-mono">{String(a.rule_id || '—')}</td>
              <td className="px-2 py-2 font-mono">{String(a.device_ip || a.device_mac || '—')}</td>
              <td className="px-2 py-2">{String(a.message || '')}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}
