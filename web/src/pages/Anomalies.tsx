import { useLive } from '../lib/live'

export function AnomaliesPage() {
  const { anomalies } = useLive()
  if (!anomalies) return <p className="muted">Loading…</p>

  const alerts = anomalies.alerts || []
  const contrib = anomalies.last_contributors || []

  return (
    <div className="grid gap-4">
      <section className="panel">
        <p className="muted m-0 text-sm">{anomalies.status || 'Anomaly model'}</p>
        <p className="mt-2 text-sm">{String(anomalies.insight_plain || anomalies.insight || '')}</p>
        <div className="mt-3 grid grid-cols-2 gap-0 overflow-hidden rounded border border-[var(--line)] bg-[var(--surface-muted)] sm:grid-cols-3">
          {[
            ['Score', anomalies.score],
            ['Robust Z', anomalies.robust_z],
            ['Centroid', anomalies.centroid_distance],
            ['Packet/s', anomalies.packets_per_sec],
            ['Entropy', anomalies.entropy],
            ['Unusual ports', anomalies.unusual_ports],
          ].map(([label, value]) => (
            <article key={String(label)} className="border-b border-r border-[var(--line)] p-3">
              <div className="font-mono text-xs font-semibold text-[var(--text-soft)]">{label}</div>
              <div className="font-mono text-xl font-semibold tabular-nums">
                {typeof value === 'number' ? value.toFixed(2) : String(value ?? '0')}
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="panel overflow-x-auto">
        <h2 className="m-0 mb-3 font-[family-name:var(--font-display)] text-lg font-bold">Contributors (last window)</h2>
        {contrib.length === 0 ? (
          <p className="muted text-sm">No contributor data yet.</p>
        ) : (
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-[var(--line)] text-left text-[var(--text-soft)]">
                <th className="px-2 py-2">Feature</th>
                <th className="px-2 py-2">Value</th>
                <th className="px-2 py-2">Baseline</th>
                <th className="px-2 py-2">σ</th>
              </tr>
            </thead>
            <tbody>
              {contrib.map((c, i) => (
                <tr key={i} className="border-b border-[var(--line)]">
                  <td className="px-2 py-2 font-mono">{String(c.feature || c.name || '—')}</td>
                  <td className="px-2 py-2 font-mono tabular-nums">{String(c.value ?? '—')}</td>
                  <td className="px-2 py-2 font-mono tabular-nums">{String(c.baseline ?? c.median ?? '—')}</td>
                  <td className="px-2 py-2 font-mono tabular-nums">{String(c.sigma ?? c.robust_sigma ?? '—')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="panel">
        <h2 className="m-0 mb-3 font-[family-name:var(--font-display)] text-lg font-bold">All anomaly events</h2>
        {alerts.length === 0 ? (
          <p className="muted text-sm">No anomalies yet.</p>
        ) : (
          <ul className="m-0 grid list-none gap-2 p-0">
            {alerts.map((a, i) => (
              <li key={i} className="rounded border border-[var(--line)] border-l-[3px] bg-[var(--surface-muted)] p-3">
                <div className="mb-1 flex justify-between gap-2">
                  <span className="font-mono text-sm text-[var(--text-soft)]">
                    {a.time ? new Date(String(a.time)).toLocaleString() : '—'} · <strong>{String(a.severity || 'info')}</strong>
                  </span>
                  <span className="badge">{String(a.score ?? '')}</span>
                </div>
                <p className="m-0 text-sm">{String(a.summary || a.message || a.insight_plain || '')}</p>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  )
}
