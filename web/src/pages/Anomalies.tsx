import { useLive } from '../lib/live'

export function AnomaliesPage() {
  const { anomalies } = useLive()
  if (!anomalies) return <p className="muted">Loading…</p>

  const alerts = anomalies.recent_alerts || []
  const contrib = anomalies.last_contributions || []
  const features = anomalies.last_features

  return (
    <div className="grid gap-4">
      <section className="panel">
        <p className="muted m-0 text-sm">{anomalies.status || 'Anomaly model'}</p>
        <p className="mt-2 text-sm">{String(anomalies.last_summary || '')}</p>
        {anomalies.last_summary_detail ? (
          <p className="muted mt-1 text-xs">{String(anomalies.last_summary_detail)}</p>
        ) : null}
        <div className="mt-3 grid grid-cols-2 gap-0 overflow-hidden rounded border border-[var(--line)] bg-[var(--surface-muted)] sm:grid-cols-3">
          {[
            ['Score', anomalies.current_score],
            ['Robust Z', anomalies.robust_z_score],
            ['Centroid', anomalies.centroid_distance],
            ['Packet/s', features?.packet_rate],
            ['Entropy', features?.port_entropy],
            ['Unusual ports', features?.unusual_port_count],
            ['DNS/s', features?.dns_rate],
            ['HTTP/s', features?.http_rate],
            ['TLS/s', features?.tls_rate],
          ].map(([label, value]) => (
            <article key={String(label)} className="border-b border-r border-[var(--line)] p-3">
              <div className="font-mono text-xs font-semibold text-[var(--text-soft)]">{label}</div>
              <div className="font-mono text-xl font-semibold tabular-nums">
                {typeof value === 'number' ? value.toFixed(2) : String(value ?? '—')}
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
                <th className="px-2 py-2">Robust Z</th>
              </tr>
            </thead>
            <tbody>
              {contrib.map((c, i) => (
                <tr key={i} className="border-b border-[var(--line)]">
                  <td className="px-2 py-2 font-mono">{String(c.label || c.feature || '—')}</td>
                  <td className="px-2 py-2 font-mono tabular-nums">{c.value != null ? c.value.toFixed(2) : '—'}</td>
                  <td className="px-2 py-2 font-mono tabular-nums">
                    {c.baseline_median != null ? c.baseline_median.toFixed(2) : '—'}
                  </td>
                  <td className="px-2 py-2 font-mono tabular-nums">{c.robust_z != null ? c.robust_z.toFixed(2) : '—'}</td>
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
                    {a.observed_at ? new Date(String(a.observed_at)).toLocaleString() : '—'} ·{' '}
                    <strong>{String(a.severity || 'info')}</strong>
                  </span>
                  <span className="badge">{String(a.score ?? '')}</span>
                </div>
                <p className="m-0 text-sm">{String(a.summary || '')}</p>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  )
}
