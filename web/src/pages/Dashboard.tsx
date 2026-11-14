import { Link } from 'react-router-dom'
import { TrafficDoughnut } from '../components/charts/TrafficDoughnut'
import { TrafficSparkline } from '../components/charts/Sparkline'
import { useLive } from '../lib/live'

const PACKET_LABELS: Array<[string, string]> = [
  ['total', 'Total'],
  ['arp', 'ARP'],
  ['tcp', 'TCP'],
  ['udp', 'UDP'],
  ['icmp', 'ICMP'],
  ['dns', 'DNS'],
  ['http', 'HTTP'],
  ['tls', 'TLS'],
]

export function DashboardPage() {
  const { summary, anomalies } = useLive()
  const stats = summary?.packet_stats || {}
  const generated = summary?.generated_at
    ? `Last refresh: ${new Date(summary.generated_at).toLocaleTimeString()}`
    : 'Waiting for telemetry…'

  return (
    <div className="grid gap-4">
      <p className="muted m-0 text-sm">{generated}</p>

      <section className="panel">
        <header className="mb-3 flex items-baseline justify-between gap-3">
          <h2 className="m-0 font-[family-name:var(--font-display)] text-lg font-bold">Traffic</h2>
        </header>
        <div className="grid gap-0 overflow-hidden rounded border border-[var(--line)] bg-[var(--surface-muted)] sm:grid-cols-4 grid-cols-2">
          {PACKET_LABELS.map(([key, label]) => (
            <article key={key} className="border-b border-r border-[var(--line)] p-3">
              <div className="font-mono text-xs font-semibold text-[var(--text-soft)]">{label}</div>
              <div className="mt-1 font-mono text-2xl font-semibold tabular-nums">{stats[key] || 0}</div>
            </article>
          ))}
          <article className="border-b border-r border-[var(--line)] p-3">
            <div className="font-mono text-xs font-semibold text-[var(--text-soft)]">Devices</div>
            <div className="mt-1 font-mono text-2xl font-semibold tabular-nums">{summary?.device_count ?? 0}</div>
          </article>
        </div>
      </section>

      <div className="grid gap-4 lg:grid-cols-2">
        <section className="panel">
          <h2 className="mb-3 font-[family-name:var(--font-display)] text-lg font-bold">Protocol mix</h2>
          <TrafficDoughnut stats={stats} />
        </section>
        <section className="panel">
          <h2 className="mb-3 font-[family-name:var(--font-display)] text-lg font-bold">Packets per refresh</h2>
          <TrafficSparkline total={Number(stats.total || 0)} />
        </section>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <section className="panel">
          <header className="mb-3 flex items-baseline justify-between gap-3">
            <h2 className="m-0 font-[family-name:var(--font-display)] text-lg font-bold">Recent devices</h2>
            <Link className="text-sm font-bold text-[var(--accent)] no-underline hover:underline" to="/devices">
              All devices
            </Link>
          </header>
          <div className="grid gap-2">
            {(summary?.recent_devices || []).length === 0 ? (
              <p className="muted text-sm">No devices observed yet.</p>
            ) : (
              (summary?.recent_devices || []).map((d) => (
                <article key={d.mac} className="rounded border border-[var(--line)] bg-[var(--surface-muted)] p-3">
                  <strong className="block">
                    <Link className="text-[var(--accent)] no-underline hover:underline" to={`/device/${encodeURIComponent(d.mac)}`}>
                      {d.ip} · {d.vendor || 'Unknown'}
                    </Link>
                    {d.is_gateway ? <span className="badge ml-2">GW</span> : null}
                  </strong>
                  <div className="mt-1 flex justify-between gap-2 font-mono text-sm text-[var(--text-soft)]">
                    <span>MAC {d.mac}</span>
                    <span>DNS {d.dns_queries || 0}</span>
                  </div>
                  <div className="flex justify-between gap-2 font-mono text-sm text-[var(--text-soft)]">
                    <span>HTTP {d.http_requests || 0}</span>
                    <span>TLS {d.tls || 0}</span>
                  </div>
                </article>
              ))
            )}
          </div>
        </section>

        <section className="panel">
          <header className="mb-3 flex items-baseline justify-between gap-3">
            <h2 className="m-0 font-[family-name:var(--font-display)] text-lg font-bold">Anomaly status</h2>
            <Link className="text-sm font-bold text-[var(--accent)] no-underline hover:underline" to="/anomalies">
              Full history
            </Link>
          </header>
          <p className="muted m-0 text-sm">
            {anomalies?.insight_plain || anomalies?.insight || anomalies?.status || 'Model warming up…'}
          </p>
          <div className="mt-3 grid grid-cols-3 gap-0 overflow-hidden rounded border border-[var(--line)] bg-[var(--surface-muted)]">
            {[
              ['Score', anomalies?.score],
              ['Robust Z', anomalies?.robust_z],
              ['Centroid', anomalies?.centroid_distance],
              ['Packet/s', anomalies?.packets_per_sec],
              ['Entropy', anomalies?.entropy],
              ['Unusual ports', anomalies?.unusual_ports],
            ].map(([label, value]) => (
              <article key={String(label)} className="border-b border-r border-[var(--line)] p-2.5">
                <div className="font-mono text-[0.7rem] font-semibold text-[var(--text-soft)]">{label}</div>
                <div className="font-mono text-lg font-semibold tabular-nums">
                  {typeof value === 'number' ? value.toFixed(2) : value ?? '0'}
                </div>
              </article>
            ))}
          </div>
        </section>
      </div>
    </div>
  )
}
