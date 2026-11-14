import { BarRankChart } from '../components/charts/BarRankChart'
import { TrafficDoughnut } from '../components/charts/TrafficDoughnut'
import { useLive } from '../lib/live'
import { sumRecord } from '../lib/types'

export function AnalyticsPage() {
  const { summary, anomalies } = useLive()
  const features = anomalies?.last_features

  const kpiRow: Array<[string, string | number]> = [
    ['Devices', summary?.device_count ?? 0],
    ['Services', Object.keys(summary?.top_services || {}).length],
    ['Vendors', Object.keys(summary?.top_vendors || {}).length],
    ['DNS domains', sumRecord(summary?.dns_response_domains)],
    ['TLS SNIs', sumRecord(summary?.top_tls_snis)],
    ['Correlated DNS', sumRecord(summary?.dns_correlated_domains)],
    ['Encrypted DNS', sumRecord(summary?.encrypted_dns)],
    ['Packet/s', features?.packet_rate != null ? features.packet_rate.toFixed(1) : '—'],
  ]

  return (
    <div className="grid gap-4">
      <p className="muted m-0 text-sm">Protocol mix, vendors, DNS, TLS, and live anomaly features.</p>

      <section className="panel">
        <h2 className="mb-3 font-[family-name:var(--font-display)] text-lg font-bold">Fleet KPIs</h2>
        <div className="grid gap-0 overflow-hidden rounded border border-[var(--line)] bg-[var(--surface-muted)] sm:grid-cols-4 grid-cols-2">
          {kpiRow.map(([label, value]) => (
            <article key={label} className="border-b border-r border-[var(--line)] p-3">
              <div className="font-mono text-xs font-semibold text-[var(--text-soft)]">{label}</div>
              <div className="mt-1 font-mono text-xl font-semibold tabular-nums">{value}</div>
            </article>
          ))}
        </div>
      </section>

      <div className="grid gap-4 lg:grid-cols-2">
        <section className="panel">
          <h2 className="mb-3 font-[family-name:var(--font-display)] text-lg font-bold">Protocol mix</h2>
          <TrafficDoughnut stats={summary?.packet_stats} />
        </section>
        <section className="panel">
          <h2 className="mb-3 font-[family-name:var(--font-display)] text-lg font-bold">Top services</h2>
          <BarRankChart title="Services" values={summary?.top_services} />
        </section>
        <section className="panel">
          <h2 className="mb-3 font-[family-name:var(--font-display)] text-lg font-bold">Top vendors</h2>
          <BarRankChart title="Vendors" values={summary?.top_vendors} />
        </section>
        <section className="panel">
          <h2 className="mb-3 font-[family-name:var(--font-display)] text-lg font-bold">DNS query types</h2>
          <BarRankChart title="DNS types" values={summary?.dns_query_types} />
        </section>
        <section className="panel">
          <h2 className="mb-3 font-[family-name:var(--font-display)] text-lg font-bold">DNS response codes</h2>
          <BarRankChart title="DNS codes" values={summary?.dns_response_codes} />
        </section>
        <section className="panel">
          <h2 className="mb-3 font-[family-name:var(--font-display)] text-lg font-bold">DNS response domains</h2>
          <BarRankChart title="DNS domains" values={summary?.dns_response_domains} />
        </section>
        <section className="panel">
          <h2 className="mb-3 font-[family-name:var(--font-display)] text-lg font-bold">TLS versions</h2>
          <BarRankChart title="TLS versions" values={summary?.tls_versions} />
        </section>
        <section className="panel">
          <h2 className="mb-3 font-[family-name:var(--font-display)] text-lg font-bold">Top TLS SNIs</h2>
          <BarRankChart title="SNI" values={summary?.top_tls_snis} />
        </section>
        <section className="panel">
          <h2 className="mb-3 font-[family-name:var(--font-display)] text-lg font-bold">Encrypted DNS</h2>
          <BarRankChart title="Encrypted DNS" values={summary?.encrypted_dns} />
        </section>
        <section className="panel">
          <h2 className="mb-3 font-[family-name:var(--font-display)] text-lg font-bold">Correlated domains</h2>
          <BarRankChart title="Correlated" values={summary?.dns_correlated_domains} />
        </section>
      </div>
    </div>
  )
}
