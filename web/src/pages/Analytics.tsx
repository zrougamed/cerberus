import { BarRankChart } from '../components/charts/BarRankChart'
import { TrafficDoughnut } from '../components/charts/TrafficDoughnut'
import { useLive } from '../lib/live'

export function AnalyticsPage() {
  const { summary } = useLive()

  return (
    <div className="grid gap-4">
      <p className="muted m-0 text-sm">Protocol mix, vendors, and DNS from the live summary.</p>
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
        <section className="panel lg:col-span-2">
          <h2 className="mb-3 font-[family-name:var(--font-display)] text-lg font-bold">DNS response codes</h2>
          <BarRankChart title="DNS codes" values={summary?.dns_response_codes} />
        </section>
      </div>
    </div>
  )
}
