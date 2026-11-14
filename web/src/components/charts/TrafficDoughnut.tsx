import { Doughnut } from 'react-chartjs-2'
import type { PacketStats } from '../../lib/types'
import { chartColors, textSoft } from './register'
import './register'

const KEYS: Array<[keyof PacketStats | string, string]> = [
  ['tcp', 'TCP'],
  ['udp', 'UDP'],
  ['dns', 'DNS'],
  ['http', 'HTTP'],
  ['tls', 'TLS'],
  ['icmp', 'ICMP'],
  ['arp', 'ARP'],
]

export function TrafficDoughnut({ stats }: { stats?: PacketStats }) {
  const rows = KEYS.map(([k, label]) => ({ label, value: Number(stats?.[k as string] || 0) })).filter(
    (r) => r.value > 0,
  )
  const colors = chartColors()

  if (!rows.length) {
    return <p className="muted text-sm">Waiting for packet counters…</p>
  }

  return (
    <div className="mx-auto h-56 max-w-xs">
      <Doughnut
        aria-label="Traffic mix"
        data={{
          labels: rows.map((r) => r.label),
          datasets: [
            {
              data: rows.map((r) => r.value),
              backgroundColor: rows.map((_, i) => colors[i % colors.length]),
              borderWidth: 0,
              hoverOffset: 4,
            },
          ],
        }}
        options={{
          responsive: true,
          maintainAspectRatio: false,
          cutout: '62%',
          plugins: {
            legend: {
              position: 'bottom',
              labels: { color: textSoft(), boxWidth: 12, font: { size: 12 } },
            },
          },
        }}
      />
    </div>
  )
}
