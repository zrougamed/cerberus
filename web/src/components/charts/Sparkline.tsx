import { useEffect, useRef, useState } from 'react'
import { Line } from 'react-chartjs-2'
import { chartColors, lineColor, textSoft } from './register'
import './register'

/** Rolling total-packets sparkline from live summary polls. */
export function TrafficSparkline({ total }: { total: number }) {
  const [series, setSeries] = useState<number[]>([])
  const last = useRef<number | null>(null)

  useEffect(() => {
    if (last.current === null) {
      last.current = total
      setSeries([0])
      return
    }
    const delta = Math.max(0, total - last.current)
    last.current = total
    setSeries((s) => [...s.slice(-29), delta])
  }, [total])

  const color = chartColors()[0]

  return (
    <div className="h-40">
      <Line
        aria-label="Packets per refresh"
        data={{
          labels: series.map((_, i) => `${i}`),
          datasets: [
            {
              data: series,
              borderColor: color,
              backgroundColor: `${color}33`,
              fill: true,
              tension: 0.35,
              pointRadius: 0,
              borderWidth: 2,
            },
          ],
        }}
        options={{
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false }, tooltip: { enabled: true } },
          scales: {
            x: { display: false },
            y: {
              beginAtZero: true,
              ticks: { color: textSoft(), font: { size: 10, family: 'IBM Plex Mono, monospace' } },
              grid: { color: lineColor() },
              border: { display: false },
            },
          },
        }}
      />
    </div>
  )
}
