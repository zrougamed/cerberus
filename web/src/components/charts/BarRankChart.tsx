import { Bar } from 'react-chartjs-2'
import { chartColors, lineColor, textSoft } from './register'
import './register'

export function BarRankChart({
  values,
  title,
}: {
  values?: Record<string, number>
  title: string
}) {
  const entries = Object.entries(values || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
  const colors = chartColors()

  if (!entries.length) {
    return <p className="muted text-sm">No data yet.</p>
  }

  return (
    <div className="h-56">
      <Bar
        aria-label={title}
        data={{
          labels: entries.map(([k]) => k),
          datasets: [
            {
              label: title,
              data: entries.map(([, v]) => v),
              backgroundColor: entries.map((_, i) => colors[i % colors.length]),
              borderRadius: 4,
              barThickness: 18,
            },
          ],
        }}
        options={{
          indexAxis: 'y',
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: { enabled: true },
          },
          scales: {
            x: {
              ticks: { color: textSoft(), font: { family: 'IBM Plex Mono, monospace', size: 11 } },
              grid: { color: lineColor() },
              border: { display: false },
            },
            y: {
              ticks: { color: textSoft(), font: { size: 12 } },
              grid: { display: false },
              border: { display: false },
            },
          },
        }}
      />
    </div>
  )
}
