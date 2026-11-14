import {
  ArcElement,
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  Filler,
  Legend,
  LinearScale,
  LineElement,
  PointElement,
  Tooltip,
} from 'chart.js'

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  LineElement,
  PointElement,
  ArcElement,
  Tooltip,
  Legend,
  Filler,
)

export function chartColors() {
  const styles = getComputedStyle(document.documentElement)
  return [1, 2, 3, 4, 5].map((n) => styles.getPropertyValue(`--chart-${n}`).trim() || '#1a2740')
}

export function textSoft() {
  return getComputedStyle(document.documentElement).getPropertyValue('--text-soft').trim() || '#5a6675'
}

export function lineColor() {
  return getComputedStyle(document.documentElement).getPropertyValue('--line').trim() || '#c5d0dc'
}
