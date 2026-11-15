import { Link } from 'react-router-dom'
import { useLive } from '../lib/live'

export function AlertsPage() {
  const { alerts } = useLive()

  if (!alerts) return <p className="muted">Loading…</p>
  if (!alerts.length) return <section className="panel"><p className="muted m-0">No rule alerts yet.</p></section>

  return (
    <section className="panel overflow-x-auto">
      <p className="muted mb-3 text-sm">Rule alerts from the monitor: volume thresholds, infrastructure baselines, watchlists and industrial protocol operations.</p>
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-[var(--line)] text-left text-[var(--text-soft)]">
            <th className="px-2 py-2">Time</th>
            <th className="px-2 py-2">Severity</th>
            <th className="px-2 py-2">Rule</th>
            <th className="px-2 py-2">Device</th>
            <th className="px-2 py-2">Message</th>
            <th className="px-2 py-2">ATT&amp;CK for ICS</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((a, i) => (
            <tr key={i} className="border-b border-[var(--line)]">
              <td className="px-2 py-2 font-mono text-[var(--text-soft)]">
                {a.observed_at || a.time ? new Date(String(a.observed_at || a.time)).toLocaleString() : '—'}
              </td>
              <td className="px-2 py-2"><span className="badge">{String(a.severity || 'info')}</span></td>
              <td className="px-2 py-2 font-mono">{String(a.rule || a.rule_id || '—')}</td>
              <td className="px-2 py-2 font-mono">{String(a.device_ip || a.device_mac || '—')}</td>
              <td className="px-2 py-2 [overflow-wrap:anywhere]">
                {String(a.message || '')}
                {a.capture_id ? (
                  <Link className="ml-2 whitespace-nowrap text-sm font-bold text-[var(--accent)]" to="/captures">
                    Packet capture
                  </Link>
                ) : null}
              </td>
              <td className="px-2 py-2">
                {a.techniques && a.techniques.length ? (
                  <ul className="m-0 flex list-none flex-col gap-1 p-0">
                    {a.techniques.map((t) => (
                      <li key={t.id}>
                        <a
                          className="whitespace-nowrap font-mono text-xs font-bold text-[var(--accent)]"
                          href={`https://attack.mitre.org/techniques/${t.id}/`}
                          target="_blank"
                          rel="noopener noreferrer"
                          title={t.name}
                        >
                          {t.id}
                        </a>{' '}
                        <span className="text-xs">{t.name}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <span className="muted">—</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}
