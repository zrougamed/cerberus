import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { AccessNote } from '../components/AccessNote'
import { policyWrite } from '../lib/api'
import { useLive } from '../lib/live'
import { useCan } from '../lib/session'
import type { AlertEvent } from '../lib/types'

export function AlertsPage() {
  const { alerts, refresh } = useLive()
  const canAck = useCan('analyst')
  const [error, setError] = useState('')

  if (!alerts) return <p className="muted">Loading…</p>
  if (!alerts.length)
    return (
      <section className="panel">
        <p className="muted m-0">No rule alerts yet.</p>
      </section>
    )

  return (
    <div className="grid grid-cols-1 gap-3">
      {error ? (
        <p role="alert" className="m-0 rounded bg-[var(--danger-soft)] px-3 py-2 font-semibold text-[var(--danger)]">
          {error}
        </p>
      ) : null}
      <section className="panel overflow-x-auto" tabIndex={0} aria-label="Rule alerts">
        <div className="mb-3 grid gap-1">
          <p className="muted m-0 text-sm">
            Rule alerts from the monitor: volume thresholds, infrastructure baselines, watchlists and industrial protocol operations.
          </p>
          <AccessNote need="analyst" action="acknowledge alerts" />
        </div>
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-[var(--line)] text-left text-[var(--text-soft)]">
              <th className="px-2 py-2">Time</th>
              <th className="px-2 py-2">Severity</th>
              <th className="px-2 py-2">Rule</th>
              <th className="px-2 py-2">Device</th>
              <th className="px-2 py-2">Message</th>
              <th className="px-2 py-2">ATT&amp;CK for ICS</th>
              <th className="px-2 py-2">Status</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a, i) => (
              <tr key={a.id || i} className="border-b border-[var(--line)] align-top">
                <td className="px-2 py-2 font-mono text-[var(--text-soft)]">
                  {a.observed_at || a.time ? new Date(String(a.observed_at || a.time)).toLocaleString() : '—'}
                </td>
                <td className="px-2 py-2">
                  <span className="badge">{String(a.severity || 'info')}</span>
                </td>
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
                <td className="min-w-[12rem] px-2 py-2">
                  <AckCell alert={a} canAck={canAck} onDone={() => void refresh()} onError={setError} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  )
}

const MAX_NOTE = 500

/** Shows who acknowledged an alert, or lets an analyst do it with a note. */
function AckCell({
  alert,
  canAck,
  onDone,
  onError,
}: {
  alert: AlertEvent
  canAck: boolean
  onDone: () => void
  onError: (msg: string) => void
}) {
  const [open, setOpen] = useState(false)
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)

  if (alert.acked_by) {
    return (
      <div className="grid gap-0.5">
        <span className="font-semibold">Acknowledged by {alert.acked_by}</span>
        {alert.acked_at ? <span className="muted text-xs">{new Date(alert.acked_at).toLocaleString()}</span> : null}
        {alert.note ? <span className="text-xs [overflow-wrap:anywhere]">{alert.note}</span> : null}
      </div>
    )
  }
  if (!canAck || !alert.id) return <span className="muted">Open</span>
  if (!open) {
    return (
      <button type="button" className="btn" onClick={() => setOpen(true)}>
        Acknowledge
      </button>
    )
  }

  const noteId = `ack-note-${alert.id}`
  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    const res = await policyWrite('POST', `/api/v1/alerts/${encodeURIComponent(alert.id!)}/ack`, { note: note.trim() })
    setBusy(false)
    if (!res.ok) {
      onError(res.error)
      return
    }
    onError('')
    setOpen(false)
    onDone()
  }

  return (
    <form className="grid gap-1.5" onSubmit={(e) => void submit(e)}>
      <label htmlFor={noteId} className="text-xs font-bold">
        Note (optional)
      </label>
      <textarea id={noteId} className="input min-h-[4rem]" maxLength={MAX_NOTE} value={note} onChange={(e) => setNote(e.target.value)} />
      <div className="flex flex-wrap gap-2">
        <button className="btn btn-primary" type="submit" disabled={busy}>
          Save
        </button>
        <button type="button" className="btn" disabled={busy} onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
    </form>
  )
}
