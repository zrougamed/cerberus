import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { downloadCapture, fetchCaptures, policyWrite } from '../lib/api'
import { useLive } from '../lib/live'
import { getToken } from '../lib/token'
import { cn } from '../lib/cn'
import type { CaptureState } from '../lib/types'
import { TokenUnlock } from '../components/TokenUnlock'

const REFRESH_MS = 10_000

function size(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

export function CapturesPage() {
  const { paused } = useLive()
  const [data, setData] = useState<CaptureState | null>(null)
  const [error, setError] = useState('')
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null)
  const [address, setAddress] = useState('')
  const [seconds, setSeconds] = useState('60')
  const [busy, setBusy] = useState(false)
  const [reloadKey, setReloadKey] = useState(0)
  const [, setTick] = useState(0)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const next = await fetchCaptures()
        if (!cancelled) {
          setData(next)
          setError('')
        }
      } catch {
        if (!cancelled) setError('Captures could not be loaded. Check that Cerberus is running.')
      }
    }
    void load()
    const id = paused ? undefined : window.setInterval(() => void load(), REFRESH_MS)
    return () => {
      cancelled = true
      window.clearInterval(id)
    }
  }, [paused, reloadKey])

  const unlocked = Boolean(getToken())

  async function captureNow(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    const res = await policyWrite('POST', '/api/v1/captures', { address: address.trim(), seconds: Number(seconds) })
    setBusy(false)
    setMsg(
      res.ok
        ? { kind: 'ok', text: `Saved ${res.data.packets} packets from the last ${seconds} seconds.` }
        : { kind: 'err', text: res.error },
    )
    setReloadKey((k) => k + 1)
  }

  async function download(id: string) {
    const err = await downloadCapture(id)
    if (err) setMsg({ kind: 'err', text: err })
  }

  async function remove(id: string) {
    const res = await policyWrite('DELETE', `/api/v1/captures/${encodeURIComponent(id)}`)
    setMsg(res.ok || res.status === 204 ? { kind: 'ok', text: 'Capture deleted.' } : { kind: 'err', text: res.error })
    setReloadKey((k) => k + 1)
  }

  if (!data && !error) return <p className="muted">Loading…</p>
  if (error) return <p className="m-0 rounded bg-[var(--danger-soft)] px-3 py-2 font-semibold text-[var(--danger)]">{error}</p>
  if (!data?.enabled) {
    return (
      <section className="panel grid gap-2">
        <h2 className="m-0 font-[family-name:var(--font-display)] text-lg font-bold">Packet capture is off</h2>
        <p className="m-0">
          To turn it on, set <code>capture.enabled: true</code> in the alerts config file (the file named by <code>CERBERUS_ALERTS_CONFIG</code>) and restart Cerberus.
          It then keeps the last two minutes of traffic in memory and saves a pcapng file for each high-severity alert.
        </p>
      </section>
    )
  }

  return (
    <div className="grid grid-cols-1 gap-3">
      <section className="panel grid gap-3">
        <p className="m-0">
          {data.interfaces.length ? (
            <>
              Recording on <strong>{data.interfaces.join(', ')}</strong>.
            </>
          ) : (
            'No capture interface is open.'
          )}{' '}
          The buffer holds {data.buffer_packets.toLocaleString()} packets ({size(data.buffer_bytes)})
          {data.buffer_oldest ? ` going back to ${new Date(data.buffer_oldest).toLocaleTimeString()}` : ''}.
          {data.pending > 0 ? ` ${data.pending} alert capture${data.pending === 1 ? ' is' : 's are'} waiting for follow-up traffic.` : ''}
        </p>
        <TokenUnlock id="captures-token" onChange={() => setTick((n) => n + 1)} />
      </section>

      <section className="panel grid gap-3">
        <h2 className="m-0 font-[family-name:var(--font-display)] text-lg font-bold">Save the buffer now</h2>
        <form className="grid items-end gap-3 sm:grid-cols-[1fr_10rem_auto]" onSubmit={(e) => void captureNow(e)}>
          <div className="field">
            <label htmlFor="cap-address">Device address (optional)</label>
            <input id="cap-address" placeholder="10.20.0.50" value={address} onChange={(e) => setAddress(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="cap-seconds">Last seconds</label>
            <input id="cap-seconds" type="number" min={1} required value={seconds} onChange={(e) => setSeconds(e.target.value)} />
          </div>
          <button className="btn btn-primary" type="submit" disabled={!unlocked || busy}>
            Save capture
          </button>
        </form>
        <p className="muted m-0 text-sm">Leave the address empty to save all traffic in the buffer.</p>
      </section>

      {msg ? (
        <p
          role="status"
          className={cn(
            'm-0 rounded px-3 py-2 font-semibold',
            msg.kind === 'ok' ? 'bg-[var(--accent-soft)] text-[var(--accent)]' : 'bg-[var(--danger-soft)] text-[var(--danger)]',
          )}
        >
          {msg.text}
        </p>
      ) : null}

      <section className="panel relative overflow-x-auto" tabIndex={0} aria-label="Saved captures">
        {data.captures.length === 0 ? (
          <p className="muted m-0">No captures yet. One is saved for each high-severity alert, or use the form above.</p>
        ) : (
          <table className="w-full border-collapse text-sm">
            <caption className="muted pb-2 text-left">Saved captures, newest first</caption>
            <thead>
              <tr className="border-b border-[var(--line)] text-left text-[var(--text-soft)]">
                <th className="px-2 py-2">Saved</th>
                <th className="px-2 py-2">Reason</th>
                <th className="px-2 py-2">Device</th>
                <th className="px-2 py-2">Window</th>
                <th className="px-2 py-2 text-right">Packets</th>
                <th className="px-2 py-2 text-right">Size</th>
                <th className="px-2 py-2">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {data.captures.map((c) => (
                <tr key={c.id} className="border-b border-[var(--line)]">
                  <td className="px-2 py-2 text-[var(--text-soft)]">{new Date(c.created_at).toLocaleString()}</td>
                  <td className="px-2 py-2">{c.reason === 'alert' ? <span className="font-mono">{c.rule}</span> : 'Manual'}</td>
                  <td className="px-2 py-2 font-mono">{c.address || 'All traffic'}</td>
                  <td className="px-2 py-2 whitespace-nowrap">
                    {new Date(c.from).toLocaleTimeString()} to {new Date(c.to).toLocaleTimeString()}
                  </td>
                  <td className="px-2 py-2 text-right font-mono">{c.packets}</td>
                  <td className="px-2 py-2 text-right font-mono">{size(c.bytes)}</td>
                  <td className="px-2 py-2">
                    <div className="flex justify-end gap-2">
                      <button type="button" className="btn" disabled={!unlocked} onClick={() => void download(c.id)}>
                        Download
                      </button>
                      <button type="button" className="btn btn-danger" disabled={!unlocked} onClick={() => void remove(c.id)}>
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {!unlocked && data.captures.length > 0 ? (
          <p className="muted m-0 mt-2 text-sm">Captures hold full packet contents. Unlock changes with the API token to download them.</p>
        ) : null}
      </section>
    </div>
  )
}
