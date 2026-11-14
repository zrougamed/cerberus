import { useEffect, useState } from 'react'
import { fetchBaseline, policyWrite } from '../lib/api'
import { useLive } from '../lib/live'
import { getToken } from '../lib/token'
import { cn } from '../lib/cn'
import { protocolNames } from '../lib/protocols'
import type { BaselineFlow, BaselineState } from '../lib/types'
import { TokenUnlock } from '../components/TokenUnlock'

const REFRESH_MS = 10_000

function FlowRow({
  f,
  selectable,
  selected,
  onToggle,
}: {
  f: BaselineFlow
  selectable: boolean
  selected?: boolean
  onToggle?: () => void
}) {
  return (
    <tr className="border-b border-[var(--line)]">
      {selectable ? (
        <td className="px-2 py-2">
          <input
            type="checkbox"
            aria-label={`Select ${f.client} to ${f.server} ${f.protocol} ${f.class}`}
            checked={selected}
            onChange={onToggle}
          />
        </td>
      ) : null}
      <td className="px-2 py-2 font-mono">{f.client}</td>
      <td className="px-2 py-2 font-mono">{f.server}</td>
      <td className="px-2 py-2">{protocolNames[f.protocol] || f.protocol}</td>
      <td className={cn('px-2 py-2 font-semibold', f.class !== 'read' && f.class !== 'other' && 'text-[var(--danger)]')}>{f.class}</td>
      <td className="px-2 py-2 font-mono">{f.count}</td>
      <td className="px-2 py-2 text-[var(--text-soft)]">{new Date(f.first_seen).toLocaleString()}</td>
      <td className="px-2 py-2 text-[var(--text-soft)]">{new Date(f.last_seen).toLocaleString()}</td>
    </tr>
  )
}

function FlowTable({ caption, flows, children }: { caption: string; flows: BaselineFlow[]; children: (f: BaselineFlow) => React.ReactNode }) {
  const selectable = caption.startsWith('New')
  return (
    <table className="w-full border-collapse text-sm">
      <caption className="muted pb-2 text-left">{caption}</caption>
      <thead>
        <tr className="border-b border-[var(--line)] text-left text-[var(--text-soft)]">
          {selectable ? <th className="px-2 py-2"><span className="sr-only">Select</span></th> : null}
          <th className="px-2 py-2">Client</th>
          <th className="px-2 py-2">Server</th>
          <th className="px-2 py-2">Protocol</th>
          <th className="px-2 py-2">Operation</th>
          <th className="px-2 py-2">Requests</th>
          <th className="px-2 py-2">First seen</th>
          <th className="px-2 py-2">Last seen</th>
        </tr>
      </thead>
      <tbody>{flows.map(children)}</tbody>
    </table>
  )
}

export function BaselinePage() {
  const { paused } = useLive()
  const [data, setData] = useState<BaselineState | null>(null)
  const [error, setError] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null)
  const [confirmRelearn, setConfirmRelearn] = useState(false)
  const [reloadKey, setReloadKey] = useState(0)
  const [, setTick] = useState(0)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const next = await fetchBaseline()
        if (!cancelled) {
          setData(next)
          setError('')
        }
      } catch {
        if (!cancelled) setError('The baseline could not be loaded. Check that Cerberus is running.')
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
  const flows = data?.flows || []
  const fresh = flows.filter((f) => f.status === 'new')
  const known = flows.filter((f) => f.status !== 'new')
  const status = data?.status

  async function act(path: string, ids: string[], done: (n: number) => string) {
    const res = await policyWrite('POST', path, { ids })
    if (res.ok) {
      const n = Object.values(res.data as Record<string, number>)[0] || 0
      setMsg({ kind: 'ok', text: done(n) })
      setSelected(new Set())
    } else {
      setMsg({ kind: 'err', text: res.error })
    }
    setReloadKey((k) => k + 1)
  }

  async function relearn() {
    setConfirmRelearn(false)
    const res = await policyWrite('POST', '/api/v1/baseline/relearn', {})
    setMsg(res.ok ? { kind: 'ok', text: 'All flows were dropped and learning started again.' } : { kind: 'err', text: res.error })
    setReloadKey((k) => k + 1)
  }

  function toggle(id: string) {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  if (!data && !error) return <p className="muted">Loading…</p>

  return (
    <div className="grid gap-3">
      <section className="panel grid gap-3">
        {status?.state === 'disabled' ? (
          <p className="m-0">The flow baseline is turned off. Set <code>flow_baseline.enabled: true</code> in the alerts config to use it.</p>
        ) : status ? (
          <>
            <p className="m-0 text-base">
              {status.state === 'learning' ? (
                <>
                  <strong>Learning</strong> until {new Date(status.learning_until!).toLocaleString()}. Every industrial flow seen until then is treated as normal.
                </>
              ) : (
                <>
                  <strong>Watching for new flows</strong> since {new Date(status.learning_until!).toLocaleString()}. A flow that was not seen while learning raises a <code>baseline_new_flow</code> alert.
                </>
              )}
            </p>
            <dl className="m-0 grid grid-cols-2 gap-2 text-sm sm:grid-cols-4">
              {[
                ['Learned', status.learned],
                ['Approved', status.approved],
                ['New, to review', status.new],
                ['Dropped (baseline full)', status.dropped],
              ].map(([k, v]) => (
                <div key={String(k)}>
                  <dt className="muted">{k}</dt>
                  <dd className="m-0 font-mono text-lg font-bold">{v}</dd>
                </div>
              ))}
            </dl>
          </>
        ) : null}
        <TokenUnlock id="baseline-token" onChange={() => setTick((n) => n + 1)} />
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
      {error ? <p className="m-0 rounded bg-[var(--danger-soft)] px-3 py-2 font-semibold text-[var(--danger)]">{error}</p> : null}

      {status && status.state !== 'disabled' ? (
        <>
          <section className="panel grid gap-3 overflow-x-auto">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="m-0 mr-auto font-[family-name:var(--font-display)] text-lg font-bold">New flows</h2>
              <button
                type="button"
                className="btn"
                disabled={!unlocked || selected.size === 0}
                onClick={() => void act('/api/v1/baseline/approve', [...selected], (n) => `${n} flow${n === 1 ? '' : 's'} approved.`)}
              >
                Approve selected
              </button>
              <button
                type="button"
                className="btn btn-danger"
                disabled={!unlocked || selected.size === 0}
                onClick={() => void act('/api/v1/baseline/forget', [...selected], (n) => `${n} flow${n === 1 ? '' : 's'} removed; they alert again if seen.`)}
              >
                Forget selected
              </button>
            </div>
            {fresh.length === 0 ? (
              <p className="muted m-0">
                {status.state === 'learning' ? 'Nothing to review while learning.' : 'No new flows. Everything seen matches the baseline.'}
              </p>
            ) : (
              <FlowTable caption={`New flows: ${fresh.length}`} flows={fresh}>
                {(f) => <FlowRow key={f.id} f={f} selectable selected={selected.has(f.id)} onToggle={() => toggle(f.id)} />}
              </FlowTable>
            )}
            {!unlocked && fresh.length > 0 ? <p className="muted m-0 text-sm">Unlock changes with the API token to approve or forget flows.</p> : null}
          </section>

          <section className="panel overflow-x-auto">
            <details>
              <summary className="cursor-pointer font-bold">Known flows ({known.length})</summary>
              <div className="mt-3">
                {known.length === 0 ? (
                  <p className="muted m-0">No flows recorded yet.</p>
                ) : (
                  <FlowTable caption="Learned and approved flows" flows={known}>
                    {(f) => <FlowRow key={f.id} f={f} selectable={false} />}
                  </FlowTable>
                )}
              </div>
            </details>
          </section>

          <section className="panel grid gap-2">
            <h2 className="m-0 font-[family-name:var(--font-display)] text-lg font-bold">Start over</h2>
            <p className="muted m-0 text-sm">Drops every flow and learns for the configured period again. Use it after a planned change to the network.</p>
            <div className="flex flex-wrap gap-2">
              {confirmRelearn ? (
                <>
                  <button type="button" className="btn btn-danger" onClick={() => void relearn()}>
                    Drop all flows and relearn
                  </button>
                  <button type="button" className="btn" onClick={() => setConfirmRelearn(false)}>
                    Keep the baseline
                  </button>
                </>
              ) : (
                <button type="button" className="btn" disabled={!unlocked} onClick={() => setConfirmRelearn(true)}>
                  Start learning again
                </button>
              )}
            </div>
          </section>
        </>
      ) : null}
    </div>
  )
}
