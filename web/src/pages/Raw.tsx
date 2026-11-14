import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { fetchRaw } from '../lib/api'

const ENDPOINTS = ['summary', 'devices', 'alerts', 'anomalies', 'policy', 'policylog'] as const

export function RawPage() {
  const { endpoint = 'summary' } = useParams()
  const navigate = useNavigate()
  const [body, setBody] = useState('Loading…')
  const ep = ENDPOINTS.includes(endpoint as (typeof ENDPOINTS)[number]) ? endpoint : 'summary'

  async function load(value: string) {
    setBody('Loading…')
    try {
      setBody(await fetchRaw(value))
    } catch (e) {
      setBody(e instanceof Error ? e.message : 'Failed to load')
    }
  }

  useEffect(() => {
    void load(ep)
  }, [ep])

  return (
    <section className="panel">
      <p className="muted mb-3 text-sm">Read-only view of JSON returned by the REST API.</p>
      <div className="mb-3 flex flex-wrap items-end gap-3">
        <label className="grid gap-1 text-sm font-semibold text-[var(--text-soft)]">
          Endpoint
          <select
            className="min-h-11 min-w-[220px] rounded border border-[var(--line)] bg-[var(--surface)] px-2.5 text-[var(--text)]"
            value={ep}
            onChange={(e) => navigate(`/raw/${e.target.value}`)}
          >
            {ENDPOINTS.map((v) => (
              <option key={v} value={v}>
                GET /api/v1/{v === 'policylog' ? 'policy/log' : v}
              </option>
            ))}
          </select>
        </label>
        <button type="button" className="btn" onClick={() => void load(ep)}>
          Refresh
        </button>
      </div>
      <pre
        tabIndex={0}
        className="m-0 max-h-[min(70vh,720px)] overflow-auto whitespace-pre-wrap break-words rounded border border-[var(--line)] bg-[var(--surface-muted)] p-3.5 font-mono text-xs leading-relaxed"
      >
        {body}
      </pre>
    </section>
  )
}
