import { useEffect, useState } from 'react'
import { fetchAssetAdvisories } from '../lib/api'
import { cn } from '../lib/cn'
import { SEVERITY_CLASS } from '../lib/severity'
import type { AdvisoryMatch } from '../lib/types'

/** Published advisories that match one device's reported identity. */
export function AdvisoryPanel({ mac }: { mac: string }) {
  const [matches, setMatches] = useState<AdvisoryMatch[] | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    fetchAssetAdvisories(mac)
      .then((m) => {
        if (!cancelled) setMatches(m)
      })
      .catch(() => {
        if (!cancelled) setError('Advisories could not be loaded.')
      })
    return () => {
      cancelled = true
    }
  }, [mac])

  if (error) return <p className="m-0 text-sm text-[var(--danger)]">{error}</p>
  if (!matches || matches.length === 0) return null
  return (
    <section className="panel grid gap-3" aria-labelledby="advisory-heading">
      <h2 id="advisory-heading" className="m-0 font-[family-name:var(--font-display)] text-lg font-bold">
        Published advisories ({matches.length})
      </h2>
      <ul className="m-0 grid list-none gap-3 p-0">
        {matches.map((m) => (
          <li key={m.id} className="grid gap-1 border-t border-[var(--line)] pt-3 first:border-t-0 first:pt-0">
            <div className="flex flex-wrap items-baseline gap-2">
              <span className={cn('rounded border px-2 py-0.5 text-xs font-bold uppercase', SEVERITY_CLASS[m.severity])}>
                {m.severity} {m.score ? m.score.toFixed(1) : ''}
              </span>
              {m.url ? (
                <a className="font-mono text-sm font-bold text-[var(--accent)]" href={m.url} target="_blank" rel="noopener noreferrer">
                  {m.id}
                </a>
              ) : (
                <span className="font-mono text-sm font-bold">{m.id}</span>
              )}
              <span className="font-semibold">{m.title}</span>
            </div>
            <p className="muted m-0 text-sm">
              Matched “{m.product}”{m.affected ? `, affected versions ${m.affected}` : ', all versions'}.{' '}
              {m.confidence === 'affected version'
                ? 'The reported firmware is in the affected range.'
                : 'The firmware is unknown or not comparable: check the version on the device.'}
              {m.cves && m.cves.length ? ` ${m.cves.length} CVE${m.cves.length === 1 ? '' : 's'}.` : ''}
            </p>
          </li>
        ))}
      </ul>
    </section>
  )
}
