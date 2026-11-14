import type { IndustrialStats } from '../lib/types'

const protocolNames: Record<string, string> = {
  modbus: 'Modbus/TCP',
  s7comm: 'S7comm',
  s7comm_plus: 'S7comm-plus',
  dnp3: 'DNP3',
}

// Operations that change what the controller does; shown in the danger colour.
const riskyClasses = new Set(['write', 'diagnostic', 'control', 'program'])

const classOrder = ['read', 'write', 'diagnostic', 'control', 'program', 'other']

function sortedEntries(values?: Record<string, number>): [string, number][] {
  return Object.entries(values || {}).sort((a, b) => b[1] - a[1])
}

const acronyms = new Set(['cotp', 'plc', 'cpu', 'fifo', 'ram', 'rom', 'pi'])

function humanize(name: string): string {
  const words = name.split('_').map((w) => (acronyms.has(w) ? w.toUpperCase() : w))
  const text = words.join(' ')
  return text.charAt(0).toUpperCase() + text.slice(1)
}

function ProtocolSection({ protocol, stats }: { protocol: string; stats: IndustrialStats }) {
  const ops = Object.entries(stats.operations || {}).sort(
    (a, b) => classOrder.indexOf(a[0]) - classOrder.indexOf(b[0]),
  )
  const functions = sortedEntries(stats.functions)
  const role =
    stats.requests > 0 && stats.responses === 0
      ? 'Sends requests (client)'
      : stats.responses > 0 && stats.requests === 0
        ? 'Answers requests (server)'
        : 'Sends and answers requests'

  return (
    <section aria-labelledby={`ind-${protocol}`} className="border-t border-[var(--line)] pt-3">
      <h3 id={`ind-${protocol}`} className="m-0 text-base font-bold">
        {protocolNames[protocol] || protocol}
      </h3>
      <p className="muted m-0 mt-1 text-sm">
        {role}
        {stats.last_seen ? `, last seen ${new Date(stats.last_seen).toLocaleString()}` : ''}
      </p>

      <dl className="mt-3 grid grid-cols-3 gap-2 text-sm sm:max-w-md">
        <div>
          <dt className="muted">Requests sent</dt>
          <dd className="m-0 font-mono text-lg font-bold">{stats.requests}</dd>
        </div>
        <div>
          <dt className="muted">Responses sent</dt>
          <dd className="m-0 font-mono text-lg font-bold">{stats.responses}</dd>
        </div>
        <div>
          <dt className="muted">Error replies</dt>
          <dd className="m-0 font-mono text-lg font-bold">{stats.exceptions}</dd>
        </div>
      </dl>

      {ops.length > 0 && (
        <ul className="m-0 mt-3 flex list-none flex-wrap gap-2 p-0" aria-label="Requests by operation">
          {ops.map(([cls, n]) => (
            <li
              key={cls}
              className={
                riskyClasses.has(cls)
                  ? 'rounded border border-[var(--danger)] bg-[var(--danger-soft)] px-2 py-1 text-sm font-semibold text-[var(--danger)]'
                  : 'rounded border border-[var(--line)] px-2 py-1 text-sm'
              }
            >
              {humanize(cls)}: <span className="font-mono">{n}</span>
            </li>
          ))}
        </ul>
      )}

      <div className="mt-3 grid gap-3 md:grid-cols-2">
        {functions.length > 0 && (
          <table className="w-full border-collapse text-sm">
            <caption className="muted pb-1 text-left text-sm">Functions requested</caption>
            <tbody>
              {functions.map(([fn, n]) => (
                <tr key={fn} className="border-b border-[var(--line)]">
                  <th scope="row" className="py-1 pr-2 text-left font-normal">{humanize(fn)}</th>
                  <td className="py-1 text-right font-mono">{n}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {stats.details && Object.keys(stats.details).length > 0 && (
          <div>
            <p className="muted m-0 pb-1 text-sm">Connection targets</p>
            <ul className="m-0 flex list-none flex-wrap gap-1 p-0 text-sm">
              {sortedEntries(stats.details).map(([detail, n]) => (
                <li key={detail} className="rounded bg-[var(--surface-muted)] px-2 py-0.5">
                  {humanize(detail)} <span className="font-mono">({n})</span>
                </li>
              ))}
            </ul>
          </div>
        )}
        {stats.peers && stats.peers.length > 0 && (
          <div>
            <p className="muted m-0 pb-1 text-sm">Talks to</p>
            <ul className="m-0 flex list-none flex-wrap gap-1 p-0 font-mono text-sm">
              {[...stats.peers].reverse().map((peer) => (
                <li key={peer} className="rounded bg-[var(--surface-muted)] px-2 py-0.5">{peer}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </section>
  )
}

export function IndustrialPanel({ industrial }: { industrial?: Record<string, IndustrialStats> }) {
  const protocols = Object.entries(industrial || {})
  if (!protocols.length) return null
  return (
    <section className="panel grid gap-3" aria-labelledby="industrial-heading">
      <h2 id="industrial-heading" className="m-0 font-[family-name:var(--font-display)] text-lg font-bold">
        Industrial protocols
      </h2>
      {protocols.map(([protocol, stats]) => (
        <ProtocolSection key={protocol} protocol={protocol} stats={stats} />
      ))}
    </section>
  )
}
