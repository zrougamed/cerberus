import { useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import { policyWrite } from '../lib/api'
import { useLive } from '../lib/live'
import { useCan } from '../lib/session'
import { AccessNote } from '../components/AccessNote'
import { TokenUnlock } from '../components/TokenUnlock'
import { cn } from '../lib/cn'
import { ruleTarget, type BlockRule } from '../lib/types'

const VERDICT: Record<string, string> = { drop: 'Block', accept: 'Allow', continue: 'Count' }

// Example value for the blocklist target, by the selected kind of match.
const TARGET_EXAMPLE: Record<string, string> = {
  cidr: '203.0.113.0/24',
  mac: '02:00:00:00:00:66',
  dns: '*.example.com',
  sni: '*.example.com',
  host: '*.example.com',
}

export function PolicyPage() {
  const { policy, policyError, policyLog, reloadPolicy } = useLive()
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [targetKind, setTargetKind] = useState('cidr')

  const unlocked = useCan('admin')
  const writes = policy?.writes_enabled !== false
  const mode = policy?.mode || 'monitor'
  const filters = policy?.filters || []
  const rules = policy?.rules || []
  const audit = policy?.audit || []

  const modeClass = mode === 'enforce' ? 'is-enforce' : 'is-monitor'

  async function toggleMode() {
    setBusy(true)
    const next = mode === 'enforce' ? 'monitor' : 'enforce'
    const res = await policyWrite('PUT', '/api/v1/policy/mode', { mode: next })
    setBusy(false)
    setMsg(res.ok ? { kind: 'ok', text: `Mode set to ${next}.` } : { kind: 'err', text: res.error })
    await reloadPolicy()
  }

  async function addBlocklist(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    const fd = new FormData(e.currentTarget)
    const kind = String(fd.get('kind') || 'cidr')
    const value = String(fd.get('target') || '').trim()
    const body: Record<string, unknown> = {
      action: String(fd.get('action') || 'drop'),
      ttl_seconds: Number(fd.get('ttl') || 0),
      comment: String(fd.get('comment') || ''),
      force: fd.get('force') === 'on',
    }
    if (kind === 'mac') {
      body.mac = value
    } else if (kind === 'dns' || kind === 'sni' || kind === 'host') {
      body.hostname = value
      body.host_match = kind === 'host' ? 'any' : kind
    } else {
      body.cidr = value
      body.direction = String(fd.get('direction') || 'any')
    }
    setBusy(true)
    const res = await policyWrite('POST', '/api/v1/policy/rules', body)
    setBusy(false)
    if (!res.ok) {
      setMsg({ kind: 'err', text: res.error })
      return
    }
    e.currentTarget.reset()
    setMsg({ kind: 'ok', text: 'Blocklist entry added.' })
    await reloadPolicy()
  }

  async function addFilter(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    const fd = new FormData(e.currentTarget)
    const proto = String(fd.get('protocol') || '')
    const match: Record<string, unknown> = {}
    const put = (k: string, v: string) => {
      if (v) match[k] = v
    }
    put('protocol', proto)
    put('interface', String(fd.get('interface') || ''))
    put('src', String(fd.get('src') || ''))
    put('dst', String(fd.get('dst') || ''))
    put('src_mac', String(fd.get('src_mac') || ''))
    if (match.src) match.src_not = fd.get('src_not') === 'on'
    if (match.dst) match.dst_not = fd.get('dst_not') === 'on'
    if (proto !== 'icmp' && proto !== 'icmpv6') {
      put('src_port', String(fd.get('src_port') || ''))
      put('dst_port', String(fd.get('dst_port') || ''))
      if (match.src_port) match.src_port_not = fd.get('src_port_not') === 'on'
      if (match.dst_port) match.dst_port_not = fd.get('dst_port_not') === 'on'
    }
    const body: Record<string, unknown> = {
      verdict: String(fd.get('verdict') || 'drop'),
      match,
      log: fd.get('log') === 'on',
      ttl_seconds: Number(fd.get('ttl') || 0),
      comment: String(fd.get('comment') || ''),
      force: fd.get('force') === 'on',
    }
    if (body.log) body.log_every_seconds = Number(fd.get('log_every') || 1)
    if (String(fd.get('position')) === 'top') body.position = 0
    setBusy(true)
    const res = await policyWrite('POST', '/api/v1/policy/filters', body)
    setBusy(false)
    if (!res.ok) {
      setMsg({ kind: 'err', text: res.error })
      return
    }
    e.currentTarget.reset()
    setMsg({ kind: 'ok', text: `Filter ${res.data.id} added.` })
    await reloadPolicy()
  }

  const ifaceList = useMemo(() => policy?.interfaces || [], [policy])

  return (
    <div className="mx-auto grid max-w-[1100px] gap-4">
      <section
        className={cn(
          'panel flex flex-wrap items-center justify-between gap-3 border-l-[6px]',
          modeClass === 'is-enforce' ? 'border-l-[var(--danger)] bg-[var(--danger-soft)]' : 'border-l-[var(--warn)] bg-[var(--warn-soft)]',
        )}
        aria-live="polite"
      >
        <div>
          <h2 className={cn('m-0 font-[family-name:var(--font-display)] text-xl font-bold', modeClass === 'is-enforce' ? 'text-[var(--danger)]' : 'text-[var(--warn)]')}>
            {mode === 'enforce' ? 'Enforcing' : 'Dry run'}
          </h2>
          <p className="m-0 max-w-[62ch] text-sm">
            {policyError ||
              (mode === 'enforce'
                ? 'Block and allow rules are applied in the kernel.'
                : 'Rules are evaluated and counted, but packets are not dropped yet.')}
          </p>
        </div>
        {writes ? (
          <button type="button" className="btn" disabled={busy || !unlocked} onClick={() => void toggleMode()}>
            {mode === 'enforce' ? 'Stop enforcing' : 'Start enforcing'}
          </button>
        ) : null}
      </section>

      <section className="panel">
        <h2 className="m-0 mb-2 font-[family-name:var(--font-display)] text-lg font-bold">Console access</h2>
        {!writes ? (
          <p className="muted text-sm">This server is read-only: neither CERBERUS_API_TOKEN nor sign-in is configured.</p>
        ) : (
          <div className="grid gap-2">
            <TokenUnlock id="policy-token" onChange={() => void reloadPolicy()} />
            <AccessNote need="admin" action="change policy" />
          </div>
        )}
      </section>

      {msg ? (
        <p
          className={cn('m-0 rounded px-3 py-2 font-semibold', msg.kind === 'ok' ? 'bg-[var(--accent-soft)] text-[var(--accent)]' : 'bg-[var(--danger-soft)] text-[var(--danger)]')}
          role={msg.kind === 'err' ? 'alert' : 'status'}
        >
          {msg.text}
        </p>
      ) : null}

      <section className="panel overflow-x-auto" tabIndex={0} aria-label="Filter rules">
        <h2 className="m-0 mb-2 font-[family-name:var(--font-display)] text-lg font-bold">Filter rules</h2>
        {filters.length === 0 ? (
          <p className="muted text-sm">No filter rules.</p>
        ) : (
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-[var(--line)] text-left text-[var(--text-soft)]">
                <th className="px-2 py-2">#</th>
                <th className="px-2 py-2">Action</th>
                <th className="px-2 py-2">Match</th>
                <th className="px-2 py-2">Hits</th>
                <th className="px-2 py-2" />
              </tr>
            </thead>
            <tbody>
              {filters.map((f, idx) => (
                <tr key={f.id} className={cn('border-b border-[var(--line)]', f.enabled === false && 'opacity-55')}>
                  <td className="px-2 py-2 font-mono text-[var(--text-soft)]">{idx + 1}</td>
                  <td className="px-2 py-2">
                    <span className="badge">{VERDICT[String(f.verdict)] || String(f.verdict)}</span>
                  </td>
                  <td className="px-2 py-2 font-mono text-xs">{JSON.stringify(f.match || {})}</td>
                  <td className="px-2 py-2 font-mono tabular-nums">{Number(f.hits || 0)}</td>
                  <td className="px-2 py-2">
                    <button
                      type="button"
                      className="btn btn-danger"
                      disabled={!unlocked || busy}
                      onClick={() =>
                        void (async () => {
                          setBusy(true)
                          await policyWrite('DELETE', `/api/v1/policy/filters/${encodeURIComponent(f.id)}`)
                          setBusy(false)
                          await reloadPolicy()
                        })()
                      }
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="panel">
        <h2 className="m-0 mb-3 font-[family-name:var(--font-display)] text-lg font-bold">Add a filter rule</h2>
        <form className="grid gap-4" onSubmit={(e) => void addFilter(e)}>
          <fieldset className="flex flex-wrap gap-4 border-0 p-0">
            <legend className="mb-1 w-full font-bold">Action</legend>
            <label className="inline-flex items-center gap-2">
              <input type="radio" name="verdict" value="drop" defaultChecked /> Block
            </label>
            <label className="inline-flex items-center gap-2">
              <input type="radio" name="verdict" value="accept" /> Allow
            </label>
            <label className="inline-flex items-center gap-2">
              <input type="radio" name="verdict" value="continue" /> Count only
            </label>
          </fieldset>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div className="field">
              <label htmlFor="filter-protocol">Protocol</label>
              <select id="filter-protocol" name="protocol" defaultValue="">
                <option value="">Any</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="icmp">ICMP</option>
                <option value="icmpv6">ICMPv6</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="filter-iface">Interface</label>
              <input id="filter-iface" name="interface" list="filter-iface-list" autoComplete="off" spellCheck={false} />
              <datalist id="filter-iface-list">
                {ifaceList.map((i) => (
                  <option key={i} value={i} />
                ))}
              </datalist>
            </div>
            <div className="field">
              <label htmlFor="filter-src">Source address</label>
              <input id="filter-src" name="src" autoComplete="off" spellCheck={false} />
            </div>
            <div className="field">
              <label htmlFor="filter-dst">Destination address</label>
              <input id="filter-dst" name="dst" autoComplete="off" spellCheck={false} />
            </div>
            <div className="field">
              <label htmlFor="filter-sport">Source port</label>
              <input id="filter-sport" name="src_port" inputMode="numeric" autoComplete="off" />
            </div>
            <div className="field">
              <label htmlFor="filter-dport">Destination port</label>
              <input id="filter-dport" name="dst_port" inputMode="numeric" autoComplete="off" />
            </div>
            <div className="field">
              <label htmlFor="filter-position">Position</label>
              <select id="filter-position" name="position" defaultValue="end">
                <option value="end">At the end</option>
                <option value="top">At the top</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="filter-ttl">Duration</label>
              <select id="filter-ttl" name="ttl" defaultValue="0">
                <option value="0">Until removed</option>
                <option value="900">15 minutes</option>
                <option value="3600">1 hour</option>
                <option value="86400">24 hours</option>
              </select>
            </div>
            <div className="field sm:col-span-2 lg:col-span-4">
              <label htmlFor="filter-comment">Reason</label>
              <input id="filter-comment" name="comment" maxLength={256} autoComplete="off" />
            </div>
          </div>
          <label className="inline-flex items-center gap-2">
            <input name="log" type="checkbox" /> Log matching packets
          </label>
          <label className="inline-flex items-center gap-2">
            <input name="force" type="checkbox" /> Allow a broad or self-matching block
          </label>
          <button className="btn btn-primary justify-self-start" type="submit" disabled={!unlocked || busy}>
            Add filter rule
          </button>
        </form>
      </section>

      <section className="panel">
        <h2 className="m-0 mb-3 font-[family-name:var(--font-display)] text-lg font-bold">Blocklist</h2>
        <form className="grid gap-4" onSubmit={(e) => void addBlocklist(e)}>
          <fieldset
            className="flex flex-wrap gap-4 border-0 p-0"
            onChange={(e) => {
              const input: EventTarget = e.target
              if (input instanceof HTMLInputElement) setTargetKind(input.value)
            }}
          >
            <legend className="mb-1 w-full font-bold">Match traffic by</legend>
            <label className="inline-flex items-center gap-2">
              <input type="radio" name="kind" value="cidr" defaultChecked /> IP address or range
            </label>
            <label className="inline-flex items-center gap-2">
              <input type="radio" name="kind" value="mac" /> Device (MAC)
            </label>
            <label className="inline-flex items-center gap-2">
              <input type="radio" name="kind" value="dns" /> DNS name
            </label>
            <label className="inline-flex items-center gap-2">
              <input type="radio" name="kind" value="sni" /> TLS SNI
            </label>
            <label className="inline-flex items-center gap-2">
              <input type="radio" name="kind" value="host" /> DNS or SNI
            </label>
          </fieldset>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div className="field">
              <label htmlFor="policy-target">Address or hostname</label>
              <input
                id="policy-target"
                name="target"
                required
                autoComplete="off"
                spellCheck={false}
                placeholder={TARGET_EXAMPLE[targetKind]}
              />
            </div>
            <div className="field">
              <label htmlFor="policy-direction">Direction</label>
              <select id="policy-direction" name="direction" defaultValue="any">
                <option value="any">To or from it</option>
                <option value="dst">Going to it</option>
                <option value="src">Coming from it</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="policy-action">Action</label>
              <select id="policy-action" name="action" defaultValue="drop">
                <option value="drop">Block</option>
                <option value="log">Count only</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="policy-ttl">Duration</label>
              <select id="policy-ttl" name="ttl" defaultValue="0">
                <option value="0">Until removed</option>
                <option value="900">15 minutes</option>
                <option value="3600">1 hour</option>
                <option value="86400">24 hours</option>
              </select>
            </div>
            <div className="field sm:col-span-2 lg:col-span-4">
              <label htmlFor="policy-comment">Reason</label>
              <input id="policy-comment" name="comment" maxLength={256} autoComplete="off" />
            </div>
          </div>
          <label className="inline-flex items-center gap-2">
            <input id="policy-force" name="force" type="checkbox" /> Allow rules that cover this host or the gateway
          </label>
          <button className="btn btn-primary justify-self-start" type="submit" disabled={!unlocked || busy}>
            Add to blocklist
          </button>
        </form>
      </section>

      <section className="panel overflow-x-auto" tabIndex={0} aria-label="Blocklist entries">
        <h2 className="m-0 mb-2 font-[family-name:var(--font-display)] text-lg font-bold">Blocklist entries</h2>
        {rules.length === 0 ? (
          <p className="muted text-sm">No blocklist entries.</p>
        ) : (
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-[var(--line)] text-left text-[var(--text-soft)]">
                <th className="px-2 py-2">Target</th>
                <th className="px-2 py-2">Action</th>
                <th className="px-2 py-2">Hits</th>
                <th className="px-2 py-2" />
              </tr>
            </thead>
            <tbody>
              {rules.map((r: BlockRule) => (
                <tr key={r.id} className="border-b border-[var(--line)]">
                  <td className="px-2 py-2 font-mono">
                    {ruleTarget(r)}
                    {r.parent_id ? <span className="badge ml-2">auto</span> : null}
                    {r.comment ? <div className="muted text-xs">{String(r.comment)}</div> : null}
                  </td>
                  <td className="px-2 py-2"><span className="badge">{r.action}</span></td>
                  <td className="px-2 py-2 font-mono tabular-nums">{Number(r.counters?.packets || 0)}</td>
                  <td className="px-2 py-2">
                    <button
                      type="button"
                      className="btn btn-danger"
                      disabled={!unlocked || busy || Boolean(r.parent_id)}
                      title={r.parent_id ? 'Derived from a hostname rule; remove the parent instead' : undefined}
                      onClick={() =>
                        void (async () => {
                          setBusy(true)
                          await policyWrite('DELETE', `/api/v1/policy/rules/${encodeURIComponent(r.id)}`)
                          setBusy(false)
                          await reloadPolicy()
                        })()
                      }
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="panel overflow-x-auto" tabIndex={0} aria-label="Live log">
        <h2 className="m-0 mb-2 font-[family-name:var(--font-display)] text-lg font-bold">Live log</h2>
        {(policyLog || []).length === 0 ? (
          <p className="muted text-sm">No log entries yet.</p>
        ) : (
          <pre className="m-0 max-h-64 overflow-auto rounded border border-[var(--line)] bg-[var(--surface-muted)] p-3 font-mono text-xs">
            {JSON.stringify(policyLog, null, 2)}
          </pre>
        )}
      </section>

      <section className="panel">
        <h2 className="m-0 mb-2 font-[family-name:var(--font-display)] text-lg font-bold">Recent changes</h2>
        {audit.length === 0 ? (
          <p className="muted text-sm">No audit events.</p>
        ) : (
          <ul className="m-0 grid list-none gap-2 p-0">
            {audit.map((a, i) => (
              <li key={i} className="border-b border-[var(--line)] pb-2">
                <div className="font-mono text-xs text-[var(--text-soft)]">{a.at ? new Date(String(a.at)).toLocaleString() : '—'}</div>
                <div className="text-sm">
                  <strong>{String(a.action || '')}</strong> {String(a.detail || '')}
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  )
}
