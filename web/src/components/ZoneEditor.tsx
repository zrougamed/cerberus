import { useState } from 'react'
import type { FormEvent } from 'react'
import { policyWrite } from '../lib/api'
import { cn } from '../lib/cn'
import { PURDUE_LEVELS } from '../lib/purdue'
import type { ConduitConfig, Segmentation, ZoneConfig, ZoneRuleConfig } from '../lib/types'

type Props = {
  seg: Segmentation
  unlocked: boolean
  onSaved: (next: Segmentation) => void
  onMessage: (m: { kind: 'ok' | 'err'; text: string }) => void
}

const SEVERITIES = ['low', 'medium', 'high']

function slug(name: string, taken: Set<string>): string {
  const base = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'zone'
  let id = base
  for (let n = 2; taken.has(id); n++) id = `${base}-${n}`
  return id
}

function splitList(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean)
}

const emptyZone = { name: '', level: '1', cidrs: '', industrial: true, enforce: false }

export function ZoneEditor({ seg, unlocked, onSaved, onMessage }: Props) {
  const [editing, setEditing] = useState<string | null>(null) // zone id, or null for a new zone
  const [zone, setZone] = useState(emptyZone)
  const [enforceTouched, setEnforceTouched] = useState(false)
  const [conduit, setConduit] = useState({ from: '', to: '', ports: '', bidirectional: false })
  const [rules, setRules] = useState({ no_conduit: seg.no_conduit, level_skip: seg.level_skip })
  const [busy, setBusy] = useState(false)
  const [confirmRevert, setConfirmRevert] = useState(false)
  const names = new Map(seg.zones.map((z) => [z.id, z.name]))

  async function save(next: Omit<Segmentation, 'source'>, done: string): Promise<boolean> {
    setBusy(true)
    const res = await policyWrite('PUT', '/api/v1/segmentation', next)
    setBusy(false)
    if (!res.ok) {
      onMessage({ kind: 'err', text: `Not saved: ${res.error}` })
      return false
    }
    onSaved(res.data as Segmentation)
    onMessage({ kind: 'ok', text: done })
    return true
  }

  function base() {
    return { zones: seg.zones, conduits: seg.conduits, no_conduit: seg.no_conduit, level_skip: seg.level_skip }
  }

  async function submitZone(e: FormEvent) {
    e.preventDefault()
    const cidrs = splitList(zone.cidrs)
    if (!cidrs.length) {
      onMessage({ kind: 'err', text: 'Enter at least one address range, for example 10.20.0.0/24.' })
      return
    }
    const fields = { name: zone.name.trim(), level: Number(zone.level), cidrs, industrial: zone.industrial, enforce: zone.enforce }
    const zones: ZoneConfig[] = editing
      ? seg.zones.map((z) => (z.id === editing ? { ...z, ...fields } : z))
      : [...seg.zones, { id: slug(fields.name, new Set(seg.zones.map((z) => z.id))), ...fields }]
    if (await save({ ...base(), zones }, editing ? `${fields.name} updated.` : `${fields.name} added.`)) {
      setEditing(null)
      setZone(emptyZone)
      setEnforceTouched(false)
    }
  }

  function startEdit(z: ZoneConfig) {
    setEditing(z.id)
    setEnforceTouched(true)
    setZone({ name: z.name, level: String(z.level), cidrs: z.cidrs.join('\n'), industrial: z.industrial, enforce: z.enforce })
  }

  async function removeZone(z: ZoneConfig) {
    const conduits = seg.conduits.filter((c) => c.from !== z.id && c.to !== z.id)
    const dropped = seg.conduits.length - conduits.length
    await save(
      { ...base(), zones: seg.zones.filter((x) => x.id !== z.id), conduits },
      `${z.name} removed${dropped ? `, with ${dropped} conduit${dropped === 1 ? '' : 's'}` : ''}.`,
    )
  }

  async function submitConduit(e: FormEvent) {
    e.preventDefault()
    if (conduit.from === conduit.to) {
      onMessage({ kind: 'err', text: 'A conduit connects two different zones.' })
      return
    }
    const ports = splitList(conduit.ports).map(Number)
    if (ports.some((p) => !Number.isInteger(p) || p < 1 || p > 65535)) {
      onMessage({ kind: 'err', text: 'Ports are numbers from 1 to 65535, separated by commas.' })
      return
    }
    const next: ConduitConfig = { from: conduit.from, to: conduit.to, ports: ports.length ? ports : null, bidirectional: conduit.bidirectional }
    if (await save({ ...base(), conduits: [...seg.conduits, next] }, `Conduit from ${names.get(next.from)} to ${names.get(next.to)} added.`)) {
      setConduit({ from: '', to: '', ports: '', bidirectional: false })
    }
  }

  async function removeConduit(i: number) {
    await save({ ...base(), conduits: seg.conduits.filter((_, j) => j !== i) }, 'Conduit removed.')
  }

  async function submitRules(e: FormEvent) {
    e.preventDefault()
    await save({ ...base(), ...rules }, 'Zone alert settings saved.')
  }

  async function revert() {
    setConfirmRevert(false)
    const res = await policyWrite('DELETE', '/api/v1/segmentation')
    if (!res.ok) {
      onMessage({ kind: 'err', text: res.error })
      return
    }
    const next = res.data as Segmentation
    setRules({ no_conduit: next.no_conduit, level_skip: next.level_skip })
    onSaved(next)
    onMessage({ kind: 'ok', text: 'Zones are back to the ones in the config file.' })
  }

  function ruleRow(key: 'no_conduit' | 'level_skip', title: string, help: string) {
    const r: ZoneRuleConfig = rules[key]
    const set = (patch: Partial<ZoneRuleConfig>) => setRules((prev) => ({ ...prev, [key]: { ...prev[key], ...patch } }))
    return (
      <fieldset className="grid items-end gap-3 border-0 border-t border-[var(--line)] p-0 pt-3 sm:grid-cols-[1fr_9rem_9rem]">
        <legend className="sr-only">{title}</legend>
        <label className="inline-flex items-start gap-2">
          <input className="mt-1" type="checkbox" checked={r.enabled} disabled={!unlocked} onChange={(e) => set({ enabled: e.target.checked })} />
          <span>
            <span className="font-bold">{title}</span>
            <span className="muted block text-sm">{help}</span>
          </span>
        </label>
        <div className="field">
          <label htmlFor={`${key}-severity`}>Severity</label>
          <select id={`${key}-severity`} value={r.severity} disabled={!unlocked || !r.enabled} onChange={(e) => set({ severity: e.target.value })}>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s[0].toUpperCase() + s.slice(1)}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor={`${key}-repeat`}>Repeat after (min)</label>
          <input
            id={`${key}-repeat`}
            type="number"
            min={0}
            value={Math.round(r.realert_seconds / 60)}
            disabled={!unlocked || !r.enabled}
            onChange={(e) => set({ realert_seconds: Math.max(0, Number(e.target.value)) * 60 })}
          />
        </div>
      </fieldset>
    )
  }

  const locked = !unlocked || busy

  return (
    <div className="grid gap-3">
      <section className="panel grid gap-3" aria-labelledby="zone-list-heading">
        <div className="flex flex-wrap items-center gap-2">
          <h2 id="zone-list-heading" className="m-0 mr-auto font-[family-name:var(--font-display)] text-lg font-bold">
            Zones
          </h2>
          <span className="muted text-sm">{seg.source === 'saved' ? 'Saved from the console' : 'From the config file'}</span>
          {seg.source === 'saved' ? (
            confirmRevert ? (
              <>
                <button type="button" className="btn btn-danger" disabled={locked} onClick={() => void revert()}>
                  Discard console changes
                </button>
                <button type="button" className="btn" onClick={() => setConfirmRevert(false)}>
                  Keep them
                </button>
              </>
            ) : (
              <button type="button" className="btn" disabled={locked} onClick={() => setConfirmRevert(true)}>
                Use the config file instead
              </button>
            )
          ) : null}
        </div>
        {seg.zones.length ? (
          <div className="overflow-x-auto" tabIndex={0} aria-label="Zone list">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-[var(--line)] text-left text-[var(--text-soft)]">
                  <th className="px-2 py-2">Name</th>
                  <th className="px-2 py-2">Level</th>
                  <th className="px-2 py-2">Address ranges</th>
                  <th className="px-2 py-2">Blocking rules</th>
                  <th className="px-2 py-2">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {[...seg.zones]
                  .sort((a, b) => b.level - a.level || a.name.localeCompare(b.name))
                  .map((z) => (
                    <tr key={z.id} className="border-b border-[var(--line)] align-top">
                      <td className="px-2 py-2 font-bold">
                        {z.name}
                        {z.industrial ? <span className="muted block text-xs font-normal">Industrial</span> : null}
                      </td>
                      <td className="px-2 py-2 font-mono">L{z.level}</td>
                      <td className="px-2 py-2 font-mono text-xs [overflow-wrap:anywhere]">{z.cidrs.join(', ')}</td>
                      <td className="px-2 py-2">{z.enforce ? 'Allowed' : 'Watch only'}</td>
                      <td className="px-2 py-2">
                        <div className="flex justify-end gap-2">
                          <button type="button" className="btn" disabled={locked} onClick={() => startEdit(z)}>
                            Edit
                          </button>
                          <button type="button" className="btn btn-danger" disabled={locked} onClick={() => void removeZone(z)}>
                            Remove
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        ) : null}

        <form className="grid gap-3 border-t border-[var(--line)] pt-3" onSubmit={(e) => void submitZone(e)}>
          <h3 className="m-0 text-base font-bold">{editing ? `Edit ${names.get(editing)}` : 'Add a zone'}</h3>
          <div className="grid items-start gap-3 md:grid-cols-[1fr_16rem]">
            <div className="field">
              <label htmlFor="zone-name">Name</label>
              <input id="zone-name" required maxLength={64} placeholder="Line 1 PLCs" value={zone.name} disabled={!unlocked} onChange={(e) => setZone({ ...zone, name: e.target.value })} />
            </div>
            <div className="field">
              <label htmlFor="zone-level">Level</label>
              <select id="zone-level" value={zone.level} disabled={!unlocked} onChange={(e) => setZone({ ...zone, level: e.target.value })}>
                {[5, 4, 3, 2, 1, 0].map((l) => (
                  <option key={l} value={l}>
                    L{l}: {PURDUE_LEVELS[l]}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="field">
            <label htmlFor="zone-cidrs">Address ranges</label>
            <textarea
              id="zone-cidrs"
              rows={3}
              required
              spellCheck={false}
              aria-describedby="zone-cidrs-help"
              placeholder={'10.20.0.0/24\n10.20.1.5'}
              value={zone.cidrs}
              disabled={!unlocked}
              onChange={(e) => setZone({ ...zone, cidrs: e.target.value })}
            />
            <p id="zone-cidrs-help" className="m-0 text-xs text-[var(--text-soft)]">
              One per line. A single address counts as /32. When ranges overlap, the most specific one decides the zone.
            </p>
          </div>
          <div className="grid gap-2">
            <label className="inline-flex items-start gap-2">
              <input
                className="mt-1"
                type="checkbox"
                checked={zone.industrial}
                disabled={!unlocked}
                onChange={(e) =>
                  setZone({ ...zone, industrial: e.target.checked, enforce: enforceTouched ? zone.enforce : !e.target.checked })
                }
              />
              <span>
                Industrial zone
                <span className="muted block text-sm">Carries control traffic: PLCs, RTUs, HMIs, field devices.</span>
              </span>
            </label>
            <label className="inline-flex items-start gap-2">
              <input
                className="mt-1"
                type="checkbox"
                checked={zone.enforce}
                disabled={!unlocked}
                onChange={(e) => {
                  setEnforceTouched(true)
                  setZone({ ...zone, enforce: e.target.checked })
                }}
              />
              <span>
                Allow blocking rules in this zone
                <span className="muted block text-sm">
                  Off by default for industrial zones: a dropped packet can stop a process. Policy rules that would block traffic here are refused unless forced.
                </span>
              </span>
            </label>
          </div>
          <div className="flex flex-wrap gap-2">
            <button className="btn btn-primary" type="submit" disabled={locked}>
              {editing ? 'Save zone' : 'Add zone'}
            </button>
            {editing ? (
              <button
                type="button"
                className="btn"
                onClick={() => {
                  setEditing(null)
                  setZone(emptyZone)
                  setEnforceTouched(false)
                }}
              >
                Cancel
              </button>
            ) : null}
          </div>
        </form>
      </section>

      <section className="panel grid gap-3" aria-labelledby="conduit-edit-heading">
        <h2 id="conduit-edit-heading" className="m-0 font-[family-name:var(--font-display)] text-lg font-bold">
          Conduits
        </h2>
        <p className="muted m-0 text-sm">
          A conduit allows traffic from one zone to another, on the listed ports or on any port. Replies are allowed automatically.
        </p>
        {seg.conduits.length ? (
          <ul className="m-0 grid list-none gap-2 p-0">
            {seg.conduits.map((c, i) => (
              <li key={`${c.from}-${c.to}-${i}`} className="flex flex-wrap items-center gap-2 border-b border-[var(--line)] pb-2">
                <span className="mr-auto">
                  <strong>{names.get(c.from) || c.from}</strong> to <strong>{names.get(c.to) || c.to}</strong>
                  <span className="muted">
                    {' '}
                    on {c.ports && c.ports.length ? `port${c.ports.length > 1 ? 's' : ''} ${c.ports.join(', ')}` : 'any port'}
                    {c.bidirectional ? ', either side opens' : ''}
                  </span>
                </span>
                <button type="button" className="btn btn-danger" disabled={locked} onClick={() => void removeConduit(i)}>
                  Remove
                </button>
              </li>
            ))}
          </ul>
        ) : null}
        {seg.zones.length >= 2 ? (
          <form className="grid gap-3" onSubmit={(e) => void submitConduit(e)}>
            <div className="grid items-start gap-3 sm:grid-cols-2 lg:grid-cols-[1fr_1fr_12rem]">
              <div className="field">
                <label htmlFor="conduit-from">From</label>
                <select id="conduit-from" required value={conduit.from} disabled={!unlocked} onChange={(e) => setConduit({ ...conduit, from: e.target.value })}>
                  <option value="">Choose a zone</option>
                  {seg.zones.map((z) => (
                    <option key={z.id} value={z.id}>
                      {z.name}
                    </option>
                  ))}
                </select>
              </div>
              <div className="field">
                <label htmlFor="conduit-to">To</label>
                <select id="conduit-to" required value={conduit.to} disabled={!unlocked} onChange={(e) => setConduit({ ...conduit, to: e.target.value })}>
                  <option value="">Choose a zone</option>
                  {seg.zones.map((z) => (
                    <option key={z.id} value={z.id}>
                      {z.name}
                    </option>
                  ))}
                </select>
              </div>
              <div className="field">
                <label htmlFor="conduit-ports">Ports</label>
                <input id="conduit-ports" placeholder="502, 102" inputMode="numeric" aria-describedby="conduit-ports-help" value={conduit.ports} disabled={!unlocked} onChange={(e) => setConduit({ ...conduit, ports: e.target.value })} />
                <p id="conduit-ports-help" className="m-0 text-xs text-[var(--text-soft)]">
                  Empty allows any port.
                </p>
              </div>
            </div>
            <label className="inline-flex items-center gap-2">
              <input type="checkbox" checked={conduit.bidirectional} disabled={!unlocked} onChange={(e) => setConduit({ ...conduit, bidirectional: e.target.checked })} />
              Either zone may open connections
            </label>
            <div>
              <button className="btn btn-primary" type="submit" disabled={locked}>
                Add conduit
              </button>
            </div>
          </form>
        ) : (
          <p className="muted m-0 text-sm">Add at least two zones to create a conduit between them.</p>
        )}
      </section>

      <section className="panel" aria-labelledby="zone-rules-heading">
        <h2 id="zone-rules-heading" className="m-0 mb-3 font-[family-name:var(--font-display)] text-lg font-bold">
          Zone alerts
        </h2>
        <form className="grid gap-3" onSubmit={(e) => void submitRules(e)}>
          {ruleRow('no_conduit', 'Traffic with no conduit', 'Traffic between two zones that no conduit allows.')}
          {ruleRow('level_skip', 'Traffic that skips a level', 'The same, between zones more than one level apart, such as the office reaching a PLC network.')}
          <div>
            <button className={cn('btn btn-primary')} type="submit" disabled={locked}>
              Save alert settings
            </button>
          </div>
        </form>
      </section>
    </div>
  )
}
