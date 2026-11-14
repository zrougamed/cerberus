import { useState } from 'react'
import type { FormEvent } from 'react'
import { getToken, setToken } from '../lib/token'

/** Unlock/lock form for the API token used by write requests. */
export function TokenUnlock({ id, onChange }: { id: string; onChange: () => void }) {
  const [input, setInput] = useState('')
  const unlocked = Boolean(getToken())

  function unlock(e: FormEvent) {
    e.preventDefault()
    setToken(input.trim())
    setInput('')
    onChange()
  }

  if (unlocked) {
    return (
      <div className="flex flex-wrap items-center gap-2">
        <span className="badge">Changes unlocked</span>
        <button
          type="button"
          className="btn"
          onClick={() => {
            setToken('')
            onChange()
          }}
        >
          Lock changes
        </button>
      </div>
    )
  }
  return (
    <form className="grid gap-3 sm:grid-cols-[1fr_auto]" onSubmit={unlock}>
      <div className="field">
        <label htmlFor={id}>API token</label>
        <input
          id={id}
          type="password"
          autoComplete="current-password"
          minLength={16}
          required
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />
        <p className="m-0 text-xs text-[var(--text-soft)]">CERBERUS_API_TOKEN. Kept in this tab only.</p>
      </div>
      <div className="flex items-end">
        <button className="btn" type="submit">
          Unlock changes
        </button>
      </div>
    </form>
  )
}
