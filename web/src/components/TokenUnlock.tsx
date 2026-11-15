import { useState } from 'react'
import type { FormEvent } from 'react'
import { getToken, setToken } from '../lib/token'

/**
 * Unlock/lock form for the API token used by write requests. The help text
 * sits under the input and button row, so it never pushes the input out of
 * line with the button.
 */
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
    <form className="grid gap-1.5" onSubmit={unlock}>
      <label htmlFor={id} className="text-[0.9rem] font-bold">
        API token
      </label>
      <div className="flex flex-col gap-2 sm:flex-row">
        <input
          id={id}
          className="input sm:flex-1"
          type="password"
          autoComplete="current-password"
          aria-describedby={`${id}-help`}
          minLength={16}
          required
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />
        <button className="btn shrink-0" type="submit">
          Unlock changes
        </button>
      </div>
      <p id={`${id}-help`} className="m-0 text-xs text-[var(--text-soft)]">
        The value of CERBERUS_API_TOKEN on the server. It is kept in this browser tab only.
      </p>
    </form>
  )
}
