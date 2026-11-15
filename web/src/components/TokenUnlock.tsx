import { useState } from 'react'
import type { FormEvent } from 'react'
import { useSession } from '../lib/session'
import { setToken } from '../lib/token'

/**
 * Who the console is acting as, with the way to change it: sign out of a
 * browser session, forget a pasted API token, or paste one. The help text
 * sits under the input and button row, so it never pushes the input out of
 * line with the button.
 */
export function TokenUnlock({ id, onChange }: { id: string; onChange?: () => void }) {
  const { session, tokenRejected, refresh, signOut } = useSession()
  const [input, setInput] = useState('')

  async function unlock(e: FormEvent) {
    e.preventDefault()
    setToken(input.trim())
    setInput('')
    await refresh()
    onChange?.()
  }

  if (session && !session.writes_enabled) {
    // No token or sign-in exists on the server, so nothing typed here could
    // work. Say how to turn changes on instead.
    return (
      <div className="grid gap-1.5">
        <p className="m-0 font-bold">Changes are turned off on this server</p>
        <p className="m-0 text-sm">
          To make changes from the console, set <code>CERBERUS_API_TOKEN</code> to a secret of at least 16 characters and restart Cerberus, then
          enter the same value here. With Docker Compose, uncomment the <code>CERBERUS_API_TOKEN</code> line in <code>docker-compose.yml</code>.
          For named tokens, roles or sign-in, use <code>CERBERUS_AUTH_CONFIG</code> (see docs/access-control.md).
        </p>
      </div>
    )
  }

  if (session?.authenticated) {
    const viaToken = session.method === 'token'
    return (
      <div className="flex flex-wrap items-center gap-2">
        <span className="badge">
          {viaToken ? 'Token' : 'Signed in as'} {session.name} ({session.role})
        </span>
        <button
          type="button"
          className="btn"
          onClick={async () => {
            if (viaToken) {
              setToken('')
              await refresh()
            } else {
              await signOut()
            }
            onChange?.()
          }}
        >
          {viaToken ? 'Forget token' : 'Sign out'}
        </button>
      </div>
    )
  }
  return (
    <form className="grid gap-1.5" onSubmit={(e) => void unlock(e)}>
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
          aria-invalid={tokenRejected || undefined}
          minLength={16}
          required
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />
        <button className="btn shrink-0" type="submit">
          Use token
        </button>
      </div>
      <p id={`${id}-help`} className="m-0 text-xs text-[var(--text-soft)]">
        {tokenRejected
          ? 'That token was not accepted. Check it and try again.'
          : 'CERBERUS_API_TOKEN or a named token from the auth config. It is kept in this browser tab only.'}
      </p>
    </form>
  )
}
