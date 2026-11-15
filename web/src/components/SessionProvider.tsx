import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { fetchSession, HTTPError, logout } from '../lib/api'
import { SessionContext, setCSRF, type Session } from '../lib/session'
import { getToken, setToken } from '../lib/token'

const SIGNED_OUT: Session = { authenticated: false, role: 'none', oidc: false, protect_reads: false, writes_enabled: false }

// Re-check the session now and then, so an expired sign-in shows up
// before the next change fails.
const RECHECK_MS = 5 * 60 * 1000

async function load(): Promise<{ session: Session; tokenRejected: boolean }> {
  try {
    return { session: await fetchSession(), tokenRejected: false }
  } catch (err) {
    // A wrong pasted token makes the session call itself fail; forget it
    // and ask again as an anonymous caller.
    if (getToken() && err instanceof HTTPError && err.status === 401) {
      setToken('')
      try {
        return { session: await fetchSession(), tokenRejected: true }
      } catch {
        return { session: SIGNED_OUT, tokenRejected: true }
      }
    }
    return { session: SIGNED_OUT, tokenRejected: false }
  }
}

/** Loads who the console is talking as, and keeps the CSRF token current. */
export function SessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null)
  const [tokenRejected, setTokenRejected] = useState(false)

  const apply = useCallback((r: { session: Session; tokenRejected: boolean }) => {
    setCSRF(r.session.csrf || '')
    setSession(r.session)
    setTokenRejected(r.tokenRejected)
  }, [])

  const refresh = useCallback(async () => apply(await load()), [apply])

  const signOut = useCallback(async () => {
    await logout()
    setCSRF('')
    await refresh()
  }, [refresh])

  useEffect(() => {
    let cancelled = false
    const run = () => {
      void load().then((r) => {
        if (!cancelled) apply(r)
      })
    }
    run()
    const timer = window.setInterval(run, RECHECK_MS)
    const onFocus = () => {
      if (document.visibilityState === 'visible') run()
    }
    document.addEventListener('visibilitychange', onFocus)
    return () => {
      cancelled = true
      window.clearInterval(timer)
      document.removeEventListener('visibilitychange', onFocus)
    }
  }, [apply])

  return <SessionContext.Provider value={{ session, tokenRejected, refresh, signOut }}>{children}</SessionContext.Provider>
}
