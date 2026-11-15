import { createContext, useContext } from 'react'

export type Role = 'none' | 'viewer' | 'analyst' | 'admin'

/** GET /api/v1/session */
export type Session = {
  authenticated: boolean
  name?: string
  role: Role
  method?: 'token' | 'oidc'
  csrf?: string
  oidc: boolean
  login_url?: string
  protect_reads: boolean
  writes_enabled: boolean
}

const RANK: Record<Role, number> = { none: 0, viewer: 1, analyst: 2, admin: 3 }

export type SessionState = {
  session: Session | null
  /** The pasted API token was refused and has been forgotten. */
  tokenRejected: boolean
  refresh: () => Promise<void>
  signOut: () => Promise<void>
}

export const SessionContext = createContext<SessionState>({
  session: null,
  tokenRejected: false,
  refresh: async () => {},
  signOut: async () => {},
})

export function useSession() {
  return useContext(SessionContext)
}

/** True when the current user or token has at least the given role. */
export function useCan(role: Role): boolean {
  const { session } = useSession()
  return Boolean(session && RANK[session.role] >= RANK[role])
}

// The CSRF token of a browser session, sent on every change.
let csrfToken = ''

export function setCSRF(t: string) {
  csrfToken = t
}

export function getCSRF() {
  return csrfToken
}
