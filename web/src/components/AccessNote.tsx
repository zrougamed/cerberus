import { useSession, type Role } from '../lib/session'

/** Explains why a change is unavailable: not signed in, or the role is too low. */
export function AccessNote({ need, action }: { need: Role; action: string }) {
  const { session } = useSession()
  if (!session) return null
  const ranks: Role[] = ['none', 'viewer', 'analyst', 'admin']
  if (ranks.indexOf(session.role) >= ranks.indexOf(need)) return null
  let text: string
  if (!session.writes_enabled) {
    text = 'Changes are turned off on this server.'
  } else if (!session.authenticated) {
    text = session.oidc ? `Sign in to ${action}.` : `Enter the API token to ${action}.`
  } else {
    text = `Your role (${session.role}) cannot ${action}; it needs ${need}.`
  }
  return <p className="muted m-0 text-sm">{text}</p>
}
