import { useSession } from '../lib/session'
import { Logo } from './Logo'
import { TokenUnlock } from './TokenUnlock'

/** Shown instead of the console when reads require signing in. */
export function SignIn() {
  const { session, refresh } = useSession()
  return (
    <main className="grid min-h-screen place-items-center bg-[var(--bg)] p-4">
      <section className="panel grid w-full max-w-md gap-4" aria-labelledby="signin-heading">
        <div className="flex items-center gap-3">
          <Logo />
          <h1 id="signin-heading" className="m-0 font-[family-name:var(--font-display)] text-2xl font-bold">
            Sign in to Cerberus
          </h1>
        </div>
        <p className="m-0">This Control Room only shows data to signed-in users.</p>
        {session?.oidc && session.login_url ? (
          <a className="btn btn-primary no-underline" href={session.login_url}>
            Sign in with your organisation account
          </a>
        ) : null}
        <div className="grid gap-2">
          <p className="muted m-0 text-sm">{session?.oidc ? 'Or use an API token:' : 'Use an API token:'}</p>
          <TokenUnlock id="signin-token" onChange={() => void refresh()} />
        </div>
      </section>
    </main>
  )
}
