# Access control

Cerberus has three roles. Each role includes everything the role below it can do.

| Role | Can |
|------|-----|
| `viewer` | Read everything: devices, alerts, assets, zones, baseline, policy, captures list, `/metrics` |
| `analyst` | Also acknowledge alerts, approve or forget baseline flows, set asset roles |
| `admin` | Also change the policy (blocking), zones and conduits, relearn the baseline, download, delete and take packet captures, reload the advisory bundle |

A caller gets a role in one of three ways:

1. **`CERBERUS_API_TOKEN`**: one shared token with the `admin` role. It is the only
   option without an auth file, and it works the same as before roles existed.
2. **Named tokens** from the auth file. Each has a name, a role and the token's
   SHA-256. The token itself is never stored. Use these for scripts and
   integrations, for example a read-only token for Grafana.
3. **OIDC sign-in** in the Control Room, with an identity provider such as
   Keycloak, Entra ID, Okta or authentik. The user's groups decide the role.

Without `CERBERUS_AUTH_CONFIG` and without `CERBERUS_API_TOKEN`, reads are open
and nothing can be changed.

## Auth file

Point `CERBERUS_AUTH_CONFIG` at a YAML file. Unknown keys are refused, so a
typo cannot silently turn something off. An invalid file stops Cerberus from
starting.

```yaml
# Require a token or a sign-in for every API read and /metrics too.
protect_reads: true

tokens:
  - name: grafana
    role: viewer
    sha256: 5f2b...            # printf %s "$TOKEN" | sha256sum
  - name: soar
    role: analyst
    sha256: 9a41...

oidc:
  issuer: https://login.example.com/realms/plant
  client_id: cerberus
  redirect_url: https://cerberus.example.com/auth/callback
  client_secret_file: /run/secrets/cerberus-oidc   # or CERBERUS_OIDC_CLIENT_SECRET
  groups_claim: groups          # default
  roles:
    viewer: [ot-operators]
    analyst: [ot-security]
    admin: [ot-security-leads]
  default_role: ""              # users in none of the groups are refused
  session_hours: 8              # 1 to 168
```

Generate a token and its hash:

```bash
TOKEN=$(openssl rand -hex 24)
printf %s "$TOKEN" | sha256sum
```

Token names show up in the policy audit trail and on acknowledged alerts, so
pick names that say who or what uses them.

## OIDC sign-in

Register Cerberus with the identity provider as a confidential client using
the authorization code flow, and set its redirect URI to
`https://<cerberus host>/auth/callback`. Ask the provider to put the user's
groups in the ID token under the claim named in `groups_claim`.

- Cerberus uses PKCE, a one-time `state` and a `nonce`, and checks the ID
  token's signature, issuer, audience and expiry.
- The user's name comes from `preferred_username`, then `email`, then `name`.
  If the user is in several mapped groups, the highest role applies.
- Sessions live in memory. The browser holds only a random session id in an
  `HttpOnly`, `Secure`, `SameSite=Lax` cookie. Restarting Cerberus signs
  everyone out.
- Changes made from a browser session must carry the `X-Cerberus-CSRF` header,
  whose value comes from `GET /api/v1/session`. The Control Room sends it
  automatically.
- The provider is contacted the first time someone signs in, not at startup.
  Cerberus starts even if the provider is down.
- The redirect URL must use `https`. Plain `http` is accepted only for
  `localhost`, `127.0.0.1` or `::1`, for a local test; browsers keep the
  `Secure` cookie on those hosts.

Cerberus needs to reach the issuer over HTTPS. If the provider uses a private
CA, add that CA to the host's trust store, or to the container image.

## Control Room

- With `protect_reads`, the console shows a sign-in page until the user signs
  in or pastes a token.
- The top bar shows the signed-in user, their role and **Sign out**.
- Pages that make changes show a token field, or the signed-in user. Controls
  that need a higher role stay disabled with a note naming the role required.
- On **Rule alerts**, analysts can acknowledge an alert with an optional note
  (up to 500 characters). The alert then shows who acknowledged it and when.

## API

`GET /api/v1/session` says who the caller is (`authenticated`, `name`, `role`,
`method`) and how to sign in (`oidc`, `login_url`, `protect_reads`,
`writes_enabled`). For browser sessions it also returns `csrf`. It stays
readable when reads are protected.

| Response | Meaning |
|----------|---------|
| **401** | No credentials, or a bearer token that matches nothing |
| **403** | Signed in, but the role is too low (the error names the role needed), a browser change without the right CSRF header, or no way to authenticate is configured |
| **429** | Ten failed attempts from one client within a minute |

Acknowledged alerts carry `acked_by`, `acked_at` and `note`. The ack is kept in
memory with the alert history.
