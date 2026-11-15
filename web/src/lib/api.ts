import type {
  AnomalySnapshot,
  DeviceSummary,
  PolicyLogEntry,
  PolicyState,
  Summary,
  VersionInfo,
  AlertEvent,
  AssetEntry,
  BaselineState,
  ZoneSummary,
  CaptureState,
  Segmentation,
  AdvisoryStatus,
  AdvisoryMatch,
} from './types'
import { getToken, setToken } from './token'
import { getCSRF, type Session } from './session'

function authHeaders(): Record<string, string> {
  const h: Record<string, string> = { Accept: 'application/json' }
  const token = getToken()
  if (token) h.Authorization = `Bearer ${token}`
  return h
}

/** A non-2xx API response. */
export class HTTPError extends Error {
  readonly status: number
  constructor(path: string, status: number) {
    super(`${path} → ${status}`)
    this.status = status
  }
}

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(path, { headers: authHeaders() })
  if (!res.ok) throw new HTTPError(path, res.status)
  return res.json() as Promise<T>
}

export function fetchSummary() {
  return getJSON<Summary>('/api/v1/summary')
}

export function fetchDevices() {
  return getJSON<DeviceSummary[]>('/api/v1/devices')
}

export function fetchAlerts() {
  return getJSON<AlertEvent[]>('/api/v1/alerts')
}

export function fetchAnomalies() {
  return getJSON<AnomalySnapshot>('/api/v1/anomalies')
}

export function fetchVersion() {
  return getJSON<VersionInfo>('/api/v1/version')
}

export function fetchAssets() {
  return getJSON<AssetEntry[]>('/api/v1/assets')
}

export function fetchBaseline() {
  return getJSON<BaselineState>('/api/v1/baseline?limit=2000')
}

export function fetchZones() {
  return getJSON<ZoneSummary>('/api/v1/zones')
}

export function fetchCaptures() {
  return getJSON<CaptureState>('/api/v1/captures')
}

/** Downloads a capture with the API token and hands it to the browser. */
export async function downloadCapture(id: string): Promise<string | null> {
  let res: Response
  try {
    res = await fetch(`/api/v1/captures/${encodeURIComponent(id)}`, { headers: authHeaders() })
  } catch {
    return 'The server could not be reached. Check that Cerberus is running.'
  }
  if (res.status === 401) {
    setToken('')
    return 'The API token was not accepted. Enter it again to download captures.'
  }
  if (!res.ok) return `The server answered ${res.status}.`
  const url = URL.createObjectURL(await res.blob())
  const a = document.createElement('a')
  a.href = url
  a.download = `cerberus-${id}.pcapng`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
  return null
}

export function fetchSegmentation() {
  return getJSON<Segmentation>('/api/v1/segmentation')
}

export function fetchAdvisoryStatus() {
  return getJSON<AdvisoryStatus>('/api/v1/advisories')
}

export function fetchAssetAdvisories(mac: string) {
  return getJSON<AdvisoryMatch[]>(`/api/v1/assets/${encodeURIComponent(mac)}/advisories`)
}

export function fetchPolicy() {
  return getJSON<PolicyState>('/api/v1/policy')
}

export function fetchPolicyLog() {
  return getJSON<{ entries?: PolicyLogEntry[] } | PolicyLogEntry[]>('/api/v1/policy/log')
}

export async function policyWrite(
  method: string,
  path: string,
  body?: unknown,
): Promise<{ ok: true; status: number; data: any } | { ok: false; status: number; error: string }> {
  const headers = authHeaders()
  // Browser sessions prove the request comes from this page.
  if (getCSRF()) headers['X-Cerberus-CSRF'] = getCSRF()
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  let res: Response
  try {
    res = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch {
    return { ok: false, status: 0, error: 'The server could not be reached. Check that Cerberus is running.' }
  }
  let data: any = null
  try {
    data = await res.json()
  } catch {
    data = null
  }
  if (res.status === 401) {
    if (getToken()) {
      setToken('')
      return { ok: false, status: 401, error: 'The API token was not accepted. Enter it again to make changes.' }
    }
    return { ok: false, status: 401, error: 'Your sign-in has expired. Reload the page and sign in again.' }
  }
  if (!res.ok) {
    return { ok: false, status: res.status, error: (data && data.error) || `The server answered ${res.status}.` }
  }
  return { ok: true, status: res.status, data }
}

export function fetchSession() {
  return getJSON<Session>('/api/v1/session')
}

export async function logout() {
  await fetch('/auth/logout', { method: 'POST', headers: { 'X-Cerberus-CSRF': getCSRF() } })
}

export async function fetchRaw(endpoint: string) {
  const path =
    endpoint === 'policylog' ? '/api/v1/policy/log' : endpoint === 'policy' ? '/api/v1/policy' : `/api/v1/${endpoint}`
  const res = await fetch(path, { headers: authHeaders() })
  const text = await res.text()
  try {
    return JSON.stringify(JSON.parse(text), null, 2)
  } catch {
    return text
  }
}
