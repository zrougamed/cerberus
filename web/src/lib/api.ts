import type {
  AnomalySnapshot,
  DeviceSummary,
  PolicyLogEntry,
  PolicyState,
  Summary,
  VersionInfo,
  AlertEvent,
  AssetEntry,
} from './types'
import { getToken, setToken } from './token'

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(path, { headers: { Accept: 'application/json' } })
  if (!res.ok) throw new Error(`${path} → ${res.status}`)
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
  const headers: Record<string, string> = {
    Accept: 'application/json',
    Authorization: `Bearer ${getToken()}`,
  }
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
    setToken('')
    return { ok: false, status: 401, error: 'The API token was not accepted. Enter it again to make changes.' }
  }
  if (!res.ok) {
    return { ok: false, status: res.status, error: (data && data.error) || `The server answered ${res.status}.` }
  }
  return { ok: true, status: res.status, data }
}

export async function fetchRaw(endpoint: string) {
  const path =
    endpoint === 'policylog' ? '/api/v1/policy/log' : endpoint === 'policy' ? '/api/v1/policy' : `/api/v1/${endpoint}`
  const res = await fetch(path, { headers: { Accept: 'application/json' } })
  const text = await res.text()
  try {
    return JSON.stringify(JSON.parse(text), null, 2)
  } catch {
    return text
  }
}
