export type PacketStats = Record<string, number>

export type DeviceSummary = {
  mac: string
  ip: string
  vendor?: string
  is_gateway?: boolean
  first_seen?: string
  last_seen?: string
  tcp?: number
  udp?: number
  dns_queries?: number
  http_requests?: number
  tls?: number
  tls_connections?: number
  industrial?: Record<string, IndustrialStats>
  [key: string]: unknown
}

/** Per-protocol counters from the industrial decoders (see internal/models). */
export type IndustrialStats = {
  requests: number
  responses: number
  exceptions: number
  operations?: Record<string, number>
  functions?: Record<string, number>
  details?: Record<string, number>
  peers?: string[]
  last_seen?: string
}

export type Summary = {
  generated_at: string
  packet_stats: PacketStats
  device_count: number
  top_services?: Record<string, number>
  top_vendors?: Record<string, number>
  dns_query_types?: Record<string, number>
  dns_response_codes?: Record<string, number>
  dns_response_domains?: Record<string, number>
  encrypted_dns?: Record<string, number>
  tls_versions?: Record<string, number>
  top_tls_snis?: Record<string, number>
  dns_correlated_domains?: Record<string, number>
  recent_devices?: DeviceSummary[]
}

export type AlertEvent = {
  time?: string
  observed_at?: string
  severity?: string
  rule_id?: string
  rule?: string
  device_mac?: string
  device_ip?: string
  message?: string
  [key: string]: unknown
}

export type AnomalyContribution = {
  feature?: string
  label?: string
  value?: number
  baseline_median?: number
  robust_z?: number
  [key: string]: unknown
}

export type AnomalySnapshot = {
  status?: string
  window_seconds?: number
  baseline_windows?: number
  current_score?: number
  robust_z_score?: number
  centroid_distance?: number
  is_anomaly?: boolean
  recent_anomaly_count?: number
  last_summary?: string
  last_summary_detail?: string
  last_contributions?: AnomalyContribution[]
  last_features?: {
    packet_rate?: number
    dns_rate?: number
    http_rate?: number
    tls_rate?: number
    port_entropy?: number
    unusual_port_count?: number
    [key: string]: unknown
  }
  recent_alerts?: Array<{
    observed_at?: string
    score?: number
    severity?: string
    summary?: string
    detail?: string
    [key: string]: unknown
  }>
  [key: string]: unknown
}

export type PolicyState = {
  mode?: string
  writes_enabled?: boolean
  filters?: FilterRule[]
  rules?: BlockRule[]
  audit?: AuditEntry[]
  interfaces?: string[]
  max_filters?: number
  [key: string]: unknown
}

export type FilterRule = {
  id: string
  verdict?: string
  enabled?: boolean
  match?: Record<string, unknown>
  log?: boolean
  hits?: number
  counters?: { packets?: number; bytes?: number }
  comment?: string
  summary?: string
  [key: string]: unknown
}

export type BlockRule = {
  id: string
  mac?: string
  cidr?: string
  hostname?: string
  host_match?: string
  parent_id?: string
  action?: string
  direction?: string
  counters?: { packets?: number; bytes?: number }
  comment?: string
  [key: string]: unknown
}

export type AuditEntry = {
  at?: string
  actor?: string
  action?: string
  rule_id?: string
  detail?: string
  [key: string]: unknown
}

export type PolicyLogEntry = {
  time?: string
  rule_id?: string
  verdict?: string
  [key: string]: unknown
}

export type VersionInfo = {
  commit?: string
  date?: string
}

export function sumRecord(values?: Record<string, number>): number {
  if (!values) return 0
  return Object.values(values).reduce((a, b) => a + (Number(b) || 0), 0)
}

export function ruleTarget(r: BlockRule): string {
  if (r.hostname) {
    return `${r.host_match || 'any'} ${r.hostname}`
  }
  if (r.mac) return `MAC ${r.mac}`
  if (r.cidr) return r.cidr
  return r.id
}
