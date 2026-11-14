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
  [key: string]: unknown
}

export type Summary = {
  generated_at: string
  packet_stats: PacketStats
  device_count: number
  top_services?: Record<string, number>
  top_vendors?: Record<string, number>
  dns_query_types?: Record<string, number>
  dns_response_codes?: Record<string, number>
  recent_devices?: DeviceSummary[]
}

export type AlertEvent = {
  time?: string
  severity?: string
  rule_id?: string
  device_mac?: string
  device_ip?: string
  message?: string
  [key: string]: unknown
}

export type AnomalySnapshot = {
  ready?: boolean
  windows?: number
  baseline_windows?: number
  status?: string
  insight?: string
  insight_plain?: string
  score?: number
  robust_z?: number
  centroid_distance?: number
  packets_per_sec?: number
  entropy?: number
  unusual_ports?: number
  last_contributors?: Array<Record<string, unknown>>
  alerts?: Array<Record<string, unknown>>
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
  comment?: string
  [key: string]: unknown
}

export type BlockRule = {
  id: string
  target?: string
  kind?: string
  action?: string
  direction?: string
  hits?: number
  bytes?: number
  comment?: string
  [key: string]: unknown
}

export type AuditEntry = {
  time?: string
  action?: string
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
