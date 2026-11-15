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
  asset?: AssetInfo
  zone?: string
  [key: string]: unknown
}

/** GET /api/v1/zones */
export type ZoneInfo = {
  id: string
  name: string
  level: number
  cidrs: string[]
  industrial: boolean
  enforce: boolean
  devices: number
}

export type ZoneSummary = {
  zones: ZoneInfo[]
  conduits: { from: string; to: string; ports?: number[] | null; bidirectional: boolean }[]
  violations: Record<string, number> | null
}

/** GET/PUT /api/v1/segmentation */
export type ZoneConfig = {
  id: string
  name: string
  level: number
  cidrs: string[]
  industrial: boolean
  enforce: boolean
}

export type ConduitConfig = { from: string; to: string; ports: number[] | null; bidirectional: boolean }

export type ZoneRuleConfig = { enabled: boolean; severity: string; realert_seconds: number }

export type Segmentation = {
  source: 'config' | 'saved'
  zones: ZoneConfig[]
  conduits: ConduitConfig[]
  no_conduit: ZoneRuleConfig
  level_skip: ZoneRuleConfig
}

/** GET /api/v1/baseline */
export type BaselineFlow = {
  id: string
  client: string
  server: string
  protocol: string
  class: string
  status: 'learned' | 'approved' | 'new'
  first_seen: string
  last_seen: string
  count: number
}

export type BaselineState = {
  status: {
    state: 'learning' | 'enforcing' | 'disabled'
    started_at?: string
    learning_until?: string
    learned: number
    approved: number
    new: number
    dropped: number
    max_flows: number
  }
  flows: BaselineFlow[]
}

/** One row of GET /api/v1/assets. */
export type AssetEntry = {
  mac: string
  ip: string
  oui_vendor?: string
  role: string
  role_source: '' | 'inferred' | 'override'
  protocols: string[]
  asset?: AssetInfo
  last_seen: string
}

/** Identity a device reported about itself in an industrial protocol. */
export type AssetInfo = {
  vendor?: string
  model?: string
  firmware?: string
  serial?: string
  device_type?: string
  source: string
  updated_at?: string
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
  techniques?: { id: string; name: string }[]
  capture_id?: string
  [key: string]: unknown
}

/** GET /api/v1/captures */
export type CaptureEntry = {
  id: string
  created_at: string
  reason: 'alert' | 'manual'
  rule?: string
  alert_id?: string
  address?: string
  from: string
  to: string
  packets: number
  bytes: number
  drops: number
}

export type CaptureState = {
  enabled: boolean
  interfaces: string[]
  buffer_packets: number
  buffer_bytes: number
  buffer_oldest?: string
  pending: number
  skipped: number
  kernel_drops: number
  captures: CaptureEntry[]
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
