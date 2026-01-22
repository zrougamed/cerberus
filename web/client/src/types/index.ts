export interface NetworkStats {
  total_packets: number;
  arp_packets: number;
  tcp_packets: number;
  udp_packets: number;
  icmp_packets: number;
  dns_packets: number;
  http_packets: number;
  tls_packets: number;
  total_devices: number;
  active_devices: number;
  unique_patterns: number;
  interfaces_monitored: number;
  uptime_seconds: number;
}

export interface DeviceInfo {
  mac: string;
  ip: string;
  vendor: string;
  interface: string;
  first_seen: string;
  last_seen: string;
  packets_sent: number;
  packets_received: number;
  bytes_sent: number;
  bytes_received: number;
  tcp_connections: number;
  udp_connections: number;
  dns_queries: number;
  is_active: boolean;
}

export interface CommunicationPattern {
  id: string;
  timestamp: string;
  protocol: 'ARP' | 'TCP' | 'UDP' | 'ICMP' | 'DNS' | 'HTTP' | 'TLS';
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  service_name?: string;
  info?: string;
}

export interface NetworkInterface {
  name: string;
  mac: string;
  ips: string[];
  is_up: boolean;
  packets_captured: number;
}

export interface ProtocolDistribution {
  name: string;
  value: number;
  color: string;
}

// Matches backend StatsDataPoint structure
export interface TrafficPoint {
  timestamp: string;
  total_packets: number;
  tcp_packets: number;
  udp_packets: number;
  devices_active: number;
}

// Backend StatsHistoryResponse wrapper
export interface StatsHistoryResponse {
  interval: string;
  data_points: TrafficPoint[];
}

export interface VendorLookup {
  vendor: string;
  oui: string;
}

export interface ServiceLookup {
  port: number;
  service_name: string;
  description: string;
}
