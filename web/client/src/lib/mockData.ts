import { DeviceInfo, CommunicationPattern, NetworkStats, NetworkInterface, TrafficPoint } from "@/types";
import { subMinutes, subSeconds } from "date-fns";

// Utils
const randomInt = (min: number, max: number) => Math.floor(Math.random() * (max - min + 1) + min);
const randomIp = () => `192.168.1.${randomInt(1, 254)}`;
const randomMac = () => Array.from({ length: 6 }, () => randomInt(0, 255).toString(16).padStart(2, '0')).join(':').toUpperCase();
const vendors = ['Apple', 'Intel', 'Ubiquiti', 'Samsung', 'Espressif', 'Google', 'Cisco'];

// Generators
export const generateDevices = (count: number): DeviceInfo[] => {
  return Array.from({ length: count }).map(() => ({
    mac: randomMac(),
    ip: randomIp(),
    vendor: vendors[randomInt(0, vendors.length - 1)],
    interface: 'eth0',
    first_seen: subMinutes(new Date(), randomInt(10, 1000)).toISOString(),
    last_seen: subSeconds(new Date(), randomInt(0, 300)).toISOString(),
    packets_sent: randomInt(100, 10000),
    packets_received: randomInt(100, 10000),
    bytes_sent: randomInt(1000, 1000000),
    bytes_received: randomInt(1000, 1000000),
    tcp_connections: randomInt(0, 50),
    udp_connections: randomInt(0, 50),
    dns_queries: randomInt(0, 100),
    is_active: Math.random() > 0.3
  }));
};

export const generatePatterns = (count: number): CommunicationPattern[] => {
  const protocols = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'TLS'] as const;
  return Array.from({ length: count }).map((_, i) => ({
    id: `pat-${i}`,
    timestamp: subSeconds(new Date(), i * 5).toISOString(),
    protocol: protocols[randomInt(0, protocols.length - 1)],
    src_ip: randomIp(),
    dst_ip: Math.random() > 0.7 ? '8.8.8.8' : randomIp(),
    dst_port: [80, 443, 53, 22, 8080][randomInt(0, 4)],
    service_name: ['HTTP', 'HTTPS', 'DNS', 'SSH', 'Web'][randomInt(0, 4)],
    info: 'Packet captured'
  }));
};

export const generateInterfaces = (): NetworkInterface[] => [
  { name: 'eth0', mac: randomMac(), ips: ['192.168.1.50'], is_up: true, packets_captured: 154200 },
  { name: 'wlan0', mac: randomMac(), ips: ['192.168.1.51'], is_up: true, packets_captured: 45200 },
  { name: 'docker0', mac: randomMac(), ips: ['172.17.0.1'], is_up: true, packets_captured: 8200 },
];

export const generateStats = (): NetworkStats => ({
  total_packets: 1254302,
  arp_packets: 45000,
  tcp_packets: 850000,
  udp_packets: 250000,
  icmp_packets: 15000,
  dns_packets: 65000,
  http_packets: 120000,
  tls_packets: 580000,
  total_devices: 42,
  active_devices: 28,
  unique_patterns: 156,
  interfaces_monitored: 3,
  uptime_seconds: 86400 * 3
});

export const generateTrafficHistory = (): TrafficPoint[] => {
  return Array.from({ length: 20 }).map((_, i) => ({
    timestamp: subMinutes(new Date(), (20 - i) * 5).toISOString(),
    total_packets: randomInt(5000, 20000),
    tcp_packets: randomInt(3000, 12000),
    udp_packets: randomInt(1000, 5000),
    devices_active: randomInt(10, 30)
  }));
};
