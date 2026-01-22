// API client for frontend to Cerberus backend communication
// In production container, requests to /api/v1 are proxied by nginx to Cerberus
// In development, Vite proxies to the backend specified in vite.config.ts

import { 
  NetworkStats, 
  DeviceInfo, 
  CommunicationPattern, 
  NetworkInterface, 
  TrafficPoint,
  StatsHistoryResponse,
  VendorLookup,
  ServiceLookup
} from "@/types";
import { 
  generateStats, 
  generateDevices, 
  generatePatterns, 
  generateInterfaces, 
  generateTrafficHistory 
} from "./mockData";

// Use /api/v1 as base URL - proxied by Vite (dev) or nginx (production)
const API_BASE_URL = '/api/v1';

// Enable mock mode via environment variable for development without backend
const USE_MOCK = import.meta.env.VITE_USE_MOCK === 'true';

class ApiClient {
  private baseUrl: string;
  private useMock: boolean;

  constructor(baseUrl: string = API_BASE_URL, useMock: boolean = USE_MOCK) {
    this.baseUrl = baseUrl;
    this.useMock = useMock;
  }

  private async fetch<T>(endpoint: string, options?: RequestInit): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    
    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }

    return await response.json();
  }

  // Network statistics
  async getStats(): Promise<NetworkStats> {
    if (this.useMock) {
      return generateStats();
    }
    return this.fetch('/stats');
  }

  async getStatsHistory(interval: string = '5m'): Promise<TrafficPoint[]> {
    if (this.useMock) {
      return generateTrafficHistory();
    }
    const response: StatsHistoryResponse = await this.fetch(`/stats/history?interval=${interval}`);
    return response.data_points;
  }

  // Devices
  async getDevices(params?: {
    vendor?: string;
    ip?: string;
    active?: number;
    sort?: string;
    order?: 'asc' | 'desc';
    limit?: number;
    offset?: number;
  }): Promise<DeviceInfo[]> {
    if (this.useMock) {
      return generateDevices(50);
    }
    const queryParams = new URLSearchParams();
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          queryParams.append(key, String(value));
        }
      });
    }
    const query = queryParams.toString();
    return this.fetch(`/devices${query ? `?${query}` : ''}`);
  }

  async getDevice(mac: string): Promise<DeviceInfo> {
    if (this.useMock) {
      const devices = generateDevices(50);
      return devices.find(d => d.mac === mac) || devices[0];
    }
    return this.fetch(`/devices/${encodeURIComponent(mac)}`);
  }

  async getDeviceDns(mac: string) {
    if (this.useMock) {
      return [
        { domain: 'google.com', count: 45, last_seen: new Date().toISOString() },
        { domain: 'cloudflare.com', count: 32, last_seen: new Date().toISOString() },
        { domain: 'github.com', count: 18, last_seen: new Date().toISOString() },
      ];
    }
    return this.fetch(`/devices/${encodeURIComponent(mac)}/dns`);
  }

  async getDeviceServices(mac: string) {
    if (this.useMock) {
      return [
        { port: 443, service_name: 'HTTPS', protocol: 'TCP', count: 120 },
        { port: 80, service_name: 'HTTP', protocol: 'TCP', count: 45 },
        { port: 53, service_name: 'DNS', protocol: 'UDP', count: 89 },
      ];
    }
    return this.fetch(`/devices/${encodeURIComponent(mac)}/services`);
  }

  async getDevicePatterns(mac: string): Promise<CommunicationPattern[]> {
    if (this.useMock) {
      return generatePatterns(20);
    }
    return this.fetch(`/devices/${encodeURIComponent(mac)}/patterns`);
  }

  // Patterns
  async getPatterns(params?: {
    protocol?: string;
    limit?: number;
    offset?: number;
  }): Promise<CommunicationPattern[]> {
    if (this.useMock) {
      return generatePatterns(100);
    }
    const queryParams = new URLSearchParams();
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          queryParams.append(key, String(value));
        }
      });
    }
    const query = queryParams.toString();
    return this.fetch(`/patterns${query ? `?${query}` : ''}`);
  }

  // Interfaces
  async getInterfaces(): Promise<NetworkInterface[]> {
    if (this.useMock) {
      return generateInterfaces();
    }
    return this.fetch('/interfaces');
  }

  // Lookups
  async lookupVendor(mac: string): Promise<VendorLookup> {
    if (this.useMock) {
      const oui = mac.split(':').slice(0, 3).join(':');
      const vendors: Record<string, string> = {
        '00:1A:2B': 'Apple, Inc.',
        'AA:BB:CC': 'Intel Corporation',
        'DE:AD:BE': 'Ubiquiti Networks',
      };
      return { 
        vendor: vendors[oui.toUpperCase()] || 'Unknown Vendor', 
        oui: oui.toUpperCase() 
      };
    }
    return this.fetch(`/lookup/vendor/${encodeURIComponent(mac)}`);
  }

  async lookupService(port: number): Promise<ServiceLookup> {
    if (this.useMock) {
      const services: Record<number, { name: string; desc: string }> = {
        22: { name: 'SSH', desc: 'Secure Shell' },
        80: { name: 'HTTP', desc: 'Hypertext Transfer Protocol' },
        443: { name: 'HTTPS', desc: 'HTTP Secure' },
        53: { name: 'DNS', desc: 'Domain Name System' },
        21: { name: 'FTP', desc: 'File Transfer Protocol' },
      };
      const svc = services[port] || { name: 'Unknown', desc: 'Unknown service' };
      return { port, service_name: svc.name, description: svc.desc };
    }
    return this.fetch(`/lookup/service/${port}`);
  }
}

export const apiClient = new ApiClient();
