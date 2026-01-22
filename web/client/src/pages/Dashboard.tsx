import { useQuery } from "@tanstack/react-query";
import { Layout } from "@/components/layout/Layout";
import { StatsGrid } from "@/components/dashboard/StatsGrid";
import { TrafficChart } from "@/components/charts/TrafficChart";
import { ProtocolChart } from "@/components/charts/ProtocolChart";
import { ActivityFeed } from "@/components/dashboard/ActivityFeed";
import { apiClient } from "@/lib/api";
import { ProtocolDistribution } from "@/types";
import { Loader2, AlertCircle } from "lucide-react";

export default function Dashboard() {
  const { data: stats, isLoading: statsLoading, error: statsError } = useQuery({
    queryKey: ['stats'],
    queryFn: () => apiClient.getStats(),
    refetchInterval: 5000
  });

  const { data: trafficData, isLoading: trafficLoading } = useQuery({
    queryKey: ['traffic'],
    queryFn: () => apiClient.getStatsHistory('5m'),
    refetchInterval: 5000
  });

  const { data: patterns, isLoading: patternsLoading } = useQuery({
    queryKey: ['patterns-live'],
    queryFn: () => apiClient.getPatterns({ limit: 20 }),
    refetchInterval: 3000
  });

  const protocolData: ProtocolDistribution[] = stats ? [
    { name: 'TCP', value: stats.tcp_packets, color: 'hsl(var(--proto-tcp))' },
    { name: 'UDP', value: stats.udp_packets, color: 'hsl(var(--proto-udp))' },
    { name: 'HTTP', value: stats.http_packets, color: 'hsl(var(--proto-http))' },
    { name: 'DNS', value: stats.dns_packets, color: 'hsl(var(--proto-dns))' },
    { name: 'TLS', value: stats.tls_packets, color: 'hsl(var(--proto-tls))' },
  ] : [];

  const isLoading = statsLoading || trafficLoading || patternsLoading;

  if (statsError) {
    return (
      <Layout>
        <div className="flex flex-col items-center justify-center h-64 text-muted-foreground gap-4">
          <AlertCircle className="w-12 h-12 text-destructive" />
          <p>Failed to connect to Cerberus backend</p>
          <p className="text-sm">Check that the backend service is running</p>
        </div>
      </Layout>
    );
  }

  if (isLoading && !stats) {
    return (
      <Layout>
        <div className="flex items-center justify-center h-64 text-muted-foreground gap-2">
          <Loader2 className="w-6 h-6 animate-spin" />
          <span>Loading dashboard data...</span>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="space-y-6 animate-in fade-in duration-500">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
          <h2 className="text-xl sm:text-2xl font-bold tracking-tight" data-testid="dashboard-title">Dashboard Overview</h2>
          <div className="text-xs sm:text-sm text-muted-foreground font-mono" data-testid="last-updated">
            Last updated: {new Date().toLocaleTimeString()}
          </div>
        </div>

        {stats && <StatsGrid stats={stats} />}

        <div className="grid grid-cols-1 xl:grid-cols-4 gap-4 lg:gap-6">
          <div className="xl:col-span-3 h-[300px] sm:h-[350px] lg:h-[400px]">
            <TrafficChart data={trafficData || []} height={undefined} />
          </div>
          <div className="xl:col-span-1 h-[350px] lg:h-[400px]">
            <ActivityFeed patterns={patterns || []} />
          </div>
        </div>

        <div className="w-full">
          <ProtocolChart data={protocolData} />
        </div>
      </div>
    </Layout>
  );
}
