import { useRoute } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { Layout } from "@/components/layout/Layout";
import { apiClient } from "@/lib/api";
import { NeonCard } from "@/components/common/NeonCard";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ChevronLeft, Monitor, Activity, Shield, Globe, Lock } from "lucide-react";
import { Link } from "wouter";
import { TrafficChart } from "@/components/charts/TrafficChart";
import { ActivityFeed } from "@/components/dashboard/ActivityFeed";
import { ProtocolChart } from "@/components/charts/ProtocolChart";

export default function DeviceDetail() {
  const [, params] = useRoute("/devices/:mac");
  const mac = decodeURIComponent(params?.mac || "");

  const { data: device, isLoading } = useQuery({
    queryKey: ['device', mac],
    queryFn: () => apiClient.getDevice(mac),
    enabled: !!mac
  });

  const { data: traffic } = useQuery({
    queryKey: ['traffic-device', mac],
    queryFn: () => apiClient.getStatsHistory('5m'),
    enabled: !!mac
  });
  
  const { data: patterns } = useQuery({
    queryKey: ['patterns-device', mac],
    queryFn: () => apiClient.getDevicePatterns(mac),
    enabled: !!mac
  });

  if (isLoading) {
    return (
      <Layout>
        <div className="flex items-center justify-center h-64 text-muted-foreground">
          Loading device details...
        </div>
      </Layout>
    );
  }

  if (!device) {
    return (
      <Layout>
        <div className="flex items-center justify-center h-64 text-muted-foreground">
          Device not found
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="space-y-6 animate-in fade-in duration-500">
        <div className="flex items-center gap-4">
          <Link href="/devices">
            <Button variant="outline" size="icon" data-testid="button-back">
              <ChevronLeft className="w-4 h-4" />
            </Button>
          </Link>
          <div>
            <h2 className="text-2xl font-bold tracking-tight flex items-center gap-3" data-testid="device-mac">
              <Monitor className="w-6 h-6 text-primary" />
              {device.mac}
            </h2>
            <div className="flex items-center gap-2 text-muted-foreground font-mono text-sm">
              <span data-testid="device-ip">{device.ip}</span>
              <span>•</span>
              <span data-testid="device-vendor">{device.vendor}</span>
            </div>
          </div>
          <div className="ml-auto flex gap-2">
            <Badge variant="outline" className={device.is_active ? "text-green-500 border-green-500/50" : "text-gray-500"}>
              {device.is_active ? "ACTIVE" : "OFFLINE"}
            </Badge>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <NeonCard className="p-4" neonColor="primary">
            <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Total Traffic</div>
            <div className="text-xl font-bold font-mono">{((device.bytes_sent + device.bytes_received) / 1024 / 1024).toFixed(2)} MB</div>
            <div className="text-xs text-primary mt-1 flex items-center gap-1">
              <Activity className="w-3 h-3" /> Real-time
            </div>
          </NeonCard>
          <NeonCard className="p-4" neonColor="purple">
             <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1">DNS Queries</div>
             <div className="text-xl font-bold font-mono">{device.dns_queries}</div>
             <div className="text-xs text-purple-500 mt-1 flex items-center gap-1">
               <Globe className="w-3 h-3" /> Top: google.com
             </div>
          </NeonCard>
          <NeonCard className="p-4" neonColor="green">
             <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Open Ports</div>
             <div className="text-xl font-bold font-mono">3</div>
             <div className="text-xs text-green-500 mt-1 flex items-center gap-1">
               <Shield className="w-3 h-3" /> 80, 443, 22
             </div>
          </NeonCard>
          <NeonCard className="p-4" neonColor="destructive">
             <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Threat Score</div>
             <div className="text-xl font-bold font-mono">Low</div>
             <div className="text-xs text-muted-foreground mt-1 flex items-center gap-1">
               <Lock className="w-3 h-3" /> No alerts
             </div>
          </NeonCard>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <TrafficChart data={traffic || []} height={300} />
          </div>
          <div>
            <ProtocolChart data={[
              { name: 'HTTPS', value: 60, color: 'hsl(var(--proto-tls))' },
              { name: 'DNS', value: 15, color: 'hsl(var(--proto-dns))' },
              { name: 'Other', value: 25, color: 'hsl(var(--muted))' }
            ]} />
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 h-[400px]">
          <ActivityFeed patterns={patterns || []} />
          
          <NeonCard className="p-6" neonColor="secondary">
             <h3 className="font-semibold mb-4">Connection History</h3>
             <div className="space-y-4">
               {[1,2,3,4,5].map(i => (
                 <div key={i} className="flex justify-between items-center text-sm border-b border-border/50 pb-2">
                   <div className="flex items-center gap-3">
                     <div className="w-1.5 h-1.5 rounded-full bg-blue-500" />
                     <span className="font-mono text-muted-foreground">192.168.1.{100+i}</span>
                   </div>
                   <span className="text-xs text-muted-foreground">TCP : 443</span>
                   <span className="text-xs text-muted-foreground">2m ago</span>
                 </div>
               ))}
             </div>
          </NeonCard>
        </div>
      </div>
    </Layout>
  );
}
