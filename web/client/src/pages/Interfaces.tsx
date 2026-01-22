import { useQuery } from "@tanstack/react-query";
import { Layout } from "@/components/layout/Layout";
import { apiClient } from "@/lib/api";
import { NeonCard } from "@/components/common/NeonCard";
import { Network, Wifi, Server } from "lucide-react";

export default function Interfaces() {
  const { data: interfaces, isLoading } = useQuery({
    queryKey: ['interfaces'],
    queryFn: () => apiClient.getInterfaces(),
    refetchInterval: 10000
  });

  const getIcon = (name: string) => {
    if (name.includes('wlan') || name.includes('wifi')) return Wifi;
    if (name.includes('eth')) return Network;
    return Server;
  };

  return (
    <Layout>
      <div className="space-y-6 animate-in fade-in duration-500">
        <div>
          <h2 className="text-2xl font-bold tracking-tight" data-testid="interfaces-title">Network Interfaces</h2>
          <p className="text-muted-foreground">Status of monitored network adaptors</p>
        </div>

        {isLoading ? (
          <div className="text-center py-8 text-muted-foreground">Loading interfaces...</div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {interfaces?.map((iface) => {
              const Icon = getIcon(iface.name);
              return (
                <NeonCard key={iface.name} className="p-6" neonColor={iface.is_up ? "green" : "destructive"} data-testid={`card-interface-${iface.name}`}>
                  <div className="flex justify-between items-start mb-6">
                    <div className="p-3 bg-secondary/50 rounded-lg border border-border">
                      <Icon className="w-8 h-8 text-foreground" />
                    </div>
                    <div className={`px-2 py-1 rounded-full text-xs font-bold flex items-center gap-1.5 ${
                      iface.is_up ? 'bg-green-500/20 text-green-500' : 'bg-red-500/20 text-red-500'
                    }`}>
                      <span className={`w-2 h-2 rounded-full ${iface.is_up ? 'bg-green-500' : 'bg-red-500'}`} />
                      {iface.is_up ? 'UP' : 'DOWN'}
                    </div>
                  </div>

                  <div className="space-y-4">
                    <div>
                      <h3 className="text-xl font-bold font-mono">{iface.name}</h3>
                      <p className="text-sm text-muted-foreground font-mono">{iface.mac}</p>
                    </div>

                    <div className="space-y-2 pt-4 border-t border-border/50">
                      <div className="flex justify-between text-sm">
                        <span className="text-muted-foreground">IP Address</span>
                        <span className="font-mono">{iface.ips[0] || '-'}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-muted-foreground">Packets</span>
                        <span className="font-mono">{iface.packets_captured.toLocaleString()}</span>
                      </div>
                    </div>

                    <div className="h-16 mt-4 flex items-end gap-1">
                      {Array.from({ length: 20 }).map((_, i) => (
                        <div 
                          key={i} 
                          className={`flex-1 rounded-t-sm ${iface.is_up ? 'bg-primary/50' : 'bg-secondary'}`}
                          style={{ height: `${Math.random() * 100}%`, opacity: 0.3 + (i / 40) }}
                        />
                      ))}
                    </div>
                  </div>
                </NeonCard>
              );
            })}
          </div>
        )}
      </div>
    </Layout>
  );
}
