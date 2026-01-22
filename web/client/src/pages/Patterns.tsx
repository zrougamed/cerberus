import { useQuery } from "@tanstack/react-query";
import { Layout } from "@/components/layout/Layout";
import { apiClient } from "@/lib/api";
import { NeonCard } from "@/components/common/NeonCard";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Pause, Filter, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

export default function Patterns() {
  const { data: patterns, isLoading } = useQuery({
    queryKey: ['patterns-full'],
    queryFn: () => apiClient.getPatterns({ limit: 100 }),
    refetchInterval: 3000
  });

  const getProtocolColor = (proto: string) => {
    switch (proto) {
      case 'TCP': return 'text-blue-500 border-blue-500/30 bg-blue-500/10';
      case 'UDP': return 'text-green-500 border-green-500/30 bg-green-500/10';
      case 'DNS': return 'text-purple-500 border-purple-500/30 bg-purple-500/10';
      case 'HTTP': return 'text-cyan-500 border-cyan-500/30 bg-cyan-500/10';
      case 'TLS': return 'text-pink-500 border-pink-500/30 bg-pink-500/10';
      case 'ARP': return 'text-orange-500 border-orange-500/30 bg-orange-500/10';
      default: return 'text-gray-500 border-gray-500/30 bg-gray-500/10';
    }
  };

  return (
    <Layout>
      <div className="h-[calc(100vh-100px)] flex flex-col space-y-4 animate-in fade-in duration-500">
        <div className="flex justify-between items-center">
          <div>
            <h2 className="text-2xl font-bold tracking-tight" data-testid="patterns-title">Traffic Patterns</h2>
            <p className="text-muted-foreground">Live stream of network communication events</p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" data-testid="button-pause">
              <Pause className="w-4 h-4 mr-2" /> Pause Stream
            </Button>
            <Button variant="outline" size="sm" data-testid="button-filter-patterns">
              <Filter className="w-4 h-4 mr-2" /> Filter
            </Button>
            <Button variant="outline" size="sm" data-testid="button-export-patterns">
              <Download className="w-4 h-4 mr-2" /> Export
            </Button>
          </div>
        </div>

        <NeonCard className="flex-1 overflow-hidden flex flex-col p-0" neonColor="accent">
          <div className="grid grid-cols-12 gap-4 p-4 border-b border-border bg-muted/20 font-medium text-sm text-muted-foreground">
            <div className="col-span-1">Time</div>
            <div className="col-span-1">Proto</div>
            <div className="col-span-2">Source IP</div>
            <div className="col-span-1 text-center">Dir</div>
            <div className="col-span-2">Dest IP</div>
            <div className="col-span-1">Port</div>
            <div className="col-span-2">Service</div>
            <div className="col-span-2">Info</div>
          </div>
          
          <ScrollArea className="flex-1">
            {isLoading ? (
              <div className="p-8 text-center text-muted-foreground">Loading patterns...</div>
            ) : (
              <div className="divide-y divide-border/30 font-mono text-sm">
                {patterns?.map((pattern) => (
                  <div key={pattern.id} className="grid grid-cols-12 gap-4 p-3 hover:bg-white/5 transition-colors items-center" data-testid={`row-pattern-${pattern.id}`}>
                    <div className="col-span-1 text-muted-foreground text-xs">
                      {new Date(pattern.timestamp).toLocaleTimeString()}
                    </div>
                    <div className="col-span-1">
                      <Badge variant="outline" className={`font-bold ${getProtocolColor(pattern.protocol)}`}>
                        {pattern.protocol}
                      </Badge>
                    </div>
                    <div className="col-span-2 text-foreground/90">{pattern.src_ip}</div>
                    <div className="col-span-1 text-center text-muted-foreground">→</div>
                    <div className="col-span-2 text-foreground/90">{pattern.dst_ip}</div>
                    <div className="col-span-1 text-muted-foreground">{pattern.dst_port}</div>
                    <div className="col-span-2 text-xs opacity-80">{pattern.service_name || '-'}</div>
                    <div className="col-span-2 text-xs truncate text-muted-foreground">{pattern.info}</div>
                  </div>
                ))}
              </div>
            )}
          </ScrollArea>
        </NeonCard>
      </div>
    </Layout>
  );
}
