import { NeonCard } from "@/components/common/NeonCard";
import { CommunicationPattern } from "@/types";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";

interface ActivityFeedProps {
  patterns: CommunicationPattern[];
}

export function ActivityFeed({ patterns }: ActivityFeedProps) {
  const getProtocolColor = (proto: string) => {
    switch (proto) {
      case 'TCP': return 'bg-blue-500/20 text-blue-500 border-blue-500/50';
      case 'UDP': return 'bg-green-500/20 text-green-500 border-green-500/50';
      case 'DNS': return 'bg-purple-500/20 text-purple-500 border-purple-500/50';
      case 'HTTP': return 'bg-cyan-500/20 text-cyan-500 border-cyan-500/50';
      case 'TLS': return 'bg-pink-500/20 text-pink-500 border-pink-500/50';
      case 'ARP': return 'bg-orange-500/20 text-orange-500 border-orange-500/50';
      default: return 'bg-gray-500/20 text-gray-500 border-gray-500/50';
    }
  };

  return (
    <NeonCard className="h-full flex flex-col" neonColor="accent">
      <div className="p-3 sm:p-4 border-b border-border flex justify-between items-center">
        <h3 className="text-sm sm:text-base font-semibold flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
          <span className="hidden sm:inline">Live Activity Feed</span>
          <span className="sm:hidden">Live Feed</span>
        </h3>
        <Badge variant="outline" className="font-mono text-[10px]">REALTIME</Badge>
      </div>
      <ScrollArea className="flex-1 p-0">
        <div className="divide-y divide-border/50">
          {patterns.map((pattern) => (
            <div key={pattern.id} className="p-2 sm:p-3 hover:bg-white/5 transition-colors text-xs font-mono group cursor-pointer">
              <div className="flex justify-between items-center mb-1">
                <span className={`px-1.5 py-0.5 rounded border text-[10px] font-bold ${getProtocolColor(pattern.protocol)}`}>
                  {pattern.protocol}
                </span>
                <span className="text-muted-foreground opacity-70 group-hover:opacity-100 transition-opacity text-[10px] sm:text-xs">
                  {new Date(pattern.timestamp).toLocaleTimeString()}
                </span>
              </div>
              <div className="grid grid-cols-[1fr_auto_1fr] gap-1 sm:gap-2 items-center text-muted-foreground">
                <span className="truncate text-right text-foreground text-[10px] sm:text-xs">{pattern.src_ip}</span>
                <span className="text-muted-foreground/50">→</span>
                <span className="truncate text-left text-foreground text-[10px] sm:text-xs">
                  {pattern.dst_ip}
                  <span className="text-muted-foreground opacity-70">:{pattern.dst_port}</span>
                </span>
              </div>
            </div>
          ))}
        </div>
      </ScrollArea>
    </NeonCard>
  );
}
