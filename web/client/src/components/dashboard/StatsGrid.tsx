import { NeonCard } from "@/components/common/NeonCard";
import { NetworkStats } from "@/types";
import { Activity, Shield, Users, Network } from "lucide-react";

interface StatsGridProps {
  stats: NetworkStats;
}

export function StatsGrid({ stats }: StatsGridProps) {
  const cards = [
    {
      label: "Total Packets",
      value: stats.total_packets.toLocaleString(),
      subValue: undefined,
      icon: Activity,
      color: "primary",
      change: "+12%"
    },
    {
      label: "Active Devices",
      value: stats.active_devices.toString(),
      subValue: `/${stats.total_devices}`,
      icon: Users,
      color: "green",
      change: "+2"
    },
    {
      label: "Unique Patterns",
      value: stats.unique_patterns.toString(),
      subValue: undefined,
      icon: Shield,
      color: "purple",
      change: "+5%"
    },
    {
      label: "Interfaces",
      value: stats.interfaces_monitored.toString(),
      subValue: undefined,
      icon: Network,
      color: "orange",
      change: "Stable"
    }
  ] as const;

  const getColorClasses = (color: string) => {
    const map: Record<string, string> = {
      primary: "bg-primary/10 text-primary",
      green: "bg-green-500/10 text-green-500",
      purple: "bg-purple-500/10 text-purple-500",
      orange: "bg-orange-500/10 text-orange-500"
    };
    return map[color] || map.primary;
  };

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 mb-4 sm:mb-6">
      {cards.map((card, i) => (
        <NeonCard key={i} className="p-3 sm:p-4 flex flex-col justify-between" neonColor={card.color as any}>
          <div className="flex justify-between items-start mb-2">
            <div className={`p-1.5 sm:p-2 rounded ${getColorClasses(card.color)}`}>
              <card.icon className="w-4 h-4 sm:w-5 sm:h-5" />
            </div>
            <span className="text-[10px] sm:text-xs font-mono text-muted-foreground bg-secondary/50 px-1 sm:px-1.5 py-0.5 rounded">
              {card.change}
            </span>
          </div>
          <div>
            <div className="text-lg sm:text-2xl font-bold tracking-tight text-foreground flex items-baseline gap-1">
              {card.value}
              {card.subValue && <span className="text-xs sm:text-sm text-muted-foreground font-normal">{card.subValue}</span>}
            </div>
            <div className="text-[10px] sm:text-xs text-muted-foreground mt-1 uppercase tracking-wider font-semibold">
              {card.label}
            </div>
          </div>
        </NeonCard>
      ))}
    </div>
  );
}
