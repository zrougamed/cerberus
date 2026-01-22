import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts';
import { NeonCard } from '@/components/common/NeonCard';
import { TrafficPoint } from '@/types';
import { format, parseISO } from 'date-fns';

interface TrafficChartProps {
  data: TrafficPoint[];
  height?: number;
}

export function TrafficChart({ data, height }: TrafficChartProps) {
  // Transform data to include formatted time for display
  const chartData = data.map(point => ({
    ...point,
    time: format(parseISO(point.timestamp), 'HH:mm'),
  }));

  return (
    <NeonCard className="p-4 sm:p-6 h-full flex flex-col" glowing neonColor="primary">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 mb-4 sm:mb-6">
        <div>
          <h3 className="text-base sm:text-lg font-semibold tracking-tight">Network Traffic</h3>
          <p className="text-xs sm:text-sm text-muted-foreground">Packets over time by protocol</p>
        </div>
        <div className="flex gap-2 text-xs">
          <span className="px-2 py-1 bg-primary/10 text-primary rounded border border-primary/20">Live</span>
        </div>
      </div>
      
      <div className="flex-1 min-h-0" style={height ? { height } : undefined}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData} margin={{ top: 5, right: 5, left: -20, bottom: 5 }}>
            <defs>
              <linearGradient id="colorTcp" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="hsl(217, 91%, 60%)" stopOpacity={0.3}/>
                <stop offset="95%" stopColor="hsl(217, 91%, 60%)" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="colorUdp" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="hsl(142, 71%, 45%)" stopOpacity={0.3}/>
                <stop offset="95%" stopColor="hsl(142, 71%, 45%)" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
            <XAxis 
              dataKey="time" 
              stroke="hsl(var(--muted-foreground))" 
              fontSize={10}
              tickLine={false}
              axisLine={false}
              interval="preserveStartEnd"
            />
            <YAxis 
              stroke="hsl(var(--muted-foreground))" 
              fontSize={10}
              tickLine={false}
              axisLine={false}
              width={50}
              tickFormatter={(value) => value >= 1000 ? `${(value / 1000).toFixed(0)}k` : value}
            />
            <Tooltip 
              contentStyle={{ 
                backgroundColor: 'hsl(var(--card))', 
                borderColor: 'hsl(var(--border))',
                borderRadius: '8px',
                color: 'hsl(var(--foreground))',
                fontSize: '12px'
              }}
              formatter={(value: number) => [value.toLocaleString(), '']}
            />
            <Legend 
              verticalAlign="top" 
              height={36}
              iconType="line"
              formatter={(value) => <span className="text-xs text-muted-foreground">{value}</span>}
            />
            <Area 
              type="monotone" 
              dataKey="tcp_packets" 
              name="TCP"
              stroke="hsl(217, 91%, 60%)" 
              strokeWidth={2}
              fillOpacity={1} 
              fill="url(#colorTcp)" 
            />
            <Area 
              type="monotone" 
              dataKey="udp_packets" 
              name="UDP"
              stroke="hsl(142, 71%, 45%)" 
              strokeWidth={2}
              fillOpacity={1} 
              fill="url(#colorUdp)" 
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </NeonCard>
  );
}
