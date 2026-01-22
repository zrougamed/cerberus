import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip, Legend } from 'recharts';
import { NeonCard } from '@/components/common/NeonCard';
import { ProtocolDistribution } from '@/types';

interface ProtocolChartProps {
  data: ProtocolDistribution[];
}

export function ProtocolChart({ data }: ProtocolChartProps) {
  return (
    <NeonCard className="p-4 sm:p-6" glowing neonColor="purple">
      <div className="mb-4 sm:mb-6">
        <h3 className="text-base sm:text-lg font-semibold tracking-tight">Protocol Distribution</h3>
        <p className="text-xs sm:text-sm text-muted-foreground">Traffic breakdown by protocol</p>
      </div>

      <div className="h-[250px] sm:h-[300px]">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius="40%"
              outerRadius="60%"
              paddingAngle={3}
              dataKey="value"
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} stroke="rgba(0,0,0,0.5)" strokeWidth={1} />
              ))}
            </Pie>
            <Tooltip 
               contentStyle={{ 
                backgroundColor: 'hsl(var(--card))', 
                borderColor: 'hsl(var(--border))',
                borderRadius: '8px',
                color: 'hsl(var(--foreground))',
                fontSize: '12px'
              }}
              itemStyle={{ color: 'hsl(var(--foreground))' }}
            />
            <Legend 
              layout="horizontal"
              verticalAlign="bottom"
              align="center"
              iconType="circle"
              iconSize={8}
              wrapperStyle={{ fontSize: '11px' }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </NeonCard>
  );
}
