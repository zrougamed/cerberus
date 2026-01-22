import { useQuery } from "@tanstack/react-query";
import { Layout } from "@/components/layout/Layout";
import { apiClient } from "@/lib/api";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { NeonCard } from "@/components/common/NeonCard";
import { Search, Filter, MoreHorizontal } from "lucide-react";
import { StatusDot } from "@/components/common/StatusDot";
import { useLocation } from "wouter";

export default function Devices() {
  const [, setLocation] = useLocation();
  const { data: devices, isLoading } = useQuery({
    queryKey: ['devices'],
    queryFn: () => apiClient.getDevices({ limit: 100 }),
    refetchInterval: 10000
  });

  return (
    <Layout>
      <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
        <div className="flex justify-between items-end">
          <div>
            <h2 className="text-2xl font-bold tracking-tight" data-testid="devices-title">Network Devices</h2>
            <p className="text-muted-foreground">Manage and monitor connected endpoints</p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" data-testid="button-export">Export CSV</Button>
            <Button data-testid="button-add-device">Add Device</Button>
          </div>
        </div>

        <NeonCard className="p-4" neonColor="secondary">
          <div className="flex gap-4 mb-4">
            <div className="relative flex-1">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input placeholder="Search MAC, IP, or Vendor..." className="pl-9" data-testid="input-search" />
            </div>
            <Button variant="outline" size="icon" data-testid="button-filter">
              <Filter className="h-4 w-4" />
            </Button>
          </div>

          <div className="rounded-md border border-border/50 overflow-hidden">
            <Table>
              <TableHeader className="bg-secondary/50">
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-[50px]"></TableHead>
                  <TableHead>Device Info</TableHead>
                  <TableHead>IP Address</TableHead>
                  <TableHead>Vendor</TableHead>
                  <TableHead>Activity</TableHead>
                  <TableHead>Last Seen</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                      Loading devices...
                    </TableCell>
                  </TableRow>
                ) : devices?.map((device) => (
                  <TableRow 
                    key={device.mac} 
                    className="group hover:bg-secondary/30 transition-colors cursor-pointer"
                    onClick={() => setLocation(`/devices/${encodeURIComponent(device.mac)}`)}
                    data-testid={`row-device-${device.mac}`}
                  >
                    <TableCell>
                      <StatusDot status={device.is_active ? 'active' : 'inactive'} animate={device.is_active} />
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-mono font-medium text-foreground">{device.mac}</span>
                        <span className="text-xs text-muted-foreground">{device.interface}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-primary/80">{device.ip}</span>
                    </TableCell>
                    <TableCell>{device.vendor}</TableCell>
                    <TableCell>
                      <div className="flex gap-2 text-xs font-mono">
                        <Badge variant="outline" className="border-blue-500/30 text-blue-500 bg-blue-500/5">
                          T: {device.tcp_connections}
                        </Badge>
                        <Badge variant="outline" className="border-green-500/30 text-green-500 bg-green-500/5">
                          U: {device.udp_connections}
                        </Badge>
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {new Date(device.last_seen).toLocaleTimeString()}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="icon" className="opacity-0 group-hover:opacity-100 transition-opacity">
                        <MoreHorizontal className="w-4 h-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </NeonCard>
      </div>
    </Layout>
  );
}
