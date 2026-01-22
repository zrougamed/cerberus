import { Layout } from "@/components/layout/Layout";
import { NeonCard } from "@/components/common/NeonCard";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Search, Loader2 } from "lucide-react";
import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { apiClient } from "@/lib/api";
import { VendorLookup, ServiceLookup } from "@/types";

export default function Lookup() {
  const [macInput, setMacInput] = useState("");
  const [portInput, setPortInput] = useState("");

  const vendorMutation = useMutation({
    mutationFn: (mac: string) => apiClient.lookupVendor(mac)
  });

  const serviceMutation = useMutation({
    mutationFn: (port: number) => apiClient.lookupService(port)
  });

  const handleMacLookup = () => {
    if (macInput.trim()) {
      vendorMutation.mutate(macInput.trim());
    }
  };

  const handlePortLookup = () => {
    const port = parseInt(portInput);
    if (!isNaN(port) && port > 0 && port <= 65535) {
      serviceMutation.mutate(port);
    }
  };

  return (
    <Layout>
      <div className="space-y-8 animate-in fade-in duration-500 max-w-4xl mx-auto">
        <div className="text-center space-y-2">
          <h2 className="text-3xl font-bold tracking-tight" data-testid="lookup-title">Diagnostic Tools</h2>
          <p className="text-muted-foreground">Lookup vendors, services, and DNS records</p>
        </div>

        <div className="grid gap-8">
          <NeonCard className="p-8" neonColor="primary">
            <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
              <Search className="w-5 h-5 text-primary" />
              MAC Vendor Lookup
            </h3>
            <div className="flex gap-4">
              <Input 
                placeholder="Enter MAC Address (e.g. 00:1A:2B:3C:4D:5E)" 
                className="font-mono" 
                value={macInput}
                onChange={(e) => setMacInput(e.target.value)}
                data-testid="input-mac"
              />
              <Button onClick={handleMacLookup} disabled={vendorMutation.isPending} data-testid="button-lookup-mac">
                {vendorMutation.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                Search
              </Button>
            </div>
            {vendorMutation.data && (
              <div className="mt-6 p-4 bg-primary/10 border border-primary/20 rounded-lg animate-in slide-in-from-top-2">
                <div className="text-sm text-muted-foreground mb-1">Vendor Found</div>
                <div className="text-xl font-bold text-primary" data-testid="result-vendor">{vendorMutation.data.vendor}</div>
                <div className="text-xs font-mono text-muted-foreground mt-2">OUI: {vendorMutation.data.oui}</div>
              </div>
            )}
            {vendorMutation.isError && (
              <div className="mt-6 p-4 bg-destructive/10 border border-destructive/20 rounded-lg text-destructive">
                Vendor not found or lookup failed
              </div>
            )}
          </NeonCard>

          <NeonCard className="p-8" neonColor="purple">
            <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
              <Search className="w-5 h-5 text-purple-500" />
              Port Service Lookup
            </h3>
            <div className="flex gap-4">
              <Input 
                placeholder="Enter Port Number (e.g. 80)" 
                type="number" 
                className="font-mono"
                value={portInput}
                onChange={(e) => setPortInput(e.target.value)}
                data-testid="input-port"
              />
              <Button variant="secondary" onClick={handlePortLookup} disabled={serviceMutation.isPending} data-testid="button-lookup-port">
                {serviceMutation.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                Search
              </Button>
            </div>
            {serviceMutation.data && (
              <div className="mt-6 p-4 bg-purple-500/10 border border-purple-500/20 rounded-lg animate-in slide-in-from-top-2">
                <div className="text-sm text-muted-foreground mb-1">Service Found</div>
                <div className="text-xl font-bold text-purple-500" data-testid="result-service">{serviceMutation.data.service_name}</div>
                <div className="text-sm text-muted-foreground mt-2">{serviceMutation.data.description}</div>
                <div className="text-xs font-mono text-muted-foreground mt-1">Port: {serviceMutation.data.port}</div>
              </div>
            )}
            {serviceMutation.isError && (
              <div className="mt-6 p-4 bg-destructive/10 border border-destructive/20 rounded-lg text-destructive">
                Service not found or lookup failed
              </div>
            )}
          </NeonCard>
        </div>
      </div>
    </Layout>
  );
}
