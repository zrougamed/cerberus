import { Link, useLocation } from "wouter";
import { cn } from "@/lib/utils";
import { LayoutDashboard, Monitor, Activity, Network, Search } from "lucide-react";

export function Sidebar() {
  const [location] = useLocation();

  const navItems = [
    { icon: LayoutDashboard, label: "Dashboard", href: "/" },
    { icon: Monitor, label: "Devices", href: "/devices" },
    { icon: Activity, label: "Patterns", href: "/patterns" },
    { icon: Network, label: "Interfaces", href: "/interfaces" },
    { icon: Search, label: "Lookup", href: "/lookup" },
  ];

  return (
    <div className="hidden lg:flex flex-col w-56 xl:w-64 border-r border-sidebar-border bg-sidebar h-screen sticky top-0 shrink-0">
      <div className="p-4 xl:p-6 flex items-center gap-3">
        <div className="w-7 h-7 xl:w-8 xl:h-8 bg-primary/20 border border-primary/50 rounded flex items-center justify-center">
          <Activity className="w-4 h-4 xl:w-5 xl:h-5 text-primary" />
        </div>
        <h1 className="text-lg xl:text-xl font-bold tracking-tighter text-foreground">
          CERBERUS
          <span className="text-primary text-[10px] xl:text-xs ml-1 align-top">v1.0</span>
        </h1>
      </div>

      <nav className="flex-1 px-3 xl:px-4 space-y-1.5 xl:space-y-2 py-4">
        {navItems.map((item) => {
          const isActive = location === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-2 xl:gap-3 px-3 xl:px-4 py-2.5 xl:py-3 rounded-md text-sm font-medium transition-all duration-200 group relative overflow-hidden",
                isActive
                  ? "text-primary bg-primary/10 border border-primary/20 shadow-[0_0_15px_rgba(59,130,246,0.15)]"
                  : "text-muted-foreground hover:text-foreground hover:bg-sidebar-accent/50"
              )}
            >
              {isActive && (
                <div className="absolute left-0 top-0 bottom-0 w-1 bg-primary shadow-[0_0_10px_rgba(59,130,246,0.8)]" />
              )}
              <item.icon className={cn("w-4 h-4 xl:w-5 xl:h-5", isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground")} />
              {item.label}
            </Link>
          );
        })}
      </nav>

      <div className="p-3 xl:p-4 border-t border-sidebar-border">
        <div className="bg-card/50 rounded-lg p-2.5 xl:p-3 text-[10px] xl:text-xs text-muted-foreground border border-border/50">
          <div className="flex justify-between mb-1">
            <span>System Status</span>
            <span className="text-green-500 font-mono">ONLINE</span>
          </div>
          <div className="w-full bg-secondary h-1.5 rounded-full overflow-hidden">
            <div className="bg-green-500 w-full h-full animate-pulse" />
          </div>
          <div className="mt-2 font-mono opacity-70">
            UP: 3d 14h 22m
          </div>
        </div>
      </div>
    </div>
  );
}
