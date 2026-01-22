import { Bell, Search, Settings, Menu } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/common/ThemeToggle";

export function Header() {
  return (
    <header className="h-14 sm:h-16 border-b border-border bg-background/50 backdrop-blur-md px-4 sm:px-6 flex items-center justify-between sticky top-0 z-10">
      <div className="flex items-center gap-3 sm:gap-4 flex-1">
        <Button variant="ghost" size="icon" className="lg:hidden text-muted-foreground">
          <Menu className="w-5 h-5" />
        </Button>
        <div className="relative w-full max-w-xs sm:max-w-sm hidden sm:block">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            type="search"
            placeholder="Search IP, MAC, or Protocol..."
            className="pl-9 bg-secondary/50 border-border focus:border-primary/50 transition-colors text-sm"
          />
        </div>
      </div>

      <div className="flex items-center gap-2 sm:gap-4">
        <div className="hidden sm:flex items-center gap-2 px-2 sm:px-3 py-1 bg-green-500/10 border border-green-500/20 rounded-full text-[10px] sm:text-xs font-mono text-green-500">
          <div className="w-1.5 h-1.5 sm:w-2 sm:h-2 rounded-full bg-green-500 animate-pulse" />
          <span className="hidden md:inline">LIVE CAPTURE</span>
          <span className="md:hidden">LIVE</span>
        </div>
        
        <ThemeToggle />
        
        <Button variant="ghost" size="icon" className="text-muted-foreground hover:text-primary h-8 w-8 sm:h-9 sm:w-9">
          <Bell className="w-4 h-4 sm:w-5 sm:h-5" />
        </Button>
        <Button variant="ghost" size="icon" className="text-muted-foreground hover:text-primary h-8 w-8 sm:h-9 sm:w-9">
          <Settings className="w-4 h-4 sm:w-5 sm:h-5" />
        </Button>
        
        <div className="w-7 h-7 sm:w-8 sm:h-8 rounded bg-primary/20 border border-primary/50 flex items-center justify-center text-primary font-bold text-xs">
          AD
        </div>
      </div>
    </header>
  );
}
