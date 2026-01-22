import { cn } from "@/lib/utils";
import { Card } from "@/components/ui/card";

interface NeonCardProps extends React.ComponentProps<typeof Card> {
  neonColor?: "primary" | "secondary" | "accent" | "destructive" | "purple" | "green" | "orange";
  glowing?: boolean;
}

export function NeonCard({ className, neonColor = "primary", glowing = false, children, ...props }: NeonCardProps) {
  const colorMap = {
    primary: "border-primary/30 shadow-primary/5",
    secondary: "border-secondary/50",
    accent: "border-accent/50",
    destructive: "border-destructive/50",
    purple: "border-[hsl(var(--proto-dns))]/30",
    green: "border-[hsl(var(--proto-udp))]/30",
    orange: "border-[hsl(var(--proto-arp))]/30",
  };

  const glowMap = {
    primary: "shadow-[0_0_20px_-5px_hsl(var(--primary)/0.2)]",
    secondary: "",
    accent: "",
    destructive: "shadow-[0_0_20px_-5px_hsl(var(--destructive)/0.2)]",
    purple: "shadow-[0_0_20px_-5px_hsl(var(--proto-dns)/0.2)]",
    green: "shadow-[0_0_20px_-5px_hsl(var(--proto-udp)/0.2)]",
    orange: "shadow-[0_0_20px_-5px_hsl(var(--proto-arp)/0.2)]",
  };

  return (
    <Card 
      className={cn(
        "bg-card/40 backdrop-blur-md border transition-all duration-300",
        colorMap[neonColor],
        glowing && glowMap[neonColor],
        glowing && "hover:border-opacity-80 hover:shadow-lg",
        className
      )}
      {...props}
    >
      {children}
    </Card>
  );
}
