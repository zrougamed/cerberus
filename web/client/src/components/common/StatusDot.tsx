import { cn } from "@/lib/utils";

interface StatusDotProps {
  status: "active" | "inactive" | "warning" | "error";
  className?: string;
  animate?: boolean;
}

export function StatusDot({ status, className, animate = false }: StatusDotProps) {
  const colors = {
    active: "bg-green-500",
    inactive: "bg-gray-500",
    warning: "bg-yellow-500",
    error: "bg-red-500",
  };

  return (
    <div className={cn("relative flex items-center justify-center w-2.5 h-2.5", className)}>
      {animate && status === "active" && (
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
      )}
      <span className={cn("relative inline-flex rounded-full h-2 w-2", colors[status])}></span>
    </div>
  );
}
