import { Sidebar } from "./Sidebar";
import { Header } from "./Header";
import { Toaster } from "@/components/ui/toaster";

export function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen bg-background font-sans text-foreground overflow-hidden selection:bg-primary/30">
      <Sidebar />
      <div className="flex-1 flex flex-col h-screen overflow-hidden">
        <Header />
        <main className="flex-1 overflow-auto p-6 relative">
          <div className="fixed inset-0 pointer-events-none z-[-1] opacity-20"
               style={{
                 backgroundImage: "radial-gradient(circle at 50% 50%, rgba(59, 130, 246, 0.1) 0%, transparent 50%)"
               }}
          />
          <div className="fixed top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-primary to-transparent opacity-50 z-50 pointer-events-none" />
          {children}
        </main>
      </div>
      <Toaster />
    </div>
  );
}
