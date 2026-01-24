import { Header } from "./Header";
import { Sidebar } from "./Sidebar";
import { cn } from "@/lib/utils";

interface MainLayoutProps {
  children: React.ReactNode;
  className?: string;
}

export function MainLayout({ children, className }: MainLayoutProps) {
  return (
    <div className="flex h-screen bg-background overflow-hidden font-sans text-foreground selection:bg-primary/30 relative cyber-grid">
      {/* Background Texture - subtle grid pattern */}
      <div 
        className="fixed inset-0 pointer-events-none z-0 opacity-5"
        style={{ 
          backgroundImage: `
            linear-gradient(rgba(0, 184, 217, 0.1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 184, 217, 0.1) 1px, transparent 1px)
          `,
          backgroundSize: '50px 50px'
        }}
      />
      
      {/* Sidebar (Collapsible) */}
      <Sidebar />

      {/* Main Content */}
      <div className="flex-1 flex flex-col relative z-10 overflow-hidden">
        <Header />
        <main className={cn("flex-1 overflow-y-auto p-6 scrollbar-thin scrollbar-thumb-secondary scrollbar-track-transparent", className)}>
          <div className="max-w-[1500px] mx-auto w-full space-y-8">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
