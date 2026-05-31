import { useState } from "react";
import { Link, useLocation } from "wouter";
import { 
  LayoutDashboard, 
  ShieldCheck, 
  ShieldAlert, 
  Network, 
  Activity, 
  LineChart, 
  Server, 
  FileText, 
  Settings, 
  ChevronLeft, 
  ChevronRight,
  UserCircle,
  Eye,
  Terminal,
  Sparkles
} from "lucide-react";
import { cn } from "@/lib/utils";
import { motion } from "framer-motion";
import { useMonitorStore } from "@/store/monitorStore";

const sidebarItems = [
  { icon: LayoutDashboard, label: "Home", sub: "Command Center", href: "/" },
  { icon: Eye, label: "Monitor", sub: "Live Intercept", href: "/packets" },
  { icon: ShieldAlert, label: "Security", sub: "Threat Matrix", href: "/alerts" },
  { icon: Sparkles, label: "Action Center", sub: "Guided Fixes", href: "/action-center" },
  { icon: Network, label: "Devices", sub: "Node Topology", href: "/network" },
  { icon: Activity, label: "Traffic", sub: "Usage Analysis", href: "/traffic" },
  { icon: LineChart, label: "Insights", sub: "Deep Analytics", href: "/analytics" },
  { icon: Server, label: "System", sub: "Core Health", href: "/system" },
  { icon: FileText, label: "History", sub: "Event Stream", href: "/logs" },
  { icon: UserCircle, label: "Profile", sub: "Operator ID", href: "/profile" },
  { icon: Settings, label: "Settings", sub: "Config", href: "/settings" },
];

export function Sidebar() {
  const [location] = useLocation();
  const [collapsed, setCollapsed] = useState(false);
  const { isConnected } = useMonitorStore();

  return (
    <motion.div 
      initial={false}
      animate={{ width: collapsed ? 80 : 260 }}
      className="h-screen bg-card/80 border-r border-border/40 flex flex-col z-20 relative glass-panel overflow-hidden"
    >
      <div className="h-20 flex items-center px-6 border-b border-border/30">
        <div className="flex items-center gap-3 overflow-hidden">
          <div className="min-w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center text-primary border border-primary/30 shadow-[0_0_15px_rgba(0,184,217,0.2)]">
            <ShieldCheck size={24} />
          </div>
          <motion.div 
            animate={{ opacity: collapsed ? 0 : 1, x: collapsed ? -20 : 0 }}
            className="font-sans font-bold text-xl tracking-tight text-foreground whitespace-nowrap"
          >
            Packet<span className="text-primary italic">Peeper</span>
          </motion.div>
        </div>
      </div>

      <div className="flex-1 py-6 px-3 space-y-2 overflow-y-auto overflow-x-hidden scrollbar-none">
        {sidebarItems.map((item) => {
          const isActive = location === item.href;
          return (
            <Link key={item.href} href={item.href}>
              <div
                className={cn(
                  "flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-300 cursor-pointer group relative overflow-hidden",
                  isActive 
                    ? "bg-primary/10 text-primary border border-primary/20" 
                    : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
                )}
              >
                {isActive && (
                  <motion.div
                    layoutId="sidebar-active"
                    className="absolute left-0 top-0 bottom-0 w-1 bg-primary shadow-[0_0_10px_#00d4ff]"
                  />
                )}
                <item.icon size={20} className="shrink-0 relative z-10" />
                <motion.div
                  animate={{ opacity: collapsed ? 0 : 1, x: collapsed ? -10 : 0 }}
                  className="flex flex-col relative z-10"
                >
                  <span className="font-bold text-sm leading-none">{item.label}</span>
                  <span className="text-[10px] text-muted-foreground font-mono mt-1 opacity-60 uppercase tracking-tighter">
                    {item.sub}
                  </span>
                </motion.div>
              </div>
            </Link>
          );
        })}
      </div>

      <div className="p-4 bg-black/20">
        {!collapsed && (
          <div className="mb-4 px-3 py-2 rounded bg-primary/5 border border-primary/10 flex items-center gap-3">
             <Terminal size={14} className="text-primary" />
             <div className="text-[10px] font-mono text-primary font-bold uppercase tracking-widest truncate">
               {isConnected ? "● Connected" : "○ Disconnected"}
             </div>
          </div>
        )}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="w-full flex items-center justify-center p-2 rounded hover:bg-white/5 text-muted-foreground transition-all"
        >
          {collapsed ? <ChevronRight size={20} /> : <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.2em]"><ChevronLeft size={16} /> Collapse</div>}
        </button>
      </div>
    </motion.div>
  );
}
