import { MainLayout } from "@/components/layout/MainLayout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Cpu, Database, HardDrive, Wifi, ShieldCheck, Zap, RefreshCw, Activity, Server } from "lucide-react";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { useMonitorStore } from "@/store/monitorStore";
import { apiService } from "@/services/apiService";
import { useState, useEffect } from "react";
import { motion } from "framer-motion";

interface SystemInfo {
  cpu_percent: number;
  memory: { total: number; available: number; percent: number };
  disk: { total: number; used: number; percent: number };
}

export default function SystemStats() {
  const { isConnected, stats } = useMonitorStore();
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchSystemInfo = async () => {
    setLoading(true);
    try {
      const data = await apiService.getSystemInfo();
      setSystemInfo(data);
    } catch (err) {
      console.error('Failed to fetch system info:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSystemInfo();
    const interval = setInterval(fetchSystemInfo, 10000); // Refresh every 10s
    return () => clearInterval(interval);
  }, []);

  const formatBytes = (bytes: number) => {
    if (!bytes) return '0 GB';
    return (bytes / 1024 / 1024 / 1024).toFixed(1) + ' GB';
  };
  
  return (
    <MainLayout>
      <div className="space-y-6">
        <motion.div 
          className="flex items-center justify-between"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <div>
            <h1 className="text-3xl font-bold text-foreground flex items-center gap-3">
              <Server className="text-primary" />
              System Health
            </h1>
            <p className="text-muted-foreground text-lg flex items-center gap-2 mt-1">
              <Activity size={16} className="text-primary animate-pulse" />
              Checking the pulse of your security infrastructure
            </p>
          </div>
          <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
            <Button 
              variant="outline" 
              className="rounded-full gap-2 hover:border-primary/50 transition-all" 
              onClick={fetchSystemInfo}
              disabled={loading}
            >
              <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} />
              Refresh
            </Button>
          </motion.div>
        </motion.div>

        <div className="grid gap-6 md:grid-cols-3">
          {[
            { 
              title: "Processing Power", 
              value: systemInfo ? `${systemInfo.cpu_percent}%` : '...', 
              status: systemInfo?.cpu_percent && systemInfo.cpu_percent < 70 ? "Running Cool" : "Under Load", 
              icon: Cpu, 
              color: "text-primary",
              progress: systemInfo?.cpu_percent || 0,
              delay: 0.1
            },
            { 
              title: "Memory Usage", 
              value: systemInfo ? formatBytes(systemInfo.memory.total - systemInfo.memory.available) : '...', 
              status: systemInfo?.memory?.percent && systemInfo.memory.percent < 80 ? "Optimal" : "High Usage", 
              icon: Database, 
              color: "text-emerald-500",
              progress: systemInfo?.memory?.percent || 0,
              delay: 0.2
            },
            { 
              title: "Storage Space", 
              value: systemInfo ? `${systemInfo.disk.percent}%` : '...', 
              status: systemInfo?.disk?.percent && systemInfo.disk.percent < 90 ? "Healthy" : "Nearly Full", 
              icon: HardDrive, 
              color: "text-blue-500",
              progress: systemInfo?.disk?.percent || 0,
              delay: 0.3
            }
          ].map((card) => (
            <motion.div
              key={card.title}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: card.delay }}
            >
              <HealthCard {...card} />
            </motion.div>
          ))}
        </div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.4 }}
        >
          <Card className="bg-card/40 border-border/50 rounded-2xl overflow-hidden shadow-xl hover:shadow-2xl transition-all">
            <CardHeader className="bg-muted/30 border-b border-border/50">
              <CardTitle className="text-xl flex items-center gap-2">
                <Activity className="text-primary" />
                Network Performance
              </CardTitle>
            </CardHeader>
          <CardContent className="p-6">
            <div className="grid gap-8 md:grid-cols-2">
              <motion.div 
                className="space-y-4"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.5, delay: 0.5 }}
              >
                <div className="flex justify-between items-center">
                  <div className="flex items-center gap-2">
                    <motion.div
                      animate={isConnected ? { scale: [1, 1.2, 1] } : {}}
                      transition={{ duration: 1, repeat: Infinity }}
                    >
                      <Wifi className={cn("w-5 h-5", isConnected ? "text-primary" : "text-red-500")} />
                    </motion.div>
                    <span className="font-semibold text-foreground">Connection Status</span>
                  </div>
                  <span className={isConnected ? "text-emerald-500 font-bold" : "text-red-500 font-bold"}>
                    {isConnected ? 'Connected' : 'Disconnected'}
                  </span>
                </div>
                <Progress value={isConnected ? 100 : 0} className="h-2" />
                <p className="text-xs text-muted-foreground">
                  {isConnected 
                    ? 'WebSocket connection to backend is active and receiving data.'
                    : 'Not connected to the backend. Check if the server is running.'}
                </p>
              </motion.div>

              <motion.div 
                className="space-y-4"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.5, delay: 0.6 }}
              >
                <div className="flex justify-between items-center">
                  <div className="flex items-center gap-2">
                    <motion.div
                      animate={stats?.totalPackets ? { rotate: [0, 360] } : {}}
                      transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                    >
                      <Zap className="text-orange-400 w-5 h-5" />
                    </motion.div>
                    <span className="font-semibold text-foreground">Packets Per Second</span>
                  </div>
                  <span className="text-foreground font-bold">{stats?.totalPackets ? 'Active' : 'Idle'}</span>
                </div>
                <Progress value={stats?.totalPackets ? 75 : 0} className="h-2" />
                <p className="text-xs text-muted-foreground">
                  {stats?.totalPackets 
                    ? `Captured ${stats.totalPackets.toLocaleString()} packets total.`
                    : 'No packets captured yet. Start monitoring to see data.'}
                </p>
              </motion.div>
            </div>
          </CardContent>
        </Card>
        </motion.div>
      </div>
    </MainLayout>
  );
}

function HealthCard({ title, value, status, icon: Icon, color, progress }: any) {
  const isGood = status === 'Running Cool' || status === 'Optimal' || status === 'Healthy';
  
  return (
    <motion.div whileHover={{ scale: 1.02, y: -5 }} transition={{ duration: 0.2 }}>
      <Card className="bg-card/40 border-border/50 rounded-2xl overflow-hidden shadow-xl group hover:border-primary/30 hover:shadow-2xl transition-all">
        <CardContent className="pt-6">
          <div className="flex items-center justify-between mb-4">
            <motion.div 
              className={cn("p-3 rounded-xl", color.replace('text', 'bg') + '/10')}
              whileHover={{ scale: 1.1, rotate: 5 }}
            >
              <Icon className={cn("w-6 h-6", color)} />
            </motion.div>
            <div className="text-right">
              <p className="text-sm font-medium text-muted-foreground">{title}</p>
              <motion.p 
                className="text-2xl font-bold text-foreground"
                key={value}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
              >
                {value}
              </motion.p>
            </div>
          </div>
          <motion.div
            initial={{ scaleX: 0 }}
            animate={{ scaleX: 1 }}
            transition={{ duration: 0.8 }}
            style={{ originX: 0 }}
          >
            <Progress value={progress} className="h-1.5 mb-3" />
          </motion.div>
          <div className="flex items-center gap-2">
            <motion.div
              animate={isGood ? { scale: [1, 1.2, 1] } : {}}
              transition={{ duration: 2, repeat: Infinity }}
            >
              <ShieldCheck className={cn("w-3 h-3", isGood ? "text-emerald-500" : "text-amber-500")} />
            </motion.div>
            <span className={cn("text-xs font-semibold uppercase tracking-wider", isGood ? "text-emerald-500" : "text-amber-500")}>
              {status}
            </span>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
